// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package business

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	aconfig "github.com/antinvestor/service-authentication/apps/audit/config"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/tenancy"
	"github.com/pitabwire/util"
	"github.com/rs/xid"
)

const (
	discoverLimit      = 32
	retentionDeleteCap = 10_000
	retentionInterval  = time.Hour
)

// WriterRepos groups the repositories the writer needs.
type WriterRepos struct {
	Chain       repository.ChainRepository
	Intake      repository.IntakeRepository
	Rejections  repository.RejectionRepository
	Checkpoints repository.CheckpointRepository
}

// TickStats reports what one writer pass did.
type TickStats struct {
	Tenants     int
	Committed   int
	Failed      int
	Checkpoints int
}

// Writer drains intake into the chain. One instance runs per replica; the
// per-tenant advisory lock serialises replicas and SKIP LOCKED spreads
// tenants across them.
type Writer struct {
	cfg     *aconfig.AuditConfig
	repos   WriterRepos
	keys    KeyProvider
	metrics *Metrics
	service string
	frozen  map[string]struct{}

	lastTick      atomic.Int64 // unix nanos of the last completed tick
	lastErr       atomic.Pointer[string]
	oldestAge     atomic.Int64 // seconds; -1 when intake is empty
	maxBacklog    atomic.Int64
	lastRetention atomic.Int64
	lastKeyReload atomic.Int64
	now           func() time.Time
}

// NewWriter constructs the chain writer.
func NewWriter(cfg *aconfig.AuditConfig, serviceName string, repos WriterRepos, keys KeyProvider, metrics *Metrics) *Writer {
	w := &Writer{cfg: cfg, repos: repos, keys: keys, metrics: metrics, service: serviceName,
		frozen: cfg.FrozenTenantSet(), now: func() time.Time { return time.Now().UTC() }}
	w.oldestAge.Store(-1)
	return w
}

// Run is the Frame background consumer. It returns nil only when ctx is
// done; it never returns an error for transient failures (those are logged
// and retried), so the service keeps serving reads during a DB outage.
func (w *Writer) Run(ctx context.Context) error {
	log := util.Log(ctx).WithField("component", "audit_writer")
	log.Info("chain writer started")
	for {
		stats, err := w.Tick(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.WithError(err).Warn("writer tick failed")
		}
		delay := w.cfg.WriterTick
		if err != nil || stats.Committed == 0 {
			delay = w.cfg.WriterIdleTick
		}
		select {
		case <-ctx.Done():
			log.Info("chain writer stopped")
			return nil
		case <-time.After(delay):
		}
	}
}

// Tick performs one pass: discover tenants with backlog, commit one batch
// per tenant, refresh health state, and run housekeeping on its intervals.
func (w *Writer) Tick(ctx context.Context) (TickStats, error) {
	start := w.now()
	ctx, span := tracer().Start(ctx, "audit.writer.tick")
	defer span.End()
	var stats TickStats
	var firstErr error

	global := tenancy.WithSystemPrincipal(ctx, tenancy.SystemPrincipal{ServiceName: w.service, AllowGlobal: true, Reason: "intake-scan"})

	w.maybeReloadKey(global)

	backlog, err := w.repos.Chain.DiscoverBacklog(global, discoverLimit)
	if err != nil {
		w.recordTick(start, err)
		return stats, fmt.Errorf("discover backlog: %w", err)
	}
	var maxBacklog int64
	for _, b := range backlog {
		if b.Count > maxBacklog {
			maxBacklog = b.Count
		}
		w.metrics.IntakeBacklog.Record(global, b.Count, attrTenant.String(b.TenantID))
		if _, frozen := w.frozen[b.TenantID]; frozen {
			continue
		}
		scoped := tenancy.WithSystemPrincipal(ctx, tenancy.SystemPrincipal{ServiceName: w.service, TenantID: b.TenantID, Reason: "chain-writer"})
		committed, failed, checkpointed, cerr := w.commitTenant(scoped, b.TenantID)
		stats.Tenants++
		stats.Committed += committed
		stats.Failed += failed
		if checkpointed {
			stats.Checkpoints++
		}
		if cerr != nil {
			if errors.Is(cerr, repository.ErrHeadConflict) {
				w.metrics.WriterCASConflicts.Add(global, 1, attrTenant.String(b.TenantID))
			}
			util.Log(ctx).WithError(cerr).WithField("tenant_id", b.TenantID).Warn("audit: batch commit failed; will retry")
			if firstErr == nil {
				firstErr = cerr
			}
		}
	}
	w.maxBacklog.Store(maxBacklog)

	w.refreshHealth(global)
	w.maybeRetention(global)
	w.recordTick(start, firstErr)
	return stats, firstErr
}

func (w *Writer) commitTenant(ctx context.Context, tenantID string) (committed, failed int, checkpointed bool, err error) {
	signer, err := w.keys.Active()
	if err != nil {
		return 0, 0, false, fmt.Errorf("active key: %w", err)
	}
	ctx, span := tracer().Start(ctx, "audit.writer.batch")
	defer span.End()

	err = w.repos.Chain.CommitBatch(ctx, tenantID, func(tx repository.ChainTx) error {
		rows, cerr := tx.ClaimIntake(w.cfg.WriterBatch)
		if cerr != nil {
			return fmt.Errorf("claim intake: %w", cerr)
		}
		if len(rows) == 0 {
			return nil
		}
		head := tx.Head()
		seq := head.Seq
		prevHash := head.EntryHash
		// Postgres stores microseconds; hash exactly what will be stored.
		now := w.now().Truncate(time.Microsecond)

		entries := make([]*models.AuditEntry, 0, len(rows))
		ids := make([]string, 0, len(rows))
		seqs := make([]int64, 0, len(rows))
		for _, row := range rows {
			e, perr := EntryFromPayload(row)
			if perr != nil {
				if ferr := tx.MarkFailed(row.ID, perr.Error()); ferr != nil {
					return fmt.Errorf("mark failed: %w", ferr)
				}
				failed++
				continue
			}
			seq++
			e.Seq = seq
			e.ID = xid.NewWithTime(now).String()
			e.CreatedAt, e.ModifiedAt, e.Version = now, now, 1
			if serr := signer.SignEntry(e, prevHash); serr != nil {
				if ferr := tx.MarkFailed(row.ID, serr.Error()); ferr != nil {
					return fmt.Errorf("mark failed: %w", ferr)
				}
				seq--
				failed++
				continue
			}
			prevHash = e.EntryHash
			entries = append(entries, e)
			ids = append(ids, row.ID)
			seqs = append(seqs, seq)
			w.metrics.CommitLatency.Record(ctx, now.Sub(row.ReceivedAt).Seconds(), attrTenant.String(tenantID))
		}
		if len(entries) == 0 {
			return nil
		}
		if ierr := tx.InsertEntries(entries); ierr != nil {
			return fmt.Errorf("insert entries: %w", ierr)
		}
		if cp, cperr := w.maybeCheckpoint(ctx, tx, signer, tenantID, head.Seq, seq, prevHash, now); cperr != nil {
			return cperr
		} else if cp {
			checkpointed = true
		}
		if aerr := tx.AdvanceHead(seq, prevHash); aerr != nil {
			return aerr
		}
		if merr := tx.MarkCommitted(ids, seqs); merr != nil {
			return fmt.Errorf("mark committed: %w", merr)
		}
		committed = len(entries)
		w.metrics.WriterBatchSize.Record(ctx, float64(committed), attrTenant.String(tenantID))
		return nil
	})
	if err != nil {
		return 0, 0, false, err
	}
	return committed, failed, checkpointed, nil
}

// maybeCheckpoint inserts a checkpoint at newSeq when the batch crossed a
// multiple of CheckpointEveryN or the interval elapsed since the last one.
func (w *Writer) maybeCheckpoint(ctx context.Context, tx repository.ChainTx, signer *Signer, tenantID string,
	oldSeq, newSeq int64, entryHash string, now time.Time) (bool, error) {
	due := false
	if n := w.cfg.CheckpointEveryN; n > 0 && oldSeq/n != newSeq/n {
		due = true
	}
	if !due && w.cfg.CheckpointInterval > 0 {
		latest, err := w.repos.Checkpoints.Latest(ctx, tenantID)
		if err != nil {
			return false, fmt.Errorf("latest checkpoint: %w", err)
		}
		if latest == nil || now.Sub(latest.CreatedAt) >= w.cfg.CheckpointInterval {
			due = true
		}
	}
	if !due {
		return false, nil
	}
	cp := &models.AuditCheckpoint{Seq: newSeq, EntryHash: entryHash}
	cp.ID = xid.NewWithTime(now).String()
	cp.TenantID = tenantID
	cp.CreatedAt, cp.ModifiedAt, cp.Version = now, now, 1
	if err := signer.SignCheckpoint(cp); err != nil {
		return false, fmt.Errorf("sign checkpoint: %w", err)
	}
	if err := tx.InsertCheckpoint(cp); err != nil {
		return false, fmt.Errorf("insert checkpoint: %w", err)
	}
	return true, nil
}

func (w *Writer) maybeReloadKey(ctx context.Context) {
	last := time.Unix(0, w.lastKeyReload.Load())
	if w.cfg.KeyReloadInterval <= 0 || w.now().Sub(last) < w.cfg.KeyReloadInterval {
		return
	}
	w.lastKeyReload.Store(w.now().UnixNano())
	if err := w.keys.Reload(ctx); err != nil {
		util.Log(ctx).WithError(err).Error("audit: signing key reload failed")
	}
	retired := int64(0)
	if _, err := w.keys.Active(); err != nil {
		retired = 1
	}
	w.metrics.SigningKeyActive.Record(ctx, 1, attrKeyID.String(w.keys.ActiveKeyID()), attrRetired.Bool(retired == 1))
}

func (w *Writer) refreshHealth(ctx context.Context) {
	oldest, err := w.repos.Intake.OldestAccepted(ctx)
	if err != nil {
		util.Log(ctx).WithError(err).Debug("audit: oldest accepted lookup failed")
		return
	}
	if oldest.IsZero() {
		w.oldestAge.Store(-1)
		w.metrics.IntakeOldestAge.Record(ctx, 0)
	} else {
		age := w.now().Sub(oldest)
		w.oldestAge.Store(int64(age.Seconds()))
		w.metrics.IntakeOldestAge.Record(ctx, age.Seconds())
	}
	if failed, ferr := w.repos.Intake.CountFailed(ctx); ferr == nil {
		w.metrics.IntakeFailed.Record(ctx, failed)
	}
}

func (w *Writer) maybeRetention(ctx context.Context) {
	last := time.Unix(0, w.lastRetention.Load())
	now := w.now()
	if now.Sub(last) < retentionInterval {
		return
	}
	w.lastRetention.Store(now.UnixNano())
	if n, err := w.repos.Intake.DeleteCommittedBefore(ctx, now.Add(-w.cfg.IntakeCommittedRetention), retentionDeleteCap); err != nil {
		util.Log(ctx).WithError(err).Warn("audit: intake retention failed")
	} else if n > 0 {
		util.Log(ctx).WithField("deleted", n).Info("audit: committed intake rows pruned")
	}
	if n, err := w.repos.Rejections.DeleteBefore(ctx, now.Add(-w.cfg.RejectionsRetention), retentionDeleteCap); err != nil {
		util.Log(ctx).WithError(err).Warn("audit: rejection retention failed")
	} else if n > 0 {
		util.Log(ctx).WithField("deleted", n).Info("audit: rejection rows pruned")
	}
}

func (w *Writer) recordTick(start time.Time, err error) {
	w.lastTick.Store(w.now().UnixNano())
	outcome := "ok"
	if err != nil {
		outcome = "error"
		msg := err.Error()
		w.lastErr.Store(&msg)
	} else {
		w.lastErr.Store(nil)
	}
	w.metrics.WriterTickDuration.Record(context.Background(), w.now().Sub(start).Seconds(), attrOutcome.String(outcome))
}

// ReadinessChecker fails when the chain is unhealthy: the active key is
// unusable, the backlog exceeds the cap, or the oldest accepted entry is
// older than HeadMaxAge. It reads cached state only.
func (w *Writer) ReadinessChecker() frame.Checker {
	return namedChecker{name: "audit_chain", fn: func() error {
		if _, err := w.keys.Active(); err != nil {
			return fmt.Errorf("signing key: %w", err)
		}
		if cap := int64(w.cfg.IntakeMaxBacklog); cap > 0 && w.maxBacklog.Load() >= cap {
			return fmt.Errorf("intake backlog %d exceeds %d", w.maxBacklog.Load(), cap)
		}
		if age := w.oldestAge.Load(); age >= 0 && w.cfg.HeadMaxAge > 0 && time.Duration(age)*time.Second > w.cfg.HeadMaxAge {
			return fmt.Errorf("oldest accepted entry is %ds old (max %s)", age, w.cfg.HeadMaxAge)
		}
		return nil
	}}
}

// LivenessChecker fails only when the writer loop has stalled.
func (w *Writer) LivenessChecker() frame.Checker {
	return namedChecker{name: "audit_writer_loop", fn: func() error {
		last := w.lastTick.Load()
		if last == 0 {
			return nil // not started yet
		}
		limit := 3*w.cfg.WriterIdleTick + 30*time.Second
		if since := w.now().Sub(time.Unix(0, last)); since > limit {
			return fmt.Errorf("writer has not ticked for %s", since)
		}
		return nil
	}}
}

type namedChecker struct {
	name string
	fn   func() error
}

func (c namedChecker) CheckHealth() error { return c.fn() }
func (c namedChecker) Name() string       { return c.name }
