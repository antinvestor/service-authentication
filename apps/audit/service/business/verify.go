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
	"crypto/ed25519"
	"fmt"
	"time"

	aconfig "github.com/antinvestor/service-authentication/apps/audit/config"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
)

const verifyPage = 1000

// IntegrityResult reports the outcome of chain verification.
type IntegrityResult struct {
	Valid              bool
	EntriesVerified    int64
	FirstInvalidSeq    int64
	FirstInvalidEntry  string
	Message            string
	StartCheckpointSeq int64
	EndSeq             int64
	EndHash            string
	KeyIDsUsed         []string
	Partial            bool
}

// ExportHeader is the first message of an export stream.
type ExportHeader struct {
	TenantID        string
	StartSeq        int64
	EndSeq          int64
	StartCheckpoint *models.AuditCheckpoint
	EndCheckpoint   *models.AuditCheckpoint
	Keys            []*models.AuditSigningKey
}

// ExportSink receives export messages in order.
type ExportSink interface {
	Header(h *ExportHeader) error
	Entry(e *models.AuditEntry) error
}

// VerifyBusiness verifies and exports chain ranges.
type VerifyBusiness interface {
	// ResolveRange turns optional dates and seqs into a concrete [start,end].
	ResolveRange(ctx context.Context, tenantID string, startSeq, endSeq int64, startDate, endDate *time.Time) (int64, int64, error)
	VerifyIntegrity(ctx context.Context, tenantID string, startSeq, endSeq int64) (*IntegrityResult, error)
	Export(ctx context.Context, tenantID string, startSeq, endSeq int64, sink ExportSink) error
}

type verifyBusiness struct {
	cfg         *aconfig.AuditConfig
	entries     repository.AuditEntryRepository
	checkpoints repository.CheckpointRepository
	heads       repository.ChainHeadRepository
	keys        KeyProvider
	metrics     *Metrics
}

// NewVerifyBusiness creates the verification and export layer.
func NewVerifyBusiness(cfg *aconfig.AuditConfig, entries repository.AuditEntryRepository, checkpoints repository.CheckpointRepository,
	heads repository.ChainHeadRepository, keys KeyProvider, metrics *Metrics) VerifyBusiness {
	return &verifyBusiness{cfg: cfg, entries: entries, checkpoints: checkpoints, heads: heads, keys: keys, metrics: metrics}
}

func (vb *verifyBusiness) ResolveRange(ctx context.Context, tenantID string, startSeq, endSeq int64, startDate, endDate *time.Time) (int64, int64, error) {
	var err error
	if startSeq <= 0 && startDate != nil {
		if startSeq, err = vb.entries.SeqAtOrAfter(ctx, tenantID, *startDate); err != nil {
			return 0, 0, fmt.Errorf("resolve start_date: %w", err)
		}
	}
	if endSeq <= 0 && endDate != nil {
		if endSeq, err = vb.entries.SeqAtOrBefore(ctx, tenantID, *endDate); err != nil {
			return 0, 0, fmt.Errorf("resolve end_date: %w", err)
		}
	}
	if startSeq <= 0 {
		startSeq = 1
	}
	if endSeq <= 0 {
		head, herr := vb.heads.Get(ctx, tenantID)
		if herr != nil {
			return 0, 0, fmt.Errorf("load head: %w", herr)
		}
		endSeq = head.Seq
	}
	return startSeq, endSeq, nil
}

// VerifyIntegrity walks [startSeq, endSeq] forward from the checkpoint at or
// before startSeq (or genesis), recomputing each hash under its
// canon_version and checking each signature under its key_id.
func (vb *verifyBusiness) VerifyIntegrity(ctx context.Context, tenantID string, startSeq, endSeq int64) (*IntegrityResult, error) {
	ctx, span := tracer().Start(ctx, "audit.verify")
	defer span.End()
	vb.metrics.VerificationRuns.Add(ctx, 1, attrTenant.String(tenantID))

	res := &IntegrityResult{Valid: true}
	if endSeq < startSeq {
		res.Message = "empty range"
		return res, nil
	}

	cursor := int64(1)
	prevHash := ""
	if startSeq > 1 {
		cp, err := vb.checkpoints.LatestAtOrBefore(ctx, tenantID, startSeq-1)
		if err != nil {
			return nil, fmt.Errorf("load checkpoint: %w", err)
		}
		if cp != nil {
			pub, kerr := vb.keys.Public(ctx, cp.KeyID)
			if kerr != nil {
				return nil, fmt.Errorf("checkpoint key: %w", kerr)
			}
			if !VerifyHash(pub, CheckpointHash(tenantID, cp.Seq, cp.EntryHash, cp.CreatedAt), cp.Signature, models.CanonVersionV2) {
				vb.metrics.VerificationFailures.Add(ctx, 1, attrTenant.String(tenantID))
				return &IntegrityResult{FirstInvalidSeq: cp.Seq, Message: fmt.Sprintf("checkpoint at seq %d has an invalid signature", cp.Seq)}, nil
			}
			res.StartCheckpointSeq = cp.Seq
			cursor = cp.Seq + 1
			prevHash = cp.EntryHash
		}
	}

	keysUsed := map[string]struct{}{}
	pubCache := map[string]ed25519.PublicKey{}
	var verified int64
	for cursor <= endSeq {
		if vb.cfg.VerifyMaxEntries > 0 && verified >= vb.cfg.VerifyMaxEntries {
			res.Partial = true
			break
		}
		page, err := vb.entries.ListChainBySeq(ctx, tenantID, cursor, endSeq, verifyPage)
		if err != nil {
			return nil, fmt.Errorf("list chain: %w", err)
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			if vb.cfg.VerifyMaxEntries > 0 && verified >= vb.cfg.VerifyMaxEntries {
				res.Partial = true
				break
			}
			if e.Seq != cursor {
				return vb.fail(ctx, tenantID, res, e, fmt.Sprintf("gap: expected seq %d, found %d", cursor, e.Seq)), nil
			}
			if e.PreviousHash != prevHash {
				return vb.fail(ctx, tenantID, res, e, fmt.Sprintf("chain break at seq %d: previous_hash mismatch", e.Seq)), nil
			}
			expected, herr := EntryHash(e, prevHash)
			if herr != nil {
				return vb.fail(ctx, tenantID, res, e, herr.Error()), nil
			}
			if expected != e.EntryHash {
				return vb.fail(ctx, tenantID, res, e, fmt.Sprintf("hash mismatch at seq %d: content has been tampered with", e.Seq)), nil
			}
			pub, ok := pubCache[e.KeyID]
			if !ok {
				pub, err = vb.keys.Public(ctx, e.KeyID)
				if err != nil {
					return vb.fail(ctx, tenantID, res, e, fmt.Sprintf("seq %d: unknown key %q", e.Seq, e.KeyID)), nil
				}
				pubCache[e.KeyID] = pub
			}
			if !VerifyHash(pub, e.EntryHash, e.Signature, e.CanonVersion) {
				return vb.fail(ctx, tenantID, res, e, fmt.Sprintf("invalid signature at seq %d", e.Seq)), nil
			}
			keysUsed[e.KeyID] = struct{}{}
			prevHash = e.EntryHash
			res.EndSeq, res.EndHash = e.Seq, e.EntryHash
			verified++
			cursor = e.Seq + 1
		}
		if res.Partial {
			break
		}
	}
	res.EntriesVerified = verified
	for k := range keysUsed {
		res.KeyIDsUsed = append(res.KeyIDsUsed, k)
	}
	res.Message = fmt.Sprintf("verified %d entries", verified)
	if res.Partial {
		res.Message += fmt.Sprintf(" (partial; continue from seq %d)", res.EndSeq+1)
	}
	return res, nil
}

func (vb *verifyBusiness) fail(ctx context.Context, tenantID string, res *IntegrityResult, e *models.AuditEntry, msg string) *IntegrityResult {
	vb.metrics.VerificationFailures.Add(ctx, 1, attrTenant.String(tenantID))
	res.Valid = false
	res.FirstInvalidSeq = e.Seq
	res.FirstInvalidEntry = e.ID
	res.Message = msg
	return res
}

// Export streams the header (bounding checkpoints and keys) then entries
// in seq order.
func (vb *verifyBusiness) Export(ctx context.Context, tenantID string, startSeq, endSeq int64, sink ExportSink) error {
	ctx, span := tracer().Start(ctx, "audit.export")
	defer span.End()

	header := &ExportHeader{TenantID: tenantID, StartSeq: startSeq, EndSeq: endSeq}
	var err error
	if startSeq > 1 {
		if header.StartCheckpoint, err = vb.checkpoints.LatestAtOrBefore(ctx, tenantID, startSeq-1); err != nil {
			return fmt.Errorf("start checkpoint: %w", err)
		}
	}
	if header.EndCheckpoint, err = vb.checkpoints.FirstAtOrAfter(ctx, tenantID, endSeq); err != nil {
		return fmt.Errorf("end checkpoint: %w", err)
	}
	if header.Keys, err = vb.keys.List(ctx); err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	if err = sink.Header(header); err != nil {
		return err
	}

	cursor := startSeq
	for cursor <= endSeq {
		page, perr := vb.entries.ListChainBySeq(ctx, tenantID, cursor, endSeq, verifyPage)
		if perr != nil {
			return fmt.Errorf("list chain: %w", perr)
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			if serr := sink.Entry(e); serr != nil {
				return serr
			}
			cursor = e.Seq + 1
		}
		vb.metrics.ExportEntries.Add(ctx, int64(len(page)), attrTenant.String(tenantID))
	}
	return nil
}
