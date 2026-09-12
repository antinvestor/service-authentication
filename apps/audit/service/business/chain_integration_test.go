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

package business_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	auditv1 "buf.build/gen/go/antinvestor/audit/protocolbuffers/go/audit/v1"
	aconfig "github.com/antinvestor/service-authentication/apps/audit/config"
	"github.com/antinvestor/service-authentication/apps/audit/service/business"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/antinvestor/service-authentication/apps/audit/tests"
	"github.com/pitabwire/frame/v2/data"
	"github.com/stretchr/testify/suite"
)

type ChainSuite struct {
	tests.BaseTestSuite
}

func TestChainSuite(t *testing.T) {
	suite.Run(t, new(ChainSuite))
}

// stack wires the business layers on one started service, the same way
// handlers.BuildDeps does in production (duplicated here to avoid importing
// handlers into business tests).
type stack struct {
	svc      *tests.Service
	keys     business.KeyProvider
	ingest   business.IngestBusiness
	writer   *business.Writer
	verify   business.VerifyBusiness
	read     business.ReadBusiness
	manifest business.ManifestBusiness
	intake   repository.IntakeRepository
	entries  repository.AuditEntryRepository
	heads    repository.ChainHeadRepository
	cps      repository.CheckpointRepository
	keyRepo  repository.SigningKeyRepository
	metrics  *business.Metrics
}

func (s *ChainSuite) newStack(mutate func(cfg *aconfig.AuditConfig)) *stack {
	t := s.T()
	svc := s.CreateService(t, mutate)
	ctx := svc.Ctx
	st := &stack{svc: svc}
	st.keyRepo = repository.NewSigningKeyRepository(ctx, svc.Pool)
	keys, err := business.NewKeyProvider(ctx, svc.Cfg, st.keyRepo)
	s.Require().NoError(err)
	s.Require().NoError(keys.Seed(tests.GlobalContext(ctx)))
	st.keys = keys
	st.metrics = business.NewMetrics()
	st.intake = repository.NewIntakeRepository(ctx, svc.Pool)
	st.entries = repository.NewAuditEntryRepository(svc.Pool)
	st.heads = repository.NewChainHeadRepository(svc.Pool)
	st.cps = repository.NewCheckpointRepository(svc.Pool)
	rejections := repository.NewRejectionRepository(ctx, svc.Pool)
	manifestRepo := repository.NewManifestRepository(ctx, svc.Pool)
	st.manifest = business.NewManifestBusiness(manifestRepo)
	validator := business.NewValidator(st.manifest.Lookup, svc.Cfg.RequireManifest)
	st.ingest = business.NewIngestBusiness(svc.Cfg, validator, st.intake, rejections, st.metrics)
	st.writer = business.NewWriter(svc.Cfg, tests.NamespaceAudit, business.WriterRepos{
		Chain: repository.NewChainRepository(svc.Pool), Intake: st.intake, Rejections: rejections, Checkpoints: st.cps,
	}, keys, st.metrics)
	st.verify = business.NewVerifyBusiness(svc.Cfg, st.entries, st.cps, st.heads, keys, st.metrics)
	st.read = business.NewReadBusiness(st.entries, st.cps, st.heads)
	return st
}

func personCaller(tenant string) business.Caller {
	return business.Caller{TenantID: tenant, PartitionID: "p-" + tenant, ProfileID: "person-1", ServiceName: "service_loans"}
}

func entryReq(entryID, action string) *auditv1.CreateAuditEntryRequest {
	req := &auditv1.CreateAuditEntryRequest{}
	req.SetProfileId("person-1")
	req.SetAction(action)
	req.SetResourceType("loan")
	req.SetResourceId("loan-1")
	req.SetService("service_loans")
	req.SetEntryId(entryID)
	return req
}

// ingestN accepts n entries for tenant through the ingest layer.
func (s *ChainSuite) ingestN(st *stack, tenant string, n int, prefix string) {
	ctx := tests.UserContext(st.svc.Ctx, tenant, "p-"+tenant, "person-1")
	batch := make([]*auditv1.CreateAuditEntryRequest, 0, business.MaxBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		_, err := st.ingest.CreateBatch(ctx, personCaller(tenant), batch)
		s.Require().NoError(err)
		batch = batch[:0]
	}
	for i := range n {
		batch = append(batch, entryReq(fmt.Sprintf("%s-%s-%05d", prefix, tenant, i), "create"))
		if len(batch) == business.MaxBatch {
			flush()
		}
	}
	flush()
}

// drain ticks until no more work is committed.
func (s *ChainSuite) drain(st *stack) business.TickStats {
	var total business.TickStats
	for range 200 {
		stats, err := st.writer.Tick(st.svc.Ctx)
		s.Require().NoError(err)
		total.Committed += stats.Committed
		total.Failed += stats.Failed
		total.Checkpoints += stats.Checkpoints
		if stats.Committed == 0 && stats.Failed == 0 {
			return total
		}
	}
	s.FailNow("writer did not drain")
	return total
}

func (s *ChainSuite) chain(st *stack, tenant string) []*models.AuditEntry {
	entries, err := st.entries.ListChainBySeq(tests.TenantContext(st.svc.Ctx, tenant), tenant, 1, 0, 1000)
	s.Require().NoError(err)
	return entries
}

// ---------------------------------------------------------------------------

func (s *ChainSuite) TestIngest_AcceptsDuplicatesIdempotentlyAndRecordsRejections() {
	st := s.newStack(nil)
	ctx := tests.UserContext(st.svc.Ctx, "t-ingest", "p-t-ingest", "person-1")
	caller := personCaller("t-ingest")

	first, err := st.ingest.Create(ctx, caller, entryReq("e-1", "create"))
	s.Require().NoError(err)
	s.Require().Equal(models.IntakeStateAccepted, first.State)
	s.Require().Equal("e-1", first.EntryID)

	again, err := st.ingest.Create(ctx, caller, entryReq("e-1", "create"))
	s.Require().NoError(err)
	s.Require().Equal(first.IntakeID, again.IntakeID, "same entry_id returns the existing intake row")

	backlog, err := st.intake.Backlog(ctx, "t-ingest")
	s.Require().NoError(err)
	s.Require().Equal(int64(1), backlog)

	bad := entryReq("e-2", "create")
	bad.SetService("service_other")
	_, err = st.ingest.Create(ctx, caller, bad)
	var verr *business.ValidationError
	s.Require().ErrorAs(err, &verr)
	s.Require().Equal(business.ReasonServiceBinding, verr.Reason)

	var rejections []models.AuditRejection
	s.Require().NoError(st.svc.Pool.DB(ctx, true).Find(&rejections).Error)
	s.Require().Len(rejections, 1)
	s.Require().Equal("service_other", rejections[0].Service)
	s.Require().Equal("e-2", rejections[0].EntryID)

	// A batch is all-or-nothing: the second entry fails validation, so the
	// first is not accepted either.
	_, err = st.ingest.CreateBatch(ctx, caller, []*auditv1.CreateAuditEntryRequest{entryReq("e-3", "create"), bad})
	s.Require().ErrorAs(err, &verr)
	s.Require().Contains(verr.Field, "entries[1]")
	backlog, err = st.intake.Backlog(ctx, "t-ingest")
	s.Require().NoError(err)
	s.Require().Equal(int64(1), backlog)
}

func (s *ChainSuite) TestIngest_BacklogCapReturnsResourceExhausted() {
	st := s.newStack(func(cfg *aconfig.AuditConfig) { cfg.IntakeMaxBacklog = 3 })
	ctx := tests.UserContext(st.svc.Ctx, "t-cap", "p-t-cap", "person-1")
	caller := personCaller("t-cap")
	for i := range 3 {
		_, err := st.ingest.Create(ctx, caller, entryReq(fmt.Sprintf("cap-%d", i), "create"))
		s.Require().NoError(err)
	}
	_, err := st.ingest.Create(ctx, caller, entryReq("cap-over", "create"))
	s.Require().ErrorIs(err, business.ErrBacklogExceeded)

	// Readiness is cached state refreshed by the writer: a frozen writer
	// observes the backlog at the cap and reports not ready.
	frozenCfg := *st.svc.Cfg
	frozenCfg.FrozenTenants = "t-cap"
	frozen := business.NewWriter(&frozenCfg, tests.NamespaceAudit, business.WriterRepos{
		Chain: repository.NewChainRepository(st.svc.Pool), Intake: st.intake,
		Rejections: repository.NewRejectionRepository(st.svc.Ctx, st.svc.Pool), Checkpoints: st.cps,
	}, st.keys, st.metrics)
	s.Require().NoError(frozen.ReadinessChecker().CheckHealth(), "healthy until the first tick observes the backlog")
	_, err = frozen.Tick(st.svc.Ctx)
	s.Require().NoError(err)
	s.Require().Error(frozen.ReadinessChecker().CheckHealth())

	// Draining restores readiness and lets the producer continue.
	s.drain(st)
	s.Require().NoError(st.writer.ReadinessChecker().CheckHealth())
	_, err = st.ingest.Create(ctx, caller, entryReq("cap-over", "create"))
	s.Require().NoError(err)
}

func (s *ChainSuite) TestWriter_CommitsContiguousSeqWithCheckpoints() {
	st := s.newStack(nil) // batch 100, checkpoint every 50
	s.ingestN(st, "t-one", 230, "a")

	stats := s.drain(st)
	s.Require().Equal(230, stats.Committed)
	s.Require().Zero(stats.Failed)

	entries := s.chain(st, "t-one")
	s.Require().Len(entries, 230)
	prev := ""
	for i, e := range entries {
		s.Require().Equal(int64(i+1), e.Seq)
		s.Require().Equal(prev, e.PreviousHash)
		s.Require().Equal("k1", e.KeyID)
		s.Require().Equal(int16(models.CanonVersionV2), e.CanonVersion)
		s.Require().Equal(fmt.Sprintf("a-t-one-%05d", i), e.EntryID, "receipt order is chain order")
		prev = e.EntryHash
	}

	head, err := st.heads.Get(tests.TenantContext(st.svc.Ctx, "t-one"), "t-one")
	s.Require().NoError(err)
	s.Require().Equal(int64(230), head.Seq)
	s.Require().Equal(prev, head.EntryHash)

	cps, err := st.cps.List(tests.TenantContext(st.svc.Ctx, "t-one"), "t-one", 0, 0, 100)
	s.Require().NoError(err)
	// First batch (1..100) crosses 50 and 100 → one checkpoint at 100; second
	// (101..200) → 200; third (201..230) → 230 only if the hourly interval
	// fired, which it does not. Count-based checkpoints land at batch ends.
	seqs := make([]int64, 0, len(cps))
	for _, c := range cps {
		seqs = append(seqs, c.Seq)
	}
	s.Require().Equal([]int64{100, 200}, seqs)

	committed, err := st.intake.Backlog(tests.TenantContext(st.svc.Ctx, "t-one"), "t-one")
	s.Require().NoError(err)
	s.Require().Zero(committed)
}

func (s *ChainSuite) TestWriter_TwoReplicasNeverForkOrGap() {
	st := s.newStack(func(cfg *aconfig.AuditConfig) { cfg.WriterBatch = 37 })
	tenants := []string{"t-a", "t-b", "t-c", "t-d"}
	for _, tenant := range tenants {
		s.ingestN(st, tenant, 150, "m")
	}
	// A second writer over the same database stands in for another replica.
	second := business.NewWriter(st.svc.Cfg, tests.NamespaceAudit, business.WriterRepos{
		Chain: repository.NewChainRepository(st.svc.Pool), Intake: st.intake,
		Rejections: repository.NewRejectionRepository(st.svc.Ctx, st.svc.Pool), Checkpoints: st.cps,
	}, st.keys, st.metrics)

	ctx, cancel := context.WithCancel(st.svc.Ctx)
	defer cancel()
	done := make(chan error, 2)
	for _, w := range []*business.Writer{st.writer, second} {
		go func(w *business.Writer) { done <- w.Run(ctx) }(w)
	}
	s.Require().Eventually(func() bool {
		for _, tenant := range tenants {
			head, err := st.heads.Get(tests.TenantContext(st.svc.Ctx, tenant), tenant)
			if err != nil || head.Seq < 150 {
				return false
			}
		}
		return true
	}, 30*time.Second, 50*time.Millisecond)
	cancel()
	for range 2 {
		s.Require().NoError(<-done)
	}

	for _, tenant := range tenants {
		entries := s.chain(st, tenant)
		s.Require().Len(entries, 150, tenant)
		prev := ""
		for i, e := range entries {
			s.Require().Equal(int64(i+1), e.Seq, tenant)
			s.Require().Equal(prev, e.PreviousHash, tenant)
			prev = e.EntryHash
		}
		res, err := st.verify.VerifyIntegrity(tests.TenantContext(st.svc.Ctx, tenant), tenant, 1, 150)
		s.Require().NoError(err)
		s.Require().True(res.Valid, res.Message)
		s.Require().Equal(int64(150), res.EntriesVerified)
	}
}

func (s *ChainSuite) TestWriter_PoisonRowFailsAloneAndFrozenTenantWaits() {
	st := s.newStack(func(cfg *aconfig.AuditConfig) { cfg.FrozenTenants = "t-frozen" })
	s.ingestN(st, "t-poison", 3, "p")
	s.ingestN(st, "t-frozen", 2, "f")

	// Corrupt one intake payload directly (bypassing the validator).
	global := tests.GlobalContext(st.svc.Ctx)
	s.Require().NoError(st.svc.Pool.DB(global, false).Exec(
		`UPDATE audit_intake SET payload = '{"broken": true}'::jsonb WHERE entry_id = 'p-t-poison-00001'`).Error)

	stats := s.drain(st)
	s.Require().Equal(2, stats.Committed)
	s.Require().Equal(1, stats.Failed)

	entries := s.chain(st, "t-poison")
	s.Require().Len(entries, 2)
	s.Require().Equal([]int64{1, 2}, []int64{entries[0].Seq, entries[1].Seq}, "seq stays dense around a failed row")

	failed, err := st.intake.CountFailed(global)
	s.Require().NoError(err)
	s.Require().Equal(int64(1), failed)

	frozenHead, err := st.heads.Get(tests.TenantContext(st.svc.Ctx, "t-frozen"), "t-frozen")
	s.Require().NoError(err)
	s.Require().Zero(frozenHead.Seq, "frozen tenant is never advanced")

	// Operator remediation: fix the payload and requeue.
	var row models.AuditIntake
	s.Require().NoError(st.svc.Pool.DB(global, true).Where("entry_id = ?", "p-t-poison-00001").First(&row).Error)
	good := business.EntryToPayload(&models.AuditEntry{
		ProfileID: "person-1", Action: "create", ResourceType: "loan", Service: "service_loans", EntryID: row.EntryID,
		OccurredAt: row.ReceivedAt, ReceivedAt: row.ReceivedAt, Details: data.JSONMap{"fixed": true},
	})
	s.Require().NoError(st.svc.Pool.DB(global, false).Table(models.AuditIntake{}.TableName()).Where("id = ?", row.ID).
		Update("payload", good).Error)
	n, err := st.ingest.Requeue(global, []string{row.ID})
	s.Require().NoError(err)
	s.Require().Equal(int64(1), n)
	stats = s.drain(st)
	s.Require().Equal(1, stats.Committed)
	s.Require().Len(s.chain(st, "t-poison"), 3)
}

func (s *ChainSuite) TestWriter_CancelMidBatchRollsBackAndResumes() {
	st := s.newStack(nil)
	s.ingestN(st, "t-cancel", 40, "c")

	// Cancel while the transaction is open by using a context that expires
	// almost immediately; the first tick fails, nothing is committed.
	ctx, cancel := context.WithTimeout(st.svc.Ctx, time.Nanosecond)
	defer cancel()
	_, err := st.writer.Tick(ctx)
	s.Require().Error(err)

	head, err := st.heads.Get(tests.TenantContext(st.svc.Ctx, "t-cancel"), "t-cancel")
	s.Require().NoError(err)
	s.Require().Zero(head.Seq)
	backlog, err := st.intake.Backlog(tests.TenantContext(st.svc.Ctx, "t-cancel"), "t-cancel")
	s.Require().NoError(err)
	s.Require().Equal(int64(40), backlog, "claimed rows return to ACCEPTED on rollback")

	stats := s.drain(st)
	s.Require().Equal(40, stats.Committed)
}

func (s *ChainSuite) TestVerify_DetectsTamperingAndStartsFromCheckpoint() {
	st := s.newStack(nil)
	s.ingestN(st, "t-verify", 120, "v")
	s.drain(st)
	ctx := tests.TenantContext(st.svc.Ctx, "t-verify")

	full, err := st.verify.VerifyIntegrity(ctx, "t-verify", 1, 120)
	s.Require().NoError(err)
	s.Require().True(full.Valid, full.Message)
	s.Require().Equal(int64(120), full.EntriesVerified)
	s.Require().Zero(full.StartCheckpointSeq)
	s.Require().Equal([]string{"k1"}, full.KeyIDsUsed)

	// Range 105..120 starts from the checkpoint at 100 and verifies 20 rows
	// (101..120), so cost is proportional to the range, not the chain.
	ranged, err := st.verify.VerifyIntegrity(ctx, "t-verify", 105, 120)
	s.Require().NoError(err)
	s.Require().True(ranged.Valid, ranged.Message)
	s.Require().Equal(int64(100), ranged.StartCheckpointSeq)
	s.Require().Equal(int64(20), ranged.EntriesVerified)
	s.Require().Equal(int64(120), ranged.EndSeq)

	// Date-resolved range.
	from, to, err := st.verify.ResolveRange(ctx, "t-verify", 0, 0, nil, nil)
	s.Require().NoError(err)
	s.Require().Equal(int64(1), from)
	s.Require().Equal(int64(120), to)

	// Tamper past the trigger as the superuser.
	su := st.svc.SuperuserPool(s.T())
	s.Require().NoError(su.DB(ctx, false).Exec(`ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_immutable`).Error)
	s.Require().NoError(su.DB(ctx, false).Exec(`UPDATE audit_entries SET action = 'delete' WHERE tenant_id = 't-verify' AND seq = 110`).Error)
	s.Require().NoError(su.DB(ctx, false).Exec(`ALTER TABLE audit_entries ENABLE TRIGGER audit_entries_immutable`).Error)

	broken, err := st.verify.VerifyIntegrity(ctx, "t-verify", 1, 120)
	s.Require().NoError(err)
	s.Require().False(broken.Valid)
	s.Require().Equal(int64(110), broken.FirstInvalidSeq)
	s.Require().Contains(broken.Message, "hash mismatch")

	// Verification cap yields a partial result the caller can continue.
	st.svc.Cfg.VerifyMaxEntries = 50
	partial, err := st.verify.VerifyIntegrity(ctx, "t-verify", 1, 100)
	s.Require().NoError(err)
	s.Require().True(partial.Partial)
	s.Require().Equal(int64(50), partial.EndSeq)
}

func (s *ChainSuite) TestVerify_AcrossKeyRotationAndLegacyBoundary() {
	st := s.newStack(nil)
	ctx := tests.TenantContext(st.svc.Ctx, "t-rot")
	global := tests.GlobalContext(st.svc.Ctx)

	// Legacy history: two canon v1 rows inserted the way the pre-v2 service
	// and the backfill would have left them, signed by k1 over the hex hash.
	k1, err := st.keys.Active()
	s.Require().NoError(err)
	prev := ""
	base := time.Now().UTC().Add(-time.Hour)
	for i := 1; i <= 2; i++ {
		e := &models.AuditEntry{ProfileID: "legacy", Action: "login", ResourceType: "session", Service: "service_authentication",
			Seq: int64(i), KeyID: "k1", CanonVersion: models.CanonVersionLegacy, EntryID: fmt.Sprintf("legacy-%d", i)}
		e.ID = fmt.Sprintf("legacy-%d", i)
		e.TenantID, e.PartitionID = "t-rot", "p-t-rot"
		e.CreatedAt, e.ModifiedAt, e.Version = base.Add(time.Duration(i)*time.Second), base, 1
		e.OccurredAt, e.ReceivedAt = e.CreatedAt, e.CreatedAt
		e.PreviousHash = prev
		e.EntryHash = business.EntryHashV1(e, prev)
		e.Signature, err = k1.SignHash(e.EntryHash, models.CanonVersionLegacy)
		s.Require().NoError(err)
		s.Require().NoError(st.svc.Pool.DB(global, false).Create(e).Error)
		prev = e.EntryHash
	}
	s.Require().NoError(st.svc.Pool.DB(global, false).Exec(
		`INSERT INTO audit_chain_heads (id, tenant_id, partition_id, seq, entry_hash, created_at, modified_at, version)
		 VALUES ('t-rot', 't-rot', 'p-t-rot', 2, ?, now(), now(), 1)`, prev).Error)

	// v2 rows under k1.
	s.ingestN(st, "t-rot", 5, "r1")
	s.drain(st)

	// Rotate: new key k2 on disk, new provider/writer with k2, retire k1.
	tests.WriteKeyFile(s.T(), st.svc.KeyDir, "k2")
	cfg2 := *st.svc.Cfg
	cfg2.SigningKeyRef = "file://" + filepath.Join(st.svc.KeyDir, "k2")
	cfg2.SigningKeyID = "k2"
	keys2, err := business.NewKeyProvider(st.svc.Ctx, &cfg2, st.keyRepo)
	s.Require().NoError(err)
	s.Require().NoError(keys2.Seed(global))
	_, err = keys2.Retire(global, "k1")
	s.Require().NoError(err)
	writer2 := business.NewWriter(&cfg2, tests.NamespaceAudit, business.WriterRepos{
		Chain: repository.NewChainRepository(st.svc.Pool), Intake: st.intake,
		Rejections: repository.NewRejectionRepository(st.svc.Ctx, st.svc.Pool), Checkpoints: st.cps,
	}, keys2, st.metrics)
	s.ingestN(st, "t-rot", 5, "r2")
	for range 20 {
		stats, terr := writer2.Tick(st.svc.Ctx)
		s.Require().NoError(terr)
		if stats.Committed == 0 {
			break
		}
	}

	// The retired k1 can no longer sign: reload observes the retirement and
	// the old writer's tick errors.
	s.Require().ErrorIs(st.keys.Reload(global), business.ErrActiveKeyRetired)
	_, err = st.keys.Active()
	s.Require().ErrorIs(err, business.ErrActiveKeyRetired)
	s.ingestN(st, "t-rot", 1, "r3")
	_, err = st.writer.Tick(st.svc.Ctx)
	s.Require().ErrorIs(err, business.ErrActiveKeyRetired)

	entries := s.chain(st, "t-rot")
	s.Require().Len(entries, 12)
	s.Require().Equal(int16(models.CanonVersionLegacy), entries[1].CanonVersion)
	s.Require().Equal("k1", entries[6].KeyID)
	s.Require().Equal("k2", entries[7].KeyID)

	res, err := st.verify.VerifyIntegrity(ctx, "t-rot", 1, 12)
	s.Require().NoError(err)
	s.Require().True(res.Valid, res.Message)
	s.Require().Equal(int64(12), res.EntriesVerified)
	s.Require().ElementsMatch([]string{"k1", "k2"}, res.KeyIDsUsed)

	keys, err := st.keys.List(global)
	s.Require().NoError(err)
	s.Require().Len(keys, 2)
	s.Require().NotNil(keys[0].RetiredAt)
	s.Require().Nil(keys[1].RetiredAt)

	// Retiring twice is a not-found style error; the trigger also blocks it.
	_, err = keys2.Retire(global, "k1")
	s.Require().ErrorIs(err, repository.ErrAlreadyRetiredOrMissing)
}

func (s *ChainSuite) TestKeyProvider_RefusesBadConfiguration() {
	st := s.newStack(nil)
	ctx := st.svc.Ctx
	base := *st.svc.Cfg

	missing := base
	missing.SigningKeyRef = "file:///nonexistent/key"
	_, err := business.NewKeyProvider(ctx, &missing, st.keyRepo)
	s.Require().Error(err)

	legacy := base
	legacy.LegacySigningKey = "deadbeef"
	_, err = business.NewKeyProvider(ctx, &legacy, st.keyRepo)
	s.Require().ErrorIs(err, business.ErrLegacyKeyEnvSet)

	noID := base
	noID.SigningKeyID = ""
	_, err = business.NewKeyProvider(ctx, &noID, st.keyRepo)
	s.Require().ErrorIs(err, business.ErrKeyRefMissing)

	// A different private key under the same id must not be accepted.
	tests.WriteKeyFile(s.T(), st.svc.KeyDir, "k1-other")
	mismatch := base
	mismatch.SigningKeyRef = "file://" + filepath.Join(st.svc.KeyDir, "k1-other")
	_, err = business.NewKeyProvider(tests.GlobalContext(ctx), &mismatch, st.keyRepo)
	s.Require().ErrorIs(err, business.ErrPublicKeyMismatch)

	// vault:// resolves to <mountDir>/<keyID>.
	vault := base
	vault.SigningKeyRef = "vault://antinvestor/auth/audit/signing#private_key"
	kp, err := business.NewKeyProvider(tests.GlobalContext(ctx), &vault, st.keyRepo)
	s.Require().NoError(err)
	signer, err := kp.Active()
	s.Require().NoError(err)
	s.Require().Equal("k1", signer.KeyID())

	_, err = kp.Public(tests.GlobalContext(ctx), "nope")
	s.Require().ErrorIs(err, business.ErrKeyNotFound)
	pub, err := kp.Public(tests.GlobalContext(ctx), "k1")
	s.Require().NoError(err)
	s.Require().Equal(ed25519.PublicKey(signer.Public()), pub)
}

func (s *ChainSuite) TestManifest_VersionsAndValidatorCoupling() {
	st := s.newStack(nil)
	global := tests.GlobalContext(st.svc.Ctx)
	caller := business.Caller{ServiceName: "service_loans", ProfileID: "setup-job"}

	m := &auditv1.AuditManifest{}
	m.SetService("service_loans")
	m.SetActions([]string{"create", "approve"})
	m.SetResourceTypes([]string{"loan"})
	first, err := st.manifest.Register(global, caller, m)
	s.Require().NoError(err)
	s.Require().Equal(int32(1), first.Version)

	same, err := st.manifest.Register(global, caller, m)
	s.Require().NoError(err)
	s.Require().True(same.Unchanged)
	s.Require().Equal(int32(1), same.Version)

	m.SetActions([]string{"approve", "create", "reject"})
	next, err := st.manifest.Register(global, caller, m)
	s.Require().NoError(err)
	s.Require().Equal(int32(2), next.Version)

	other := caller
	other.ServiceName = "service_other"
	_, err = st.manifest.Register(global, other, m)
	s.Require().ErrorIs(err, business.ErrManifestServiceMismatch)

	// The validator now rejects an action outside the manifest.
	ctx := tests.UserContext(st.svc.Ctx, "t-man", "p-t-man", "person-1")
	_, err = st.ingest.Create(ctx, personCaller("t-man"), entryReq("m-1", "explode"))
	var verr *business.ValidationError
	s.Require().ErrorAs(err, &verr)
	s.Require().Equal(business.ReasonVocabulary, verr.Reason)
	receipt, err := st.ingest.Create(ctx, personCaller("t-man"), entryReq("m-2", "reject"))
	s.Require().NoError(err)
	s.Require().Equal(models.IntakeStateAccepted, receipt.State)
	s.drain(st)
	e := s.chain(st, "t-man")[0]
	s.Require().Equal(int32(2), e.ManifestVersion)
	s.Require().False(e.Unmanifested)
}

func (s *ChainSuite) TestExport_StreamsHeaderThenOrderedEntries() {
	st := s.newStack(nil)
	s.ingestN(st, "t-exp", 120, "x")
	s.drain(st)
	ctx := tests.TenantContext(st.svc.Ctx, "t-exp")

	// Batches of 100 with a checkpoint every 50 entries: the checkpoint lands
	// at the end of the batch that crossed the threshold, i.e. seq 100.
	sink := &collectingSink{}
	s.Require().NoError(st.verify.Export(ctx, "t-exp", 105, 115, sink))
	s.Require().NotNil(sink.header)
	s.Require().NotNil(sink.header.StartCheckpoint)
	s.Require().Equal(int64(100), sink.header.StartCheckpoint.Seq)
	s.Require().Nil(sink.header.EndCheckpoint, "no checkpoint at or after 115 yet")
	s.Require().Len(sink.header.Keys, 1)
	s.Require().Len(sink.entries, 11)
	s.Require().Equal(int64(105), sink.entries[0].Seq)
	s.Require().Equal(int64(115), sink.entries[10].Seq)

	// An offline verifier needs only the bundle: walk from the checkpoint.
	pub := ed25519.PublicKey(sink.header.Keys[0].PublicKey)
	cp := sink.header.StartCheckpoint
	s.Require().True(business.VerifyHash(pub, business.CheckpointHash("t-exp", cp.Seq, cp.EntryHash, cp.CreatedAt), cp.Signature, models.CanonVersionV2))
	// Entries 101..104 are outside the bundle, so the verifier re-exports from 101.
	sink2 := &collectingSink{}
	s.Require().NoError(st.verify.Export(ctx, "t-exp", 101, 115, sink2))
	prev := cp.EntryHash
	for _, e := range sink2.entries {
		s.Require().Equal(prev, e.PreviousHash)
		s.Require().Equal(business.EntryHashV2(e, prev), e.EntryHash)
		s.Require().True(business.VerifyHash(pub, e.EntryHash, e.Signature, e.CanonVersion))
		prev = e.EntryHash
	}
}

type collectingSink struct {
	header  *business.ExportHeader
	entries []*models.AuditEntry
}

func (c *collectingSink) Header(h *business.ExportHeader) error { c.header = h; return nil }
func (c *collectingSink) Entry(e *models.AuditEntry) error {
	c.entries = append(c.entries, e)
	return nil
}

func (s *ChainSuite) TestRead_SearchRequiresBoundedWindow() {
	st := s.newStack(nil)
	ctx := tests.TenantContext(st.svc.Ctx, "t-read")
	_, err := st.read.SearchEntries(ctx, "cre", nil, nil, 10, "")
	s.Require().ErrorIs(err, business.ErrSearchWindowRequired)
	start := time.Now().Add(-40 * 24 * time.Hour)
	end := time.Now()
	_, err = st.read.SearchEntries(ctx, "cre", &start, &end, 10, "")
	s.Require().ErrorIs(err, business.ErrSearchWindowRequired)
	start = time.Now().Add(-time.Hour)
	_, err = st.read.SearchEntries(ctx, "cre", &start, &end, 10, "")
	s.Require().NoError(err)
}
