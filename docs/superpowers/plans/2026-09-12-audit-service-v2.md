# Audit Service v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the audit service's mutex-guarded direct chain with a validated, durable intake drained by a multi-replica-safe chain writer, add checkpoints, key rotation, export and offline verification, and fix the `common/audit` interceptor's actor rule.

**Architecture:** Handlers validate and insert into `audit_intake`; a Frame background consumer drains intake per tenant under `pg_advisory_xact_lock`, assigns `seq`, hashes with a length-prefixed canonical encoding, signs with the active Ed25519 key, and CAS-updates `audit_chain_heads`. Checkpoints and keys make ranges verifiable offline. All layers follow handler → business → repository.

**Tech Stack:** Go 1.26, Frame v2.1.8 (datastore, tenancy RLS, background consumer, health, telemetry), Connect RPC, protovalidate, Postgres 16 via testcontainers, Buf (BSR `buf.build/antinvestor/audit`).

**Spec:** `docs/superpowers/specs/2026-09-12-audit-service-v2-design.md`

## Global Constraints

- No goroutines in test setup; suites extend `pkg/tests.BaseTestSuite`; real Postgres via testcontainers.
- `func` not `var` for package-level values that lint flags; `s.Require()` assertions.
- Client timeouts at construction only; no per-call `context.WithTimeout` around peer I/O; no `context.WithoutCancel`.
- Every model embeds `data.BaseModel`; global (non-tenant) tables still embed it but leave tenant fields empty and are not tenancy-enrolled by naming the model in `Migrate` after `tenancy` exclusion is not needed (Frame enrolls by field presence; global tables carry empty tenant ids and the RLS function matches empty GUC ⇒ visible).
- Transaction-scoped advisory locks only (`pg_advisory_xact_lock`).
- Proto changes are additive to `audit.v1`; published to BSR under label `feat-audit-v2` for development, `main` on merge via CI.
- Commit after each task; `go build ./... && go vet ./apps/audit/...` green before each commit.

---

## File map

| Path | Responsibility |
|------|----------------|
| `proto/audit/audit/v1/audit.proto` | Additive fields, new RPCs, permissions |
| `apps/audit/config/config.go` | `AUDIT_*` config per spec §16 |
| `apps/audit/service/models/models.go` | `AuditEntry` (+columns), `AuditIntake`, `AuditChainHead`, `AuditCheckpoint`, `AuditSigningKey`, `AuditManifest`, `AuditRejection` |
| `apps/audit/migrations/0001/20260912_audit_v2.sql` | Unique `(tenant_id, seq)`, partial indexes, backfill, revoke |
| `apps/audit/service/repository/*.go` | One repository per table; `ChainRepository` owns the locked batch transaction |
| `apps/audit/service/business/canon.go` | `canon_v2` encoder, JCS for JSON |
| `apps/audit/service/business/keys.go` | `KeyProvider` (file/vault-file loader, active key, reload, retired check) |
| `apps/audit/service/business/signer.go` | Sign/verify by `key_id`, legacy v1 hash kept for verification |
| `apps/audit/service/business/validator.go` | §6.2 rules |
| `apps/audit/service/business/manifest.go` | Manifest registry business |
| `apps/audit/service/business/ingest.go` | Create/Batch → intake |
| `apps/audit/service/business/writer.go` | Chain writer + checkpointer + retention + readiness state |
| `apps/audit/service/business/verify.go` | `VerifyIntegrity`, `Export` |
| `apps/audit/service/business/audit.go` | Read side (get/list/search) |
| `apps/audit/service/handlers/*.go` | Connect handlers, well-known keys HTTP handler, error mapping |
| `apps/audit/cmd/main.go` | Setup vs runtime wiring |
| `apps/audit/tests/base_testsuite.go` | Suite with Postgres container and Frame service |
| `common/audit/*.go` | Actor rule, sync send, new `With*`, no body capture |
| `common/auditverify/*.go` | `Canonical`, `VerifyBundle` |

---

### Task 1: Proto additions and BSR label push

**Files:** Modify `proto/audit/audit/v1/audit.proto`; `go.mod`.

**Produces:** generated `auditv1` types: `CreateAuditEntryRequest{entry_id, on_behalf_of, occurred_at, correlation_id, event_id, intent_id, instance_id, payload_hash, authorization_hash, policy_hash, device_key_id, state_from, state_to, resource_version, relations[]}`, `CreateAuditEntryResponse{intake_id, entry_id, state}`, `IntakeState` enum, `AuditEntryObject{seq, key_id, canon_version, state, …typed}`, `VerifyIntegrityRequest{start_seq,end_seq}`, `ExportAuditEntries`, `ListCheckpoints`, `GetSigningKeys`, `RegisterAuditManifest`, `GetAuditManifest`, `RequeueIntake`, `RetireSigningKey`; permissions list.

- [ ] Edit proto (additive; keep field numbers ≥ 12 on create request, ≥ 19 on entry object).
- [ ] `cd proto/audit && buf lint && buf breaking --against '.git#branch=main,subdir=proto/audit'`.
- [ ] `buf push --label feat-audit-v2`; note the commit; `go get buf.build/gen/go/antinvestor/audit/protocolbuffers/go@<ver> buf.build/gen/go/antinvestor/audit/connectrpc/go@<ver>`; `go build ./apps/audit/...` (old handlers still compile because changes are additive).
- [ ] Commit `feat(audit-proto): v2 fields, intake state, checkpoints, keys, export, manifests`.

### Task 2: Config, models, migration

**Files:** `apps/audit/config/config.go`, `apps/audit/service/models/models.go`, `apps/audit/service/repository/migrate.go`, `apps/audit/migrations/0001/20260912_audit_v2.sql`.

**Produces:**
```go
type AuditConfig struct { config.ConfigurationDefault
  SigningKeyRef, SigningKeyID string; KeyReloadInterval, WriterTick, HeadMaxAge, CheckpointInterval,
  IntakeCommittedRetention, RejectionsRetention string; WriterBatch, IntakeMaxBacklog, CheckpointEveryN,
  VerifyMaxEntries int; FrozenTenants string; RequireManifest bool }
// models: AuditEntry(+Seq, KeyID, CanonVersion, ManifestVersion, Unmanifested, EntryID, ActorServiceAccountID,
//   OnBehalfOf, OccurredAt, ReceivedAt, CorrelationID, EventID, IntentID, InstanceID, PayloadHash,
//   AuthorizationHash, PolicyHash, DeviceKeyID, StateFrom, StateTo, ResourceVersion, Relations data.JSONMap)
// AuditIntake{Service, EntryID, Payload data.JSONMap, ReceivedAt, State, Attempts, LastError, CommittedSeq}
// AuditChainHead{Seq, EntryHash}  (ID = tenant_id)
// AuditCheckpoint{Seq, EntryHash, KeyID, Signature}
// AuditSigningKey{KeyID, PublicKey []byte, Algorithm, ValidFrom, RetiredAt *time.Time}
// AuditManifest{Service, Version int, ContentHash, Content data.JSONMap, RegisteredBy}
// AuditRejection{Service, Reason, EntryID, ReceivedAt}
```
- [ ] Write models with `TableName()`; write config; register all models in `Migrate`.
- [ ] SQL migration: unique index `(tenant_id, seq)` (created after backfill in the same file: backfill via window function per tenant, `entry_id = id`, `occurred_at = received_at = created_at`, `key_id='k1'`, `canon_version=1`), heads from max seq, partial indexes, drop `idx_audit_entries_chain`.
- [ ] Test: `repository/migrate_test.go` runs `Migrate` on a container, inserts 3 legacy rows first (via raw SQL), asserts `seq` 1..3 and head row.
- [ ] Commit `feat(audit): v2 config, models and migration with seq backfill`.

### Task 3: Canonical encoding and signer

**Files:** `business/canon.go`, `business/canon_test.go`, `business/signer.go`, `business/signer_test.go`, `business/testdata/canon_v2/*.json`.

**Produces:**
```go
func CanonicalV2(e *models.AuditEntry) []byte
func CanonicalJSON(v any) ([]byte, error)                 // RFC 8785 subset: sorted keys, no whitespace, UTF-8, numbers via strconv 'g' for float64
func EntryHashV2(e *models.AuditEntry, previousHash string) string
func EntryHashV1(e *models.AuditEntry, previousHash string) string  // legacy pipe encoding, verification only
func CheckpointHash(tenantID string, seq int64, entryHash string, at time.Time) string
type Signer struct{ keyID string; priv ed25519.PrivateKey }
func (s *Signer) Sign(hashHex string) string
func VerifyHex(pub ed25519.PublicKey, hashHex, sigHex string) bool
```
- [ ] Golden-vector tests: empty entry, pipe characters, unicode, nested details, key order independence; v1 hash equals the old `ComputeHash` output for a fixture.
- [ ] Commit `feat(audit): canonical v2 encoding and key-aware signer`.

### Task 4: Key provider

**Files:** `business/keys.go`, `business/keys_test.go`, `repository/signing_key.go`.

**Produces:**
```go
type KeyProvider interface { Active() (*Signer, error); Public(keyID string) (ed25519.PublicKey, bool); Reload(ctx) error; Retire(ctx, keyID) error; List(ctx) ([]*models.AuditSigningKey, error) }
func NewKeyProvider(ctx, cfg *config.AuditConfig, repo repository.SigningKeyRepository) (KeyProvider, error)  // fails if ref unresolvable or public key mismatch; seeds row when absent and cfg.SeedKey
func LoadPrivateKeyRef(ref string) (ed25519.PrivateKey, error)  // file:// or vault:// (both read a file path; vault maps to /var/run/secrets/audit/<key_id>)
```
- [ ] Tests: file ref happy path; missing file errors; mismatch with stored public key errors; retired active key ⇒ `Active()` errors after `Reload`; `Public` for unknown id false.
- [ ] Commit `feat(audit): key provider with rotation and retirement`.

### Task 5: Validator and manifests

**Files:** `business/validator.go`, `business/validator_test.go`, `business/manifest.go`, `repository/manifest.go`.

**Produces:**
```go
type Caller struct{ ProfileID, ServiceAccountID, ServiceName, TenantID, PartitionID string; Roles []string; CanCreateAny bool }
func CallerFromClaims(ctx) Caller
type ValidationError struct{ Field, Reason string }  // implements error; Reason ∈ {schema, actor, service_binding, vocabulary, size, forbidden_content, time, hash}
func (v *Validator) Validate(ctx, caller Caller, req *auditv1.CreateAuditEntryRequest, now time.Time) (*NormalizedEntry, *ValidationError)
type ManifestBusiness interface { Register(ctx, caller, *auditv1.AuditManifest) (version int, err); Get(ctx, service string) (*models.AuditManifest, error); Lookup(ctx, service) (*Manifest, bool) }  // Lookup is cached 60 s
```
- [ ] Table-driven tests for every rule in spec §6.2; forbidden MSISDN and Luhn positives/negatives; time window edges; batch size.
- [ ] Manifest tests: register twice same content ⇒ same version; changed content ⇒ version+1; service mismatch ⇒ `PermissionDenied`.
- [ ] Commit `feat(audit): boundary validator and audit manifests`.

### Task 6: Intake ingest

**Files:** `business/ingest.go`, `repository/intake.go`, `repository/rejection.go`, `business/ingest_test.go`.

**Produces:**
```go
type IngestBusiness interface { Create(ctx, req) (*IntakeReceipt, error); CreateBatch(ctx, reqs) ([]*IntakeReceipt, error) }
type IntakeReceipt struct{ IntakeID, EntryID string; State string }
// errors: ValidationError → InvalidArgument/PermissionDenied; ErrBacklogExceeded → ResourceExhausted
```
- [ ] Tests: accept ⇒ row `ACCEPTED`; duplicate `entry_id` ⇒ same intake id; rejection ⇒ `audit_rejections` row without content; backlog over cap ⇒ `ErrBacklogExceeded`.
- [ ] Commit `feat(audit): durable intake ingest`.

### Task 7: Chain writer, checkpointer, retention

**Files:** `repository/chain.go` (`CommitBatch` transaction), `business/writer.go`, `business/writer_test.go`.

**Produces:**
```go
type ChainRepository interface {
  DiscoverBacklog(ctx, limit int) ([]TenantBacklog, error)               // AllowGlobal principal
  CommitBatch(ctx, tenantID string, fn func(tx ChainTx) error) error     // xact lock + head FOR UPDATE + CAS; fn does the work
}
type ChainTx interface { Head() *models.AuditChainHead; ClaimIntake(limit int) ([]*models.AuditIntake, error); InsertEntries([]*models.AuditEntry) error; InsertCheckpoint(*models.AuditCheckpoint) error; MarkCommitted(ids []string, seqs []int64) error; MarkFailed(id, reason string) error; AdvanceHead(newSeq int64, hash string) error }
type Writer struct{…}; func NewWriter(svc *frame.Service, cfg, repos, keys) *Writer
func (w *Writer) Run(ctx) error          // loop; returns only on ctx.Done (nil) or fatal key error
func (w *Writer) Tick(ctx) (Stats, error) // one pass; used by tests
func (w *Writer) ReadinessChecker() frame.Checker; func (w *Writer) LivenessChecker() frame.Checker
```
- [ ] Tests: 1 tenant × 2 000 intake rows ⇒ contiguous seq, head matches last hash, checkpoints at every N; two `Writer` instances against the same DB with 4 tenants, ticked alternately ⇒ no gaps/dupes, `cas_conflicts==0`; cancel mid-batch (ctx cancel inside `fn`) ⇒ rollback, re-tick commits; poison row (manifest deleted ⇒ simulate via a hook) ⇒ FAILED and batch continues; frozen tenant skipped; readiness flips on backlog age.
- [ ] Commit `feat(audit): chain writer with per-tenant seq, CAS head, checkpoints`.

### Task 8: Verify and export

**Files:** `business/verify.go`, `business/verify_test.go`, `repository/checkpoint.go`, `repository/audit_entry.go` (`ListChainBySeq`).

**Produces:**
```go
func (b *verifyBusiness) VerifyIntegrity(ctx, tenantID string, startSeq, endSeq int64) (*IntegrityResult, error)
func (b *verifyBusiness) Export(ctx, tenantID string, startSeq, endSeq int64, send func(*auditv1.ExportAuditEntriesResponse) error) error
```
- [ ] Tests: verify from genesis, from checkpoint, across key rotation, across canon v1→v2 boundary; tamper a row via raw SQL ⇒ `first_invalid_seq`; export 3 pages verifies with `auditverify`.
- [ ] Commit `feat(audit): bounded verification and export`.

### Task 9: Handlers and main

**Files:** `handlers/audit.go` (rewrite), `handlers/keys_http.go`, `handlers/errors.go`, `cmd/main.go`.

- [ ] Map `ValidationError` → Connect codes with `connect.ErrorDetail`; remove `grpc/status`; delete `EmitAuditEntry`/`GetAuditBusiness`.
- [ ] `main.go`: fail without key; `WithSystemPrincipalAllowGlobal`; `AddHealthCheck`/`AddLivenessCheck`; `WithBackgroundConsumer(writer.Run)`; mux with `/.well-known/audit-keys.json`.
- [ ] Handler tests via suite: create with SA caller mismatch ⇒ `PermissionDenied`; SA w/o on_behalf_of ⇒ `InvalidArgument`; duplicate idempotent; get after tick shows `seq`.
- [ ] Commit `feat(audit): v2 handlers and runtime wiring`.

### Task 10: `common/audit` and `common/auditverify`

**Files (repo `antinvestor/common`):** `audit/audit.go`, `audit/http.go`, `audit/actor.go`, `audit/actor_test.go`, `auditverify/canon.go`, `auditverify/verify.go`, `auditverify/verify_test.go`, `audit/go.mod` bump.

- [ ] Actor rule per spec §9.1; synchronous send; delete `VerboseConfig` and body capture; new `With*`; `ManifestFromConstants`.
- [ ] `auditverify.Canonical` byte-identical to `business.CanonicalV2` (shared golden vectors copied).
- [ ] Commit in common on branch `feat/audit-v2`.

### Task 11: Docs and deployment notes

- [ ] Update `apps/audit` section references in `CLAUDE.md`; add `deployments` change list to the spec's §17 as a PR checklist.
- [ ] Commit.

## Self-review

Spec coverage: §6 (T5, T6, T7), §7 (T2, T3, T4, T7), §8 (T1, T9), §9 (T10), §10 (T9), §11 (T7 retention), §12/§13 (T7 tests), §15 (metrics in T6/T7 via `telemetry.NewBusinessMetrics`), §16 (T2), §17/§18 (T2 migration, T11), §19 (each task).
