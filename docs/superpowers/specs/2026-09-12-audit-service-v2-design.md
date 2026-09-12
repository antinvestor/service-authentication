# Audit Service v2 — Design

**Date:** 2026-09-12
**Status:** Proposed
**Scope:** `apps/audit` in this repo, the `audit.v1` proto under `proto/audit/audit/v1/audit.proto`, the `antinvestor/common/audit` client/interceptor, and the `service-audit` deployment in `deployments/manifests/namespaces/auth/audit/`.
**Motivation:** the Stawi Group Financial OS (`stawilabs/stawi/docs/GFOS_ARCHITECTURE.md` §10.3, §21 K7) needs a server attestation chain that is durable, safe across replicas, incrementally verifiable, exportable, and rotatable. Every finding below was confirmed against the current code at the commit this document was last revised.

**Related:** `docs/IDENTITY_AND_AUTHORIZATION.md` (JWT `sub === profile_id`), `docs/PERMISSION_REGISTRATION.md` (manifest registration pattern the audit manifests reuse), `docs/platform-timescale-hypertable-analysis.md` (superseded for this table; see §7.1).

---

## 1. Goals, non-goals and assumptions

### 1.1 Goals

| # | Goal | Measured by |
|---|------|-------------|
| G1 | An accepted entry is never lost | Accepted ⇒ row in Postgres before the RPC returns; committed ⇒ in the chain with a `seq` |
| G2 | The chain never forks, at any replica count | One head row per tenant; CAS under a transaction-scoped advisory lock |
| G3 | Verification cost is proportional to the range verified | `VerifyIntegrity(start_seq, end_seq)` starts from the nearest checkpoint |
| G4 | A third party can verify a bundle without the service | `ExportAuditEntries` + published public keys + `common/auditverify` |
| G5 | Signing keys rotate without breaking history | `key_id` on every entry and checkpoint; retired keys keep verifying |
| G6 | Only well-formed, attributable, PII-free entries enter the chain | Validator at the RPC boundary; rejections are visible errors and rows |
| G7 | Producer latency is bounded | Interceptor call ≤ 2 s, soft-fail; ingestion never waits on the chain |
| G8 | Operable by one on-call engineer | Backlog, head age and checkpoint age are metrics with alerts and a runbook |

### 1.2 Non-goals

- Auditing automated system behaviour (scheduled jobs, workflow commands, projections). That belongs to the producing service's event stream (GFOS §10.1).
- Anchoring checkpoints on-chain. Consumers such as `stawi/apps/settlement` anchor; this service only produces the anchorable unit (§7.3).
- Free-text search over `details`. `SearchAuditEntries` is retained but bounded (§8); full-text indexing is out of scope.
- Proving that a user cryptographically authorised a value movement (GFOS §10.4). The chain carries hashes of that evidence, not the evidence.

### 1.3 Assumptions (stated, not verified here)

| Assumption | Consequence if false |
|------------|----------------------|
| Postgres is reached through a pooler (`pooler-rw.datastore.svc`) that may run in transaction mode | Session-level advisory locks are unsafe; only `pg_advisory_xact_lock` inside a transaction is used (§6.4) |
| Producers hold a service-account JWT whose `ext.service_account_id` and `service_name` are populated by the token webhook | The service-binding check (§6.2) cannot resolve a caller and rejects with `PermissionDenied`; the fix is in `apps/default`, not here |
| Clock skew between producers and the audit service is under 5 minutes (NTP) | Valid entries are rejected by the time check; the manifest's `allow_backdating` is the escape hatch |
| Vault (`antinvestor/auth/audit/signing`) is the key store | `AUDIT_SIGNING_KEY_REF` resolves a Vault path; a file path is supported for local and test runs |
| Tenancy row-level security is enforced on audit tables by Frame (`FORCE ROW LEVEL SECURITY`, policy `app_tenancy_isolation`) | The writer's per-tenant `SystemPrincipal` binding is unnecessary but harmless |

---

## 2. Current weaknesses

| # | Weakness | Where |
|---|----------|-------|
| W1 | Chain tip is guarded by a process-local `sync.Mutex`; the deployment autoscales to 10 replicas (`autoscaling.maxReplicas: 10`), so two replicas read the same tip and fork the chain | `service/business/audit.go` `CreateEntry`/`BatchCreateEntries` (`ab.mu`); `service-audit.yaml` |
| W2 | Tip is found by `ORDER BY created_at DESC, id DESC` on the primary; no sequence number, so ranges cannot be verified without walking from genesis | `service/repository/audit_entry.go` `GetLatestHash`; `VerifyIntegrity` starts with `previousHash = ""` |
| W3 | Interceptor sends entries in a goroutine with a 10 s timeout on `context.Background()` and discards the error; entries are lost under load, on outage, and on process exit | `common/audit/audit.go` `record` (`go a.send(...)`) and `send` |
| W4 | Entries with an empty `profile_id` are dropped silently (`if a.auditClient != nil && profileID != ""`) instead of being rejected; an operator acting for a user has no way to record both identities | `common/audit/audit.go` `record`; `CreateAuditEntryRequest.profile_id min_len = 1` |
| W5 | The "skip internal callers" predicate is inverted relative to intent. `shouldSkipInternal` calls Frame `IsInternalSystem()`, which matches the role string `internal`. That role is granted to **root admin/owner humans** (`login_step_4_consent.go` "Grant internal role to admin/owner users"), so the most privileged people are never audited. Service-account tokens are identified by `ext.service_account_id` and are **not** reliably skipped | `common/audit/audit.go` `shouldSkipInternal`; Frame `security_claims.go` `ConstantSystemInternalRole = "internal"`; `apps/default/service/handlers/webhook.go` SA claims |
| W6 | One signing key, no key id on entries, no rotation; if `AUDIT_SIGNING_KEY` is empty the process **generates an ephemeral key and starts anyway**, producing entries nobody can verify after a restart | `config.go` `AUDIT_SIGNING_KEY`; `cmd/main.go` `loadOrGenerateSigner` |
| W7 | No export; `ListAuditEntries` is a query surface with a 500-row cap and non-streaming semantics (one `stream.Send`) | `repository/audit_entry.go` `maxLimit`; `handlers/audit.go` |
| W8 | Producers can log under any `service` name and any vocabulary; the service accepts whatever arrives, including request/response bodies with PII when `VerboseConfig` is on (4 KiB truncated snapshots) | `handlers/audit.go` `CreateAuditEntry`; `common/audit/audit.go` `VerboseConfig`, `marshalProto` |
| W9 | Verification is unbounded: it grows with chain length forever, and uses `OFFSET` pagination (quadratic) | consequence of W2; `ListChain` |
| W10 | Relations, state changes and bodies are flattened into `details`, so the fields everyone filters on are not columns | `common/audit/audit.go` `send` |
| W11 | `SearchAuditEntries` runs `ILIKE '%q%'` across four columns with no mandatory time window; a full scan per call on a growing table | `repository/audit_entry.go` `Search` |
| W12 | `EmitAuditEntry` / `GetAuditBusiness` expose an in-process write path that bypasses the RPC interceptors and any future validator | `handlers/audit.go` |
| W13 | Hash pre-image is `fmt.Sprintf("%s|%s|…")`, ambiguous when a field contains `|`; `details` is hashed through `encoding/json` map marshalling, which is key-sorted in Go but not defined for other verifiers | `service/business/signer.go` `ComputeHash` |
| W14 | Readiness and liveness probes are `tcpSocket`, so the process reports ready while the database is down or the chain writer is wedged | `service-audit.yaml` probes |
| W15 | The private key is injected as an environment variable, visible to anyone with `kubectl exec`/pod spec read, and cannot be rotated without a restart | `service-audit.yaml` `AUDIT_SIGNING_KEY` from secret `audit-signing-key` |
| W16 | Table is still described in comments/migrations as a Timescale hypertable; TimescaleDB was removed platform-wide in #858, the composite PK `(id, created_at)` remains, and no partitioning or retention exists | `migrations/0001/20260420_audit_entries_composite_pk.sql`; commit `83edcb1` |

---

## 3. Principles

0. **The audit chain records human actions.** A person (member, officer, guardian, operator, administrator) doing something in the system is the unit of audit. Automated system behaviour is not audited here; it belongs to the producing service's own event stream. This keeps the chain small, meaningful, and cheap to verify.
1. **The audit service is the only component that queues audit work.** Producers call `AuditService` RPCs. The service validates every entry at the boundary, persists it to its own intake, and drains that intake into the chain with its own worker. No producer publishes to a broker topic that the audit service consumes blindly, and no in-process caller bypasses the RPC boundary.
2. **Validation before persistence.** An entry is accepted only if it is well-formed, sized, from a service allowed to log under that `service` name, using a registered vocabulary, and free of forbidden content. Rejection is a Connect error the producer sees.
3. **Acceptance is durable; chaining is asynchronous.** The RPC returns once the entry is in the intake table. Sequencing, hashing and signing happen in a background writer under a per-tenant lock. Producers never wait on the chain.
4. **The chain head is a row, not a query.** `audit_chain_heads` holds the tip per tenant and is updated with compare-and-swap in the same transaction as the entry insert.
5. **Everything is verifiable without the service.** Sequence numbers, checkpoints, published public keys and an export RPC let `common/auditverify` check a bundle offline.
6. **Library first.** Frame provides the datastore pool, tenancy RLS binding, background consumer, health checkers, OpenTelemetry metrics (`telemetry.BusinessMetrics`), and setup-plan steps. `common` provides the Connect client factory, interceptors, permission manifests and the service catalog. Custom code is limited to the validator, canonical encoding, chain writer, checkpointer, key provider and verifier.
7. **Fail closed on identity, fail soft on availability.** Missing key, unresolvable caller, or unregistered vocabulary (when required) is an error. An unavailable audit service degrades the producer to structured-log-only auditing with a counter, never to a blocked request.

---

## 4. Architecture overview

```
 Producer (service_profile, service_identity, finance, …)
 ┌──────────────────────────────────────────────────────────┐
 │ Connect handler ─► common/audit Interceptor              │
 │   person-actor rule (§9.1) · With* enrichment            │
 │   sync CreateAuditEntry, 2 s client timeout, soft-fail   │
 └───────────────────────────┬──────────────────────────────┘
                             │ JWT (SA: ext.service_account_id, service_name)
                             ▼
 Audit service (apps/audit)  — N replicas behind HPA
 ┌──────────────────────────────────────────────────────────┐
 │ Interaction plane                                        │
 │   Connect RPCs: Create/Batch · Get/List/Search           │
 │   Verify · Export · ListCheckpoints · GetSigningKeys     │
 │   RegisterAuditManifest/GetAuditManifest                 │
 │   GET /.well-known/audit-keys.json (unauthenticated)     │
 │   /readyz /livez (Frame)                                 │
 ├──────────────────────────────────────────────────────────┤
 │ Control plane                                            │
 │   Validator (§6.2) · Manifest registry (§6.3)            │
 │   Key provider + active key selection (§7.4)             │
 ├──────────────────────────────────────────────────────────┤
 │ Execution plane (Frame background consumer)              │
 │   Chain writer (§6.4)  · Checkpointer (§7.3)             │
 │   Rejection recorder   · Backlog health checker (§10)    │
 ├──────────────────────────────────────────────────────────┤
 │ Data plane (Postgres, tenancy RLS)                       │
 │   audit_intake · audit_entries · audit_chain_heads       │
 │   audit_checkpoints · audit_signing_keys                 │
 │   audit_manifests · audit_rejections                     │
 ├──────────────────────────────────────────────────────────┤
 │ Integration plane                                        │
 │   Hydra (JWT verify) · Keto (function + tenancy access)  │
 │   Tenancy (permission registration, setup Job only)      │
 │   Vault (signing key) · OTel collector                   │
 └──────────────────────────────────────────────────────────┘
                             │
                             ▼
 Consumers: stawi/settlement (anchors checkpoints), auditors (common/auditverify), admin UI (List/Get)
```

### 4.1 Plane responsibilities and providing capability

| Plane | Responsibility | Existing capability | Custom (verified gap) |
|-------|----------------|---------------------|-----------------------|
| Interaction | Connect RPC surface, auth, tenancy and function-access interceptors | `connectInterceptors.DefaultList`, `authorizer.NewTenancyAccessChecker`, `authorizer.NewFunctionChecker`, `permissions.BuildProcedureMap` | Export streaming handler; well-known keys handler |
| Control | Request validation, vocabulary, key selection, config | `buf.validate` constraints; Frame `config.LoadWithOIDC`; Frame setup plan (`svc.Setup().RegisterFunc`) | Validator rules (§6.2); manifest registry; key provider |
| Execution | Intake drain, sequencing, hashing, signing, checkpointing | `frame.WithBackgroundConsumer`; `tenancy.WithSystemPrincipal`; `pool.DB(ctx,false).Transaction` | Chain writer; checkpointer; canonical encoding |
| Data | Storage, RLS, retention | Frame datastore + `tenancy/postgres` provider (RLS install on tenanted models); GORM auto-migrate + SQL migrations | Schema (§7.1); role grants revoking UPDATE/DELETE |
| Integration | Token verification, ReBAC, permission registration, key store, telemetry | Frame security manager; `frame.WithPermissionRegistration`; Frame OTel wiring; `telemetry.NewBusinessMetrics` | Vault/file key loader (thin adapter) |

Trust boundaries: (a) producer → audit RPC (JWT, per-RPC permission, service binding); (b) audit RPC → intake (validator); (c) intake → chain (writer runs with a scoped `SystemPrincipal`, never with caller claims); (d) chain → world (export and keys are read-only; keys are public).

---

## 5. Execution model

| Component | Runs where | Lifecycle | Concurrency | Cancellation |
|-----------|------------|-----------|-------------|--------------|
| Setup Job (`RunSetupForProcess`) | Kubernetes Job `migration.args: ["migrate"]` | Runs migrate → seed signing key row → register permissions; exits 0/1 | Single process; Frame migration advisory lock | Job timeout |
| Connect handlers | Every replica | Started by `svc.Run`; drained by Frame on SIGTERM with `HTTP_SERVER_SHUTDOWN_TIMEOUT` (15 s) and `preStop sleep 15` | One goroutine per request (net/http); no shared mutable state beyond the DB pool | Request context |
| Chain writer | Every replica | `frame.WithBackgroundConsumer(writer.Run)`; `Run` loops until `ctx.Done()`; a non-nil return stops the service (Frame semantics) so `Run` only returns on fatal misconfiguration | One loop per replica; per-tenant batches serialised by `pg_advisory_xact_lock`; tenants spread across replicas by `SKIP LOCKED` | Service context; an in-flight transaction is rolled back by Postgres on connection close |
| Checkpointer | Every replica, inside the writer loop (single background consumer slot in Frame) | Ticks every `AUDIT_CHECKPOINT_INTERVAL`; also triggered by the writer every `AUDIT_CHECKPOINT_EVERY_N` entries | Same lock as the writer for that tenant | Service context |
| Backlog health checker | Every replica | Registered with `svc.AddHealthCheck` | Cached result refreshed by the writer loop; the probe reads memory, never the DB | n/a |
| Key provider | Every replica | Loaded at start; re-read on `AUDIT_KEY_RELOAD_INTERVAL` to pick up a rotated active key | Atomic pointer swap | Service context |

Frame registers exactly one background consumer function. The writer and checkpointer are therefore composed into one `Run(ctx)` that owns a ticker for each and runs them sequentially per tick; neither spawns unbounded goroutines.

---

## 6. Ingestion

### 6.1 RPC boundary

`CreateAuditEntry` and `BatchCreateAuditEntries` remain the only write paths. `EmitAuditEntry` and `GetAuditBusiness` are deleted (W12). Both RPCs run the validator (§6.2) and, on success, insert into `audit_intake` in one transaction and return `{intake_id, state: ACCEPTED}`. They do not touch the chain. A producer that needs durability calls the RPC from its own outbox consumer and retries on `Unavailable`; the `entry_id` it supplies makes retries idempotent.

Producer identity comes from JWT claims as Frame exposes them: `claims.Ext["service_account_id"]` (set by the token webhook for `client_credentials` tokens) and `claims.GetServiceName()`. The claim, not the request field, decides which `service` value the entry may carry.

### 6.2 Validator

| Check | Rule | Error |
|-------|------|-------|
| Schema | `buf.validate` constraints on the request | `InvalidArgument` |
| Actor | `profile_id` (the person) is required. `on_behalf_of` is set when an operator or administrator acts for another person. `actor_service_account_id` is filled from the caller's claim, never from the request. Requests whose `profile_id` is a service-account profile (the caller's own `profile_id` when `service_account_id` is present and `on_behalf_of` is empty) are rejected, never silently dropped | `InvalidArgument` |
| Service binding | `request.service` must equal the caller's `service_name` claim, or the caller must hold `audit_create_any` (reserved for the audit operator role) | `PermissionDenied` |
| Vocabulary | `(service, action, resource_type)` must exist in the service's registered audit manifest (§6.3) unless the manifest declares `open_vocabulary` | `InvalidArgument` with the unknown term |
| Size | `details` ≤ 16 KiB serialised; each string field ≤ 512 bytes; `user_agent` ≤ 1 KiB; batch ≤ 100 | `InvalidArgument` |
| Forbidden content | `details` keys matching `password|secret|token|authorization|cookie|private_key|otp|pin` (case-insensitive) are rejected; values matching an MSISDN (`^\+?[0-9]{9,15}$`) or a Luhn-valid 13–19 digit run are rejected; a manifest may extend the key list | `InvalidArgument` naming the key, not the value |
| Time | `occurred_at` within ±5 minutes of receipt unless the manifest allows backdating (for outbox replays), and never in the future by more than 30 s | `InvalidArgument` |
| Hashes | `payload_hash`, `authorization_hash`, `policy_hash` are 32-byte lowercase hex when present | `InvalidArgument` |
| Idempotency | `(tenant_id, service, entry_id)` unique; a duplicate returns the existing `intake_id` with `state` as it stands. A request without `entry_id` gets a server-generated one | none |
| Tenant | `tenant_id`/`partition_id` come from claims; a request cannot name a tenant | n/a (RLS `WITH CHECK` also enforces) |

Rejections are counted per `(service, reason)` and surfaced as a metric; a rejected entry is also recorded in `audit_rejections` (tenant, service, reason, `entry_id`, received_at; never the offending content) so a misbehaving producer is itself auditable. `audit_rejections` is bounded by a 90-day retention job (§11).

### 6.3 Audit manifests

Each producing service registers its vocabulary the same way it registers permissions (`docs/PERMISSION_REGISTRATION.md`): a manifest published by its setup Job through `RegisterAuditManifest` (service-account authenticated, `audit_manifest_manage`, and the caller's `service_name` must equal `manifest.service` unless it holds `audit_create_any`). A manifest lists `actions[]`, `resource_types[]`, `open_vocabulary bool`, `allow_backdating bool`, `extra_forbidden_keys[]`. Manifests are versioned (monotonic `version` per service, content-hash deduplicated so a re-run of an unchanged setup Job is a no-op) and kept; entries record `manifest_version`. Until a service registers a manifest, its entries are accepted with `open_vocabulary` semantics and flagged `unmanifested = true`, so adoption is incremental. `AUDIT_REQUIRE_MANIFEST=true` turns the flag into a rejection once all producers have registered.

The `common/audit` constants (`ResourceProfile`, `ActionCreate`, …) become the source for a producer's manifest: `audit.ManifestFromConstants(service, actions, resources)` builds the request so vocabulary lives in one place.

### 6.4 Intake and writer

```
audit_intake (id pk, tenant_id, partition_id, service, entry_id, payload jsonb,
              received_at, state: ACCEPTED|COMMITTED|FAILED, attempts int, last_error text,
              committed_seq bigint)
  unique (tenant_id, service, entry_id)
  index (state, received_at) where state = 'ACCEPTED'      -- drain scan
  index (tenant_id, state)                                  -- backlog per tenant
```

The chain writer is the Frame background consumer. Each tick (`AUDIT_WRITER_TICK`, default 100 ms, backing off to 1 s when idle):

1. **Discover work** under `tenancy.WithSystemPrincipal(ctx, {ServiceName: "service_audit", AllowGlobal: true, Reason: "intake-scan"})`: `SELECT tenant_id, count(*) FROM audit_intake WHERE state='ACCEPTED' GROUP BY 1 ORDER BY min(received_at) LIMIT 32`. The service is allow-listed with `frame.WithSystemPrincipalAllowGlobal("service_audit")` so this works under `FRAME_TENANCY_SECURITY_MODE=fail-closed`.
2. **Per tenant**, open a transaction on the primary with a scoped principal `{TenantID: tenant}` so RLS binds the session GUCs and `WITH CHECK` passes on insert:
   - `SELECT pg_advisory_xact_lock(hashtext(tenant_id))` — transaction-scoped, so correct through a transaction-mode pooler. Frame's `AdvisoryLock` helper is session-level and pins a connection; it is used for migrations only, not here.
   - `SELECT … FROM audit_chain_heads WHERE tenant_id=$1 FOR UPDATE` (insert the genesis row `seq=0, entry_hash=''` if absent).
   - `SELECT … FROM audit_intake WHERE tenant_id=$1 AND state='ACCEPTED' ORDER BY received_at, id LIMIT $batch FOR UPDATE SKIP LOCKED` (`AUDIT_WRITER_BATCH`, default 500).
   - Assign `seq = head.seq + 1 …`, compute `entry_hash` and `signature` in order with the active key, multi-row insert into `audit_entries` (chunks of 100 to stay under the parameter limit).
   - `UPDATE audit_chain_heads SET seq=$new, entry_hash=$h, updated_at=now() WHERE tenant_id=$1 AND seq=$expected`; if `RowsAffected != 1` the transaction rolls back and the batch is retried next tick. This cannot happen while the lock is held; it is a belt-and-braces guard against a lock-free code path being introduced later.
   - `UPDATE audit_intake SET state='COMMITTED', committed_seq=… WHERE id = ANY($ids)`.
   - Commit. Emit `audit_commit_latency` (now − received_at) per entry and `audit_writer_batch_size`.
3. **Poison handling**: if signing or canonicalisation fails for one row (should be impossible after validation, but e.g. a manifest deleted between accept and commit), that row alone is marked `FAILED` with `last_error`, `attempts++`, and the batch continues without it. `FAILED` rows never block the head. A `FAILED` count > 0 raises an alert; an operator resolves by fixing data and setting `state='ACCEPTED'` through `RequeueIntake` (`audit_operate` permission), which is itself audited.
4. **Backpressure**: if a tenant's backlog exceeds `AUDIT_INTAKE_MAX_BACKLOG` (default 50 000), `CreateAuditEntry` for that tenant returns `ResourceExhausted` with a `Retry-After` of 5 s. Producers soft-fail; the metric fires the alert. This bounds intake growth during a chain-writer outage instead of letting the table grow until the disk fills.

Several replicas may run the writer; the advisory lock serialises them per tenant and `SKIP LOCKED` spreads tenants across replicas. Ordering within the chain is receipt order at the intake, which is what a server attestation should mean. Producers that need causal order across their own entries send them in one batch (a batch is inserted into intake with monotonically increasing `received_at` microseconds and consecutive ids, so it commits contiguous).

---

## 7. Chain

### 7.1 Tables

TimescaleDB is gone (#858); all tables are plain Postgres. `audit_entries` keeps its composite primary key `(id, created_at)` for compatibility, and gains a real uniqueness guarantee on the chain position, which was impossible under the hypertable constraint.

```
audit_entries (existing, pk (id, created_at)) + columns:
  seq bigint not null, key_id varchar(32) not null,
  canon_version smallint not null default 1, manifest_version int, unmanifested bool not null default false,
  entry_id varchar(64) not null, actor_service_account_id varchar(50), on_behalf_of varchar(50),
  occurred_at timestamptz not null, received_at timestamptz not null,
  correlation_id varchar(64), event_id varchar(64), intent_id varchar(64), instance_id varchar(64),
  payload_hash char(64), authorization_hash char(64), policy_hash char(64), device_key_id varchar(64),
  state_from varchar(64), state_to varchar(64), resource_version bigint,
  relations jsonb                                             -- moved out of details
  unique (tenant_id, seq)                                     -- chain walk + fork guard at the storage level
  index (intent_id) where intent_id is not null
  index (correlation_id) where correlation_id is not null
  index (event_id) where event_id is not null
audit_chain_heads (tenant_id pk, seq bigint, entry_hash char(64), updated_at)
audit_checkpoints (tenant_id, seq, entry_hash, key_id, signature, created_at; pk (tenant_id, seq))
audit_signing_keys (key_id pk, public_key bytea, algorithm varchar(16) default 'ed25519',
                    valid_from timestamptz, retired_at timestamptz, created_at)
audit_manifests (service, version, content_hash char(64), content jsonb, registered_by, created_at; pk (service, version))
audit_intake (§6.4)
audit_rejections (id, tenant_id, service, reason varchar(64), entry_id, received_at; index (service, received_at))
```

Existing single-column indexes and the `(x, created_at DESC, id DESC)` family stay for list queries. `idx_audit_entries_chain (tenant_id, created_at, id)` is dropped after backfill; the chain walks by `seq`.

`UPDATE` and `DELETE` on `audit_entries` and `audit_checkpoints` are blocked by a `BEFORE UPDATE OR DELETE` trigger, and `audit_signing_keys` by a trigger that permits only setting `retired_at` once. Triggers rather than a role-level `REVOKE` because the deployment runs migration and runtime under one database role; the backfill runs before the triggers are installed in the same migration file. `audit_chain_heads` and `audit_intake` are the only mutable chain-related tables. Frame's tenancy provider installs `FORCE ROW LEVEL SECURITY` and `app_tenancy_isolation` on every model that embeds `data.BaseModel`; `audit_signing_keys` and `audit_manifests` embed `tenancy.UnscopedMarker` so they stay global. The chain head, checkpoints and the seq-ordered chain walk are tenant-level structures that span every partition of a tenant, so the repositories read them under a tenant-scoped `SystemPrincipal` derived from the caller's tenant; browsing (`List`, `Search`, `GetAuditEntry`) stays scoped to the caller's partition.

Two storage facts shape the encoding: `jsonb` columns read `NULL` back as an empty map, and `char(n)` columns blank-pad, so hash columns are `varchar(64)` and the canonical form treats nil and empty maps identically. Timestamps are truncated to microseconds before signing because that is what Postgres stores.

