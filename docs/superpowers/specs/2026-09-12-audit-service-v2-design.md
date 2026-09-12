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

`UPDATE` and `DELETE` on `audit_entries`, `audit_checkpoints`, `audit_signing_keys` are revoked from the runtime database role (`REVOKE UPDATE, DELETE ON … FROM audit_runtime`); the migration role keeps them for backfill. `audit_chain_heads` and `audit_intake` are the only mutable chain-related tables. Frame's tenancy provider installs `FORCE ROW LEVEL SECURITY` and `app_tenancy_isolation` on every table that carries `tenant_id`/`partition_id`; `audit_chain_heads`, `audit_checkpoints` and `audit_intake` are modelled with `data.BaseModel` so they are enrolled; `audit_signing_keys` and `audit_manifests` are global and are modelled without tenancy fields.

### 7.2 Canonical encoding and hash

```
canon_v2(entry) = concat over fields in the fixed order below of
                  uvarint(len(field_bytes)) ‖ field_bytes
fields: canon_version, tenant_id, partition_id, seq, entry_id, service, manifest_version,
        profile_id, on_behalf_of, actor_service_account_id, action, resource_type, resource_id,
        resource_version, state_from, state_to, target_profile_id, device_id, device_key_id,
        ip_address, user_agent, trace_id, correlation_id, event_id, intent_id, instance_id,
        payload_hash, authorization_hash, policy_hash,
        occurred_at (RFC 3339 UTC, microseconds), received_at (same), created_at (same),
        relations (RFC 8785 JSON canonical form), details (RFC 8785 JSON canonical form)
entry_hash = hex(SHA-256(canon_v2(entry) ‖ previous_hash_bytes))
signature  = hex(Ed25519(key_id).sign(SHA-256 digest bytes))
```

Integers are encoded as decimal ASCII; absent optional fields encode as length 0. `details` and `relations` use JSON Canonicalization Scheme (RFC 8785) so any language reproduces the bytes. The encoder lives once in `service/business/canon.go` and is copied verbatim (same package tests, golden vectors in `testdata/canon_v2/*.json`) into `common/auditverify`. `canon_version = 1` denotes the legacy pipe-delimited pre-image and is only ever read, never written, after migration.

Checkpoint pre-image: `"chk" ‖ tenant_id ‖ seq ‖ entry_hash ‖ created_at`, same length-prefix rule.

### 7.3 Checkpoints

Every `AUDIT_CHECKPOINT_INTERVAL` (default 1 h) per active tenant, and every `AUDIT_CHECKPOINT_EVERY_N` entries (default 10 000), the writer inserts a checkpoint `(tenant_id, seq, entry_hash)` signed with the active key, inside the same transaction as the batch that crossed the threshold (so a checkpoint can never point at an uncommitted head). Checkpoints are what external systems anchor. `VerifyIntegrity(start_seq, end_seq)` loads the checkpoint at or before `start_seq`, verifies its signature, walks forward by `seq` in pages of 1 000 (keyset on `seq`, never `OFFSET`), and stops at `end_seq`; cost is proportional to the range. A `max_entries` guard (default 1 M) returns `partial = true` with the last verified `seq` so a client can continue.

### 7.4 Keys

`AUDIT_SIGNING_KEY` is replaced by `AUDIT_SIGNING_KEY_REF` plus `AUDIT_SIGNING_KEY_ID`:

| Ref form | Resolution |
|----------|------------|
| `vault://antinvestor/auth/audit/signing#private_key` | Read via the External Secrets–projected file `/var/run/secrets/audit/<key_id>` (the secret is mounted as a volume, not an env var; W15). The process reads the file at start and on reload |
| `file:///path` | Local development and tests |

At startup the runtime process **refuses to start** without a resolvable key (W6). The setup Job inserts `audit_signing_keys(key_id, public_key, valid_from=now())` if absent; the runtime verifies that the loaded private key matches the stored public key for `AUDIT_SIGNING_KEY_ID` and fails otherwise.

Rotation procedure (§20.1): generate `k2` in Vault, add it to the secret, run the setup Job with `AUDIT_SIGNING_KEY_ID=k2` (inserts the public key), roll the deployment with `AUDIT_SIGNING_KEY_ID=k2`, then `RetireSigningKey(k1)` sets `retired_at`. Entries and checkpoints carry `key_id`; retired keys keep verifying; a retired key can never sign (the writer checks `retired_at IS NULL` on its active key at every reload and stops with an error if it is not). Public keys are served unauthenticated at `GET /.well-known/audit-keys.json` (JSON: `keys[{key_id, algorithm, public_key_hex, valid_from, retired_at}]`, `Cache-Control: max-age=300`) and via `GetSigningKeys`.

---

## 8. API changes (`audit.v1`)

All changes are additive to `audit.v1`; field numbers are appended and no existing field changes meaning, so v1 clients keep working during rollout (§18).

| RPC | Change |
|-----|--------|
| `CreateAuditEntry`, `BatchCreateAuditEntries` | Request gains `entry_id`, `on_behalf_of`, `occurred_at`, `correlation_id`, `event_id`, `intent_id`, `instance_id`, `payload_hash`, `authorization_hash`, `policy_hash`, `device_key_id`, `state_from`, `state_to`, `resource_version`, `relations[]`. `profile_id` stays required (it is the person). `actor_service_account_id` is response-only, filled from claims. Response returns `intake_id`, `entry_id` and `state`; the chained entry is available through `GetAuditEntry` once `COMMITTED`. `data` in the response is deprecated and empty |
| `GetAuditEntry` | Returns `seq`, `key_id`, `canon_version`, `state`, and the typed columns |
| `ListAuditEntries` | Adds filters `intent_id`, `event_id`, `correlation_id`, `on_behalf_of`, `seq_from`, `seq_to`; ordering by `seq` when a seq filter is present, otherwise `(created_at, id)` as today; streams pages of ≤ 500 until the count is met instead of a single send |
| `SearchAuditEntries` | Requires `start_date` and `end_date` spanning ≤ 31 days; queries only indexed columns with prefix match (`ILIKE 'q%'`); `details` is not searched (W11) |
| `VerifyIntegrity` | Request `{start_seq, end_seq}` (date range kept as a convenience that resolves to seqs); response adds `start_checkpoint_seq`, `end_seq`, `end_hash`, `key_ids_used[]`, `partial` |
| `ExportAuditEntries` | New, server-streaming: `{start_seq, end_seq}` → first message carries bounding checkpoints and the public keys used, then entries in `seq` order in pages of 500; permission `audit_export` |
| `ListCheckpoints`, `GetSigningKeys` | New, read-only; `audit_view` |
| `RegisterAuditManifest`, `GetAuditManifest` | New; `audit_manifest_manage` for setup Jobs |
| `RequeueIntake`, `RetireSigningKey` | New; `audit_operate`; both are themselves recorded as audit entries under `service = "service_audit"` |
| Permissions | `audit_view`, `audit_create`, `audit_verify`, `audit_export`, `audit_manifest_manage`, `audit_create_any`, `audit_operate`. Role bindings: `ROLE_SERVICE` gets `audit_create`, `audit_manifest_manage`, `audit_view`, `audit_verify`; `ROLE_OWNER` adds `audit_export`, `audit_operate`; `ROLE_ADMIN` gets `audit_view`, `audit_verify`, `audit_export`; others `audit_view`. `audit_create_any` is bound to no standard role and is granted only through the audit SA policy |

Error mapping: the handler maps validator errors to Connect codes directly (`connect.NewError`) with `ErrorDetails` naming the failing field; the current `grpc/status` conversion is removed.

---

## 9. `common/audit` changes

### 9.1 Actor rule (replaces `shouldSkipInternal`)

```go
// auditable reports whether the RPC's caller is a person acting in the system.
func auditable(claims *security.AuthenticationClaims) (profileID, onBehalfOf string, ok bool) {
    if claims == nil || claims.GetProfileID() == "" { return "", "", false }
    saID, _ := claims.Ext["service_account_id"].(string)
    if saID == "" { return claims.GetProfileID(), "", true }          // user token
    if obo := OnBehalfOfFromContext(ctx); obo != "" { return obo, ... } // operator path
    return "", "", false                                                // machine caller: skipped by design
}
```

The `internal` role plays no part in the decision; root admins and owners are audited like everyone else (W5). `WithOnBehalfOf(ctx, profileID)` is the only way a service-account caller produces an entry, and the entry records both identities.

### 9.2 Interceptor

- Calls `CreateAuditEntry` **synchronously** on a client constructed once with `connection.NewServiceClient` and a client-level `Timeout: 2 s` (no per-call context deadlines), only for non-idempotent RPCs that pass the actor rule. Service-account and internal callers are skipped explicitly and this is documented on the interceptor.
- The call uses the producer's own service-account token (the `connection` token source), never the end user's JWT; caller identity travels in the request body.
- On error it logs at `Warn` with `audit=true`, increments `audit_entry_send_failures_total{service, code}`, and continues (soft-fail). It never spawns goroutines and never blocks longer than the client timeout.
- Body capture is removed; `VerboseConfig` and the `Config` body methods are deleted. Producers that want request evidence send `payload_hash`.
- `With*` helpers gain `WithIntent(intentID, payloadHash, authorizationHash, policyHash)`, `WithEvent(eventID)`, `WithInstance(instanceID)`, `WithOnBehalfOf(profileID)`, `WithResourceVersion(v)`, `WithCorrelation(id)`, `WithEntryID(id)` (for outbox replays), `WithOccurredAt(t)`.
- `trace_id` is filled from the active OTel span context when the handler did not set it.
- `HTTPMiddleware` gets the same actor rule and synchronous send.

### 9.3 `common/auditverify`

`VerifyBundle(r io.Reader, keys KeySet, opts) (Report, error)` reads an export stream (the same protobuf messages, length-delimited) and returns `{first_seq, last_seq, entries_verified, checkpoints_verified, key_ids, first_invalid_seq, reason}`. `Canonical(entry) []byte` exposes `canon_v2`. A CLI `cmd/auditverify` wraps it for auditors.

---

## 10. Runtime shape (`apps/audit/cmd/main.go`)

**Setup Job** (`frame.ShouldRunSetup`): migrate (GORM auto-migrate + SQL files, tenancy RLS install by Frame) → seed `audit_signing_keys` from `AUDIT_SIGNING_KEY_REF`/`AUDIT_SIGNING_KEY_ID` if absent → backfill (§18, idempotent, chunked) → register permissions (`frame.WithPermissionRegistration(sd)`). Exit.

**Runtime**:

```go
ctx, svc := frame.NewServiceWithContext(ctx,
    frame.WithConfig(&cfg),
    frame.WithDatastore(),
    frame.WithSystemPrincipalAllowGlobal(namespaceAudit),
)
keys   := business.NewKeyProvider(cfg)            // fails fast if the active key is unresolvable
srv    := handlers.NewAuditServer(ctx, svc, keys)  // repo → validator → business
writer := business.NewChainWriter(svc, keys, cfg)  // includes checkpointer
svc.AddHealthCheck(writer.ReadinessChecker())      // backlog / head-age gate
svc.Init(ctx,
    frame.WithHTTPHandler(mux),                    // Connect handler + /.well-known/audit-keys.json
    frame.WithBackgroundConsumer(writer.Run),
)
```

Readiness fails when: the DB primary is unreachable; the active key is retired; any tenant's intake backlog exceeds `AUDIT_INTAKE_MAX_BACKLOG`; or the oldest `ACCEPTED` row is older than `AUDIT_HEAD_MAX_AGE` (default 60 s) while intake is non-empty. Liveness fails only when the writer loop has not completed a tick in `3 × AUDIT_WRITER_TICK + 30 s` (wedged). The deployment switches probes to `httpGet` on Frame's readiness and liveness paths (W14).

---

## 11. Data ownership and retention

| Data | Owner | Mutability | Retention |
|------|-------|------------|-----------|
| `audit_entries`, `audit_checkpoints` | Chain writer | Append-only (role-level revoke) | Indefinite (regulatory) |
| `audit_chain_heads` | Chain writer | CAS-updated | Lifetime of tenant |
| `audit_intake` | Ingest handler (insert), writer (state) | State machine `ACCEPTED→COMMITTED\|FAILED` | `COMMITTED` rows deleted after 7 days by a daily setup-style job in the writer loop (bounded `DELETE … LIMIT 10 000` per tick); `FAILED` rows kept until requeued |
| `audit_rejections` | Ingest handler | Append-only | 90 days |
| `audit_signing_keys` | Setup Job (insert), `RetireSigningKey` (retire) | Insert + `retired_at` only | Indefinite |
| `audit_manifests` | `RegisterAuditManifest` | Append-only versions | Indefinite |
| Private key material | Vault | n/a | Never leaves Vault except as a mounted file |

No caches hold chain state. The key provider's in-memory active key is the only process-local state and is refreshed on an interval.

---

## 12. Failure and recovery behaviour

| Failure | Observed behaviour | Recovery |
|---------|--------------------|----------|
| Audit service unreachable from a producer | Interceptor soft-fails after 2 s; structured log still written; `audit_entry_send_failures_total` rises | Producer outbox retries (if the producer uses one); otherwise the structured log is the only record and the alert fires |
| Validator rejects an entry | Producer sees `InvalidArgument`/`PermissionDenied`; row in `audit_rejections`; metric | Fix the producer or its manifest; nothing to replay |
| Postgres primary down | `CreateAuditEntry` returns `Unavailable`; readiness fails; writer tick errors are logged and retried with backoff | Automatic when the primary returns; no data loss for accepted entries |
| Writer crashes mid-batch | Transaction rolls back: head unchanged, intake rows return to `ACCEPTED`, no partial chain | Next tick on any replica re-runs the batch |
| Two replicas process the same tenant | Second blocks on `pg_advisory_xact_lock` until the first commits; then reads the new head | n/a (by construction) |
| Head CAS affects 0 rows | Rollback + retry; `audit_writer_cas_conflicts_total` | Indicates a lock bypass bug; alert at any non-zero value |
| Single poison intake row | Marked `FAILED`; rest of batch commits | `RequeueIntake` after fix |
| Backlog exceeds `AUDIT_INTAKE_MAX_BACKLOG` | Ingest returns `ResourceExhausted` for that tenant; readiness fails on that replica's next check | Scale replicas (HPA); investigate writer latency |
| Active key file missing at start | Process exits non-zero; deployment rollout halts | Fix secret projection; the previous ReplicaSet keeps serving |
| Active key retired while running | Writer stops committing, readiness fails, alert | Roll with the new `AUDIT_SIGNING_KEY_ID` |
| Manifest deleted / downgraded | Impossible: manifests are append-only versions | n/a |
| Tampering detected by `VerifyIntegrity` | `valid=false`, `first_invalid_seq`; `audit_verification_failures_total` | Incident: freeze the tenant (`AUDIT_FROZEN_TENANTS`), export the range, compare against the last anchored checkpoint |
| Clock skew > 5 min on a producer | Entries rejected with `InvalidArgument(occurred_at)` | Fix NTP; enable `allow_backdating` only for outbox-replay producers |
| Export client disconnects | Server stream cancelled by context; no server state | Client resumes from the last `seq` it received |

---

## 13. Concurrency and scalability

- **Ingest** scales horizontally: handlers are stateless; intake inserts contend only on the unique index.
- **Chain writes** serialise per tenant. One batch of 500 entries costs 500 SHA-256 + 500 Ed25519 signatures (~0.1 ms each on one core) plus one multi-row insert; a single tenant chain sustains on the order of 2 000–4 000 entries/s on modest hardware, far above expected human-action rates. Tenants are independent, so aggregate throughput scales with replicas up to the number of active tenants.
- **Reads** go to the replica (`REPLICA_DATABASE_URL`); the writer and head reads use the primary only.
- **Bounded memory**: batch size, page size, export page size and the discovery `LIMIT 32` cap per-tick memory; no unbounded slices.
- **Connection budget**: Frame defaults `DATABASE_MAX_OPEN_CONNECTIONS=5`; the writer holds at most one primary connection per in-flight tenant batch and processes tenants sequentially per replica, so ingest is never starved. The deployment raises the limit to 10 for this service.

---

## 14. Security model

| Concern | Mechanism |
|---------|-----------|
| Authentication | Hydra JWT, `jwtVerifyAudience: service_audit`; Frame auth interceptor normalises `sub === profile_id` |
| Authorisation | Keto: `TenancyAccessInterceptor` (data access) then `FunctionAccessInterceptor` (per-RPC permission from proto annotations) |
| Producer impersonation | `service` bound to the caller's `service_name` claim; `actor_service_account_id` from `ext.service_account_id`; `audit_create_any` is the only override |
| Tenant isolation | Claims decide tenant/partition; Postgres RLS `FORCE` + `app_tenancy_isolation` on every tenanted table; the writer binds a scoped `SystemPrincipal` per batch and uses `AllowGlobal` only for the read-only discovery query |
| Integrity | Hash chain + Ed25519 per entry and per checkpoint; storage-level `UNIQUE (tenant_id, seq)`; runtime role cannot `UPDATE`/`DELETE` chain tables |
| Key custody | Private key in Vault, projected as a file with `0400` to the non-root uid 65534; never logged; `PrivateKeyHex()` is deleted from the signer |
| PII minimisation | No body capture; forbidden-key and pattern checks; `ip_address` kept (regulatory) but `user_agent` truncated to 1 KiB; `details` size cap |
| Public surface | `/.well-known/audit-keys.json` exposes public keys only; `Export` requires `audit_export` |
| Operator actions | `RequeueIntake`, `RetireSigningKey`, `RegisterAuditManifest` are audited into the chain under `service_audit` |
| Supply of unauthenticated endpoints | Only the well-known keys path; it is mounted outside the Connect handler and rate-limited by the gateway |

---

## 15. Observability (OpenTelemetry)

All instruments are created through Frame `telemetry.NewBusinessMetrics("service_audit")`; traces use Frame's Connect and GORM instrumentation; logs are `util.Log(ctx)` with `audit=true`.

| Instrument | Type | Attributes | Alert |
|------------|------|------------|-------|
| `audit_intake_accepted_total` | counter | `service` | — |
| `audit_intake_rejected_total` | counter | `service`, `reason` | > 1 % of accepted over 10 min per service |
| `audit_intake_backlog` | gauge | `tenant_id` | > 10 000 for 5 min |
| `audit_intake_oldest_age_seconds` | gauge | `tenant_id` | > 60 s for 5 min (page) |
| `audit_intake_failed` | gauge | `tenant_id` | > 0 |
| `audit_commit_latency_seconds` | histogram | — | p99 > 5 s |
| `audit_writer_batch_size` | histogram | — | — |
| `audit_writer_tick_duration_seconds` | histogram | `outcome` | — |
| `audit_writer_cas_conflicts_total` | counter | — | > 0 |
| `audit_checkpoint_age_seconds` | gauge | `tenant_id` | > 2 × interval |
| `audit_signing_key_active_info` | gauge (1) | `key_id`, `retired` | `retired=true` |
| `audit_verification_runs_total` / `audit_verification_failures_total` | counter | `outcome` | any failure (page) |
| `audit_export_entries_total` | counter | — | — |
| `audit_entry_send_failures_total` (producer side) | counter | `service`, `code` | > 0 sustained |

Spans: `audit.ingest.validate`, `audit.ingest.persist`, `audit.writer.tick`, `audit.writer.batch{tenant,size}`, `audit.checkpoint`, `audit.verify`, `audit.export`. Producer spans carry the `intake_id` as an attribute so an entry can be traced from RPC to chain. Logs never include `details` or key material.

---

## 16. Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AUDIT_SIGNING_KEY_REF` | *(required)* | `vault://…#private_key` (mounted file) or `file:///…` |
| `AUDIT_SIGNING_KEY_ID` | *(required)* | Active key id; must exist in `audit_signing_keys` and not be retired |
| `AUDIT_KEY_RELOAD_INTERVAL` | `5m` | Re-read the key file and the key row |
| `AUDIT_WRITER_TICK` | `100ms` | Drain interval when work exists; backs off to 1 s when idle |
| `AUDIT_WRITER_BATCH` | `500` | Max entries per tenant transaction |
| `AUDIT_INTAKE_MAX_BACKLOG` | `50000` | Per-tenant backlog that triggers `ResourceExhausted` and readiness failure |
| `AUDIT_HEAD_MAX_AGE` | `60s` | Oldest accepted-but-uncommitted age that fails readiness |
| `AUDIT_CHECKPOINT_INTERVAL` | `1h` | Time-based checkpoint |
| `AUDIT_CHECKPOINT_EVERY_N` | `10000` | Count-based checkpoint |
| `AUDIT_FROZEN_TENANTS` | `` | Comma-separated tenant ids the writer must not advance (incident response) |
| `AUDIT_REQUIRE_MANIFEST` | `false` | Reject unmanifested producers instead of flagging |
| `AUDIT_INTAKE_COMMITTED_RETENTION` | `168h` | Delete committed intake rows older than this |
| `AUDIT_REJECTIONS_RETENTION` | `2160h` | 90 days |
| `AUDIT_VERIFY_MAX_ENTRIES` | `1000000` | Per-call verification cap |
| `FRAME_TENANCY_SECURITY_MODE` | `fail-closed` (deployment) | Frame RLS mode; the service is allow-listed for `AllowGlobal` |
| `DATABASE_MAX_OPEN_CONNECTIONS` | `10` (deployment) | Raised from Frame's 5 |

`AUDIT_SIGNING_KEY` is removed. Startup fails with a clear message if it is still set, so a stale manifest cannot silently run the old path.

---

## 17. Deployment changes (`deployments/manifests/namespaces/auth/audit/`)

1. `audit-signing-key` ExternalSecret adds `k1`… keys as separate properties; the HelmRelease mounts the secret as a volume at `/var/run/secrets/audit` (`readOnly: true`, `defaultMode: 0400`) and drops the `AUDIT_SIGNING_KEY` env entry.
2. Probes switch from `tcpSocket` to `httpGet` on Frame's readiness/liveness paths; `startupProbe` keeps 30 × 10 s so backfill-heavy restarts are tolerated.
3. `migration.env` gains `AUDIT_SIGNING_KEY_REF`, `AUDIT_SIGNING_KEY_ID` and the secret volume so the Job can seed the public key.
4. Env adds `FRAME_TENANCY_SECURITY_MODE=fail-closed`, `DATABASE_MAX_OPEN_CONNECTIONS=10`, the `AUDIT_*` table above.
5. `podDisruptionBudget.minAvailable: 1` and `minReplicas: 2` so a node drain never leaves zero writers.
6. Alerts from §15 are added to the platform Prometheus rules; the runbook link (§20) is the annotation.

---

## 18. Migration and rollout

Aligned with GFOS §21 K7: **Phase 0** = intake, seq, actor rule, manifests; **Phase 1** = checkpoints, keys, export.

1. **Schema (setup Job, idempotent):** add columns and tables; `canon_version` defaults to 1 for existing rows; add `UNIQUE (tenant_id, seq)` as `NOT VALID` first, validated after backfill.
2. **Backfill (setup Job, chunked):** per tenant under `pg_advisory_xact_lock`, assign `seq` in `(created_at, id)` order in chunks of 10 000 using a window function on a staging CTE; write `audit_chain_heads` from the last entry; insert the current key as `key_id = "k1"` with the public key derived from the existing private key; set `entry_id = id`, `occurred_at = received_at = created_at`. Re-runnable: rows with `seq IS NOT NULL` are skipped. Existing entries keep their legacy hash; verification uses `canon_version` to pick the encoding, so history stays verifiable.
3. **Deploy the service** with the writer and intake-mode handlers. The old direct-chain path is removed in the same release because both cannot hold the head. Old `common/audit` clients keep working: `CreateAuditEntry` still accepts the v1 fields, generates `entry_id`, and returns `ACCEPTED`. Because old clients send `profile_id` from claims and the service now applies the actor rule server-side, service-account callers on old clients receive `InvalidArgument` and soft-fail; this is the intended tightening and is logged, not paged, for the first week.
4. **Roll out the new `common/audit`** to producers (`service-profile`, `service-fintech/apps/identity`, then GFOS services); each registers a manifest in its setup Job. Enable `AUDIT_REQUIRE_MANIFEST=true` when `audit_intake_accepted_total{unmanifested="true"}` is zero for 7 days.
5. **Phase 1:** enable checkpointing (`AUDIT_CHECKPOINT_*`), publish keys, ship `ExportAuditEntries` and `common/auditverify`, rotate `k1 → k2` once as a drill and record it in the runbook.
6. **Cleanup:** drop `idx_audit_entries_chain`; delete `EmitAuditEntry`, `VerboseConfig`, `PrivateKeyHex`.

Rollback: steps 1–2 are additive; rolling the image back to the previous release re-enables the direct-chain path against the same tables (it ignores `seq`), so any entries committed by v2 remain valid but the head diverges. Rollback is therefore only safe before step 3 receives traffic; after that, roll forward.

---

## 19. Testing strategy

Per `testing-go`: real Postgres via testcontainers, `BaseTestSuite`, no goroutines in setup, race detector on.

| Level | Cases |
|-------|-------|
| Unit (`business/canon_test.go`) | Golden vectors for `canon_v2` (empty fields, unicode, `|` in fields, nested `details`, key order); the same vectors run against `common/auditverify.Canonical` in its own module |
| Unit (`business/validator_test.go`) | Table-driven: every rule in §6.2 with accept/reject pairs; forbidden key case-insensitivity; MSISDN and Luhn positives/negatives; time window edges; batch limits |
| Unit (`common/audit`) | Actor rule matrix: user token, SA token, SA + `WithOnBehalfOf`, root admin with `internal` role (must be audited), nil claims |
| Integration (`business/writer_test.go`) | Single tenant 10 000 entries commit contiguous `seq`; two writer instances against one DB with 8 tenants produce no gaps, no duplicates, `cas_conflicts == 0`; kill (cancel ctx) mid-batch then resume; poison row marked `FAILED` while batch commits; frozen tenant does not advance |
| Integration (`business/verify_test.go`) | Verify from genesis, from a checkpoint, across a key rotation, across the `canon_version` boundary; mutate one row via the migration role and assert `first_invalid_seq` |
| Integration (`handlers`) | Full interceptor chain with a fake Keto: `service` mismatch → `PermissionDenied`; SA without `on_behalf_of` → `InvalidArgument`; backlog over limit → `ResourceExhausted`; duplicate `entry_id` idempotent |
| Integration (`export`) | Export 3 pages → `auditverify.VerifyBundle` succeeds; truncated stream reports partial |
| Health | Readiness flips on backlog age and on retired key; liveness flips when the tick stalls |
| Migration | Backfill on a fixture with 3 tenants × 5 000 legacy rows; re-run is a no-op; `VerifyIntegrity` passes over the boundary |
| Load (CI-optional, `-tags load`) | 4 replicas × 2 000 entries/s for 60 s; assert p99 commit latency < 2 s and backlog returns to 0 |

---

## 20. Operations runbook

### 20.1 Rotate the signing key
1. Generate an Ed25519 key in Vault under `antinvestor/auth/audit/signing` as property `k<n>`.
2. Update the ExternalSecret to project it; wait for the file to appear in a pod.
3. Run the setup Job with `AUDIT_SIGNING_KEY_ID=k<n>` (inserts the public key row).
4. Roll the deployment with `AUDIT_SIGNING_KEY_ID=k<n>`; confirm `audit_signing_key_active_info{key_id="k<n>"}`.
5. Call `RetireSigningKey(k<n-1>)`; confirm `/.well-known/audit-keys.json` shows `retired_at`.
6. Run `VerifyIntegrity` over the last hour for one tenant; expect `key_ids_used = [k<n-1>, k<n>]`.

### 20.2 Backlog growing / head age alert
1. Check `audit_writer_tick_duration_seconds` and DB primary latency; check for `cas_conflicts`.
2. If all tenants lag, scale replicas; confirm each replica's writer is ticking (`audit.writer.tick` spans).
3. If `audit_intake_failed > 0`, inspect `last_error`, fix, `RequeueIntake`.

### 20.3 Rejection spike for a service
1. `audit_intake_rejected_total{service,reason}` names the rule.
2. `vocabulary` → the producer shipped an action/resource before its manifest; re-run its setup Job.
3. `service_binding` → the producer's `service_name` claim does not match; check the tenancy SA record.
4. `forbidden_content` → the producer is leaking a secret or PII into `details`; treat as a security finding.

### 20.4 Verification failure
1. Set `AUDIT_FROZEN_TENANTS` for the affected tenant and roll.
2. `ExportAuditEntries` from the last anchored checkpoint to the reported `first_invalid_seq + 1`; run `auditverify` offline; keep the bundle.
3. Compare the stored checkpoint hash with the anchored one (settlement) to establish whether the tamper predates the anchor.
4. Do not repair rows; append a `service_audit`/`integrity_incident` entry after the freeze is lifted.

---

## 21. Extensibility and versioning

- **Wire:** `audit.v1` stays; all additions are new fields and RPCs. A breaking change (e.g. removing `data` from create responses) lands in `audit.v2` with a 2-release overlap.
- **Canonical form:** `canon_version` on every entry; a new encoding is a new version, verifiers dispatch on it, and old versions are never rewritten.
- **Keys:** `algorithm` column allows a post-quantum or HSM-backed signer later without schema change; `key_id` namespacing (`k<n>`, `hsm-<n>`) tells the verifier which loader to use.
- **Manifests:** versioned content; adding `field_policies` (per-key allow/deny) is an additive JSON change.
- **Anchoring:** checkpoints are the stable contract; anchoring backends are consumers.

---

## 22. Simplicity and trade-off review

| Considered | Decision | Why |
|------------|----------|-----|
| Broker (JetStream) between producers and the audit service | Rejected | Adds a second durable store with its own retention and a consumer whose failure is invisible to producers; the intake table gives the same decoupling with one owner and transactional idempotency |
| Synchronous chaining in the RPC (no intake) | Rejected | Couples producer latency to the per-tenant lock; a slow tenant would stall its producers |
| Separate checkpointer deployment | Rejected | Frame allows one background consumer per process and the writer already holds the lock; a second process would need its own lock protocol |
| Session-level advisory lock (Frame helper) | Rejected for the writer | Not safe through a transaction-mode pooler; kept for migrations |
| Multiple chains (streams) per tenant | Rejected | Human-action rates never approach one serialised writer's capacity; a second chain per tenant would double heads, checkpoints and verifier logic for no measured need |
| Unique index vs CAS-only | Both | The index is cheap now that Timescale is gone and catches any future lock bypass at the storage level |
| Table partitioning | Rejected | Volume does not justify it and the id is an xid, so `(created_at, id)` already gives cheap time-ordered access; revisit only on measured evidence |
| xid as the chain position instead of `seq` | Rejected | xids order by second then machine id, so two replicas committing the same tenant within one second interleave out of chain order; `seq` is one bigint on the head row and gives dense, gap-free positions |
| Per-request context deadlines in the interceptor | Rejected | `golang-patterns`: client-level timeout only |

Remaining subsystems and their justification: validator (G6), intake + writer (G1, G2, G7), checkpointer (G3), key provider (G5), export + verifier (G4), health checker (G8). Nothing else.

---

## 23. Robustness gate — what fails first in production

| Rank | Risk | Mitigation in this design |
|------|------|---------------------------|
| 1 | **Writer starvation or wedge** (long DB pause, lock held by a stuck replica) causes backlog growth and, without limits, intake bloat and disk pressure | Transaction-scoped lock released on connection loss; per-tenant backlog cap returns `ResourceExhausted`; readiness and liveness gates; backlog/age metrics with pages; committed-row retention keeps intake small |
| 2 | **Producer misconfiguration** (wrong `service_name` claim, missing manifest, clock skew) rejects legitimate entries and the human action goes unrecorded except in logs | Rejections are errors the producer sees, counted per reason, and rows in `audit_rejections`; `unmanifested` flag instead of rejection until adoption completes; ±5 min window with an explicit backdating opt-in; runbook §20.3 |
| 3 | **Key mishandling** (ephemeral key on a misconfigured pod, signing with a retired key, key exposed via env) makes entries unverifiable or the key untrustworthy | Startup refuses without a resolvable key that matches the stored public key; retired-key check at every reload; key as a `0400` mounted file; `key_id` per entry so a compromised key's window is bounded to its `valid_from…retired_at` |

---

## 24. Properties after v2

| Property | Guarantee |
|----------|-----------|
| Durability | An accepted entry is in Postgres before the RPC returns |
| No forks | One head row per tenant, updated by CAS under a transaction-scoped advisory lock, and `UNIQUE (tenant_id, seq)` at the storage level |
| No silent drops | Validation failures are errors to the producer and rows in `audit_rejections`; machine callers are excluded by rule, not lost by accident; root administrators are audited |
| No impersonation | `service` is bound to the caller's `service_name`; the SA id is recorded from claims |
| No poison | Vocabulary, size, forbidden-content and time checks at the boundary; a poison row never blocks the head |
| Bounded verification | `VerifyIntegrity` cost ∝ range, from the nearest checkpoint, keyset paged |
| Rotation | `key_id` per entry and checkpoint; retired keys keep verifying and can never sign |
| Offline proof | `ExportAuditEntries` + published keys + `common/auditverify` |
| Anchoring | Checkpoints are the anchorable unit; anchoring is done by consumers such as `stawi/apps/settlement`, not by this service |
| Bounded resources | Batch, page, discovery and backlog limits; intake and rejection retention |
| Operable | Readiness reflects chain health; every alert has a runbook section |

---

## 25. Open decisions

| # | Question | Default if unanswered |
|---|----------|-----------------------|
| D1 | Should `ip_address` be stored raw or truncated (/24, /48) for privacy? | Raw; regulatory traceability outweighs, revisit with legal |
| D2 | Should `audit_export` be granted to `ROLE_ADMIN` by default or only owners? | Admin and owner (table in §8) |
| D3 | `AUDIT_REQUIRE_MANIFEST` flip date | 7 days after the last producer registers |
| D4 | Do GFOS producers use their outbox to call `CreateAuditEntry` (durable) or rely on the interceptor (soft-fail)? | Interceptor for all; outbox only for intent-bearing RPCs in `finance` |
