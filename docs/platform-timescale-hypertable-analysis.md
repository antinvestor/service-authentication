# TimescaleDB hypertable candidacy — platform-wide analysis

**Date:** 2026-04-20
**Scope:** every backend service under `~/code/antinvestor/service-*`.

## What a hypertable earns you

TimescaleDB's hypertable is transparent Postgres-level time partitioning. For the right table it buys:

- **Insert throughput**: chunks are small, WAL + index writes stay local to the latest chunk, vacuum hot-path narrow.
- **Range-scan efficiency**: time-window queries prune to one or two chunks; no full-table scan even at billions of rows.
- **Compression**: old chunks compress ~10-20× with columnar encoding, still queryable.
- **Retention**: `drop_chunks` older than N days is O(chunks), not O(rows).
- **Continuous aggregates**: materialized views that auto-refresh only the newest chunk; ~free pre-rolled metrics.

Hypertables are the wrong tool when:
- Row count stays low (<1M) — plain Postgres is simpler.
- Rows are mutated after insert by their primary key.
- Access patterns are not time-bounded.

## Decision rubric applied

For every model across the 10 services, we filtered by:
1. Extends `data.BaseModel` so there's a `created_at` or a domain-specific time column.
2. Insert rate is unbounded with usage (per-event, per-ping, per-message, per-txn).
3. Rows are append-only or nearly so (status transitions recorded as new rows, not in-place updates).
4. Dominant query pattern is time-ranged or per-entity time-ranged.
5. Retention or rollup matters operationally.

## Tier 1 — convert now, clear ROI

| Table | Service | Time column | Why | Partition key |
|---|---|---|---|---|
| `location_points` (`LocationPoint`) | service-profile/geolocation | `ts` | GPS pings; thousands/device/day; strictly append-only; already indexed `(subject_id, ts DESC)`. Historical queries ("where was X between T1 and T2") are the entire query surface. | `(partition_id, subject_id)` + `ts` chunk |
| `geo_events` (`GeoEvent`) | service-profile/geolocation | `ts` | Geofence enter/exit/dwell; high per-subject volume; explicitly append-only per the model comment; multi-index by subject+ts and area+ts. | `(partition_id, area_id)` + `ts` |
| `room_events` (`RoomEvent`) | service-chat | `created_at` | Every message + system event in every room. Unbounded. Id is time-sorted already. Range reads by room are the main access pattern. | `(partition_id, room_id)` + `created_at` |
| `event_log` (`EventLog`) | service-trustage | `created_at` | Outbox table. Every domain event in the system lands here; `published` flips once. Pure append after that. Retention is a real need — old rows are pure bloat. | `(partition_id)` + `created_at`, compress after 7 days |
| `audit_entries` (`AuditEntry`) | service-authentication/apps/audit | `created_at` | Immutable by policy — model comment literally says "No UPDATE or DELETE operations are permitted". Regulator-grade retention. | `(partition_id, actor_id)` + `created_at`, compress old chunks, retain 7y |
| `login_events` (`LoginEvent`) | service-authentication/apps/default | `created_at` | One row per login flow (incl. failures). The obvious first candidate; we've known this. | `(partition_id, client_id)` + `created_at` |

## Tier 2 — strong candidates, convert after Tier 1 lands

| Table | Service | Time column | Notes |
|---|---|---|---|
| `usage_events` (`UsageEvent`) | service-payment/billing | `timestamp` | Metered usage events per subscription. Indexed on `timestamp`. Natural hypertable; will also benefit from a continuous aggregate for per-period billing roll-ups. |
| `notifications` + `notification_statuses` | service-notification | `created_at` | SMS/email/push with state-transition rows. Convert both — join locality across chunks stays intact. |
| `device_logs` (`DeviceLog`) | service-profile/devices | `created_at` | Device activity / crash reports. Append-only, indexed on `device_id`. |
| `device_replay_events` (`DeviceReplayEvent`) | service-chat | `created_at` | Per-device durable replay cursor; append-only; volume scales with connected devices. |
| `workflow_audit_events` (`WorkflowAuditEvent`) | service-trustage | `created_at` | Strict append-only per comment; keyed by workflow instance + execution. |

## Tier 3 — convert when volume warrants or when pairing with Tier 1

| Table | Service | Reasoning |
|---|---|---|
| `incoming_payments` (`IncomingPayment`) | service-fintech/operations | High volume, but state transitions mutate the row. Hypertables tolerate this if the PK includes the time column; otherwise it's cheaper to keep it plain until volume forces the move. |
| `transactions` + `transaction_entries` (ledger) | service-payment/ledger | Doubled-entry ledger, mutable until clearing. Convert the fact table to a hypertable AFTER the business layer stabilises around immutable entries. |
| `repayments`, `disbursements`, `penalties`, `reconciliations`, `loan_status_changes` | service-fintech/loans | Each has its own domain time column (`received_at`, `disbursed_at`, `applied_at`, `reconciled_at`, `changed_at`). Append-only. Individually medium volume; good once they all live in the same DB and time-ranged reporting across them matters. |
| `media_audit` | service-files | Per file access/action; scales with traffic. |
| `file_versions` | service-files | Per-version immutable snapshot. Low-medium volume; benefit is smaller than OCR/media logs. |
| `ocr_logs` | service-files/ocr | State transitions on the row (pending → processing → done). Convert only if OCR volume grows materially. |
| `occurrences`, `request_logs`, `infractions`, `member_scores` | service-fintech/stawi | Group-activity audit tables. Medium volume per group; hypertable wins emerge only at scale. |
| `client_assignment_history`, `client_responsibility_history`, `client_data_entry_history` | service-fintech/identity | Immutable audit trails. Low-medium volume today. |

## Not hypertable candidates

Reference / config data, low cardinality, frequently updated by PK:

- `tenants`, `partitions`, `partition_roles`, `clients`, `service_accounts`, `accesses`, `access_roles`, `page` rows in tenancy.
- `profiles`, `contacts`, `addresses`, `relationships`, `rosters` in profile.
- `settings` rows (but `setting_audit` is a Tier 3 candidate).
- `devices` (the identity row; `device_logs` is the event stream).
- `loans`, `loan_accounts`, `loan_products`, `funding_accounts`, `savings_accounts` — mutable state, PK-addressed.
- `orders`, `order_lines`, `carts` in commerce — order state is mutable.
- `rooms`, `room_members`, `room_aliases` in chat (but `room_events` is the event stream).
- `notification_templates`, `notification_languages`, `notification_routes` (but `notifications` is the event stream).
- `files`/`media` header rows (but `media_audit` and `file_versions` are streams).

## Implementation pattern

For each candidate, the migration to apply (once the TimescaleDB extension is enabled on the target DB):

```sql
-- 1. Create the table as usual (this is what the migration already does today).
CREATE TABLE IF NOT EXISTS location_points (
    id                  text PRIMARY KEY,
    tenant_id           text NOT NULL,
    partition_id        text NOT NULL,
    subject_id          text NOT NULL,
    device_id           text,
    ts                  timestamptz NOT NULL,
    latitude            double precision NOT NULL,
    longitude           double precision NOT NULL,
    -- …
    created_at          timestamptz NOT NULL DEFAULT now(),
    modified_at         timestamptz NOT NULL DEFAULT now(),
    version             int NOT NULL DEFAULT 1,
    deleted_at          timestamptz
);

-- 2. Convert to hypertable. `create_default_indexes=>false` because our
--    BaseModel primary key is the id (text/xid), not time; we rely on the
--    existing (subject_id, ts DESC) index for range queries.
SELECT create_hypertable(
    'location_points',
    'ts',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists       => TRUE,
    create_default_indexes => FALSE
);

-- 3. Compression policy: compress chunks older than 14 days. Segment by the
--    partition dimension so cross-partition queries stay cheap.
ALTER TABLE location_points SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'partition_id, subject_id',
    timescaledb.compress_orderby   = 'ts DESC'
);
SELECT add_compression_policy('location_points', INTERVAL '14 days');

-- 4. Retention policy (optional — use per-domain requirement).
--    SELECT add_retention_policy('location_points', INTERVAL '365 days');
```

Each of these lives in a dated migration per service, e.g. `20260421_location_points_hypertable.sql`.

### Non-negotiables when converting

- **Primary key must include the time column** or TimescaleDB rejects the conversion. Our `BaseModel.id` PK is single-column; we need a composite PK `(id, ts)` OR drop the PK entirely and rely on a unique index including both. Safer is to add `UNIQUE (id, ts)` before the conversion and accept that `id` alone is only locally unique per chunk.
- **Foreign keys** FROM a hypertable TO a non-hypertable are fine. FROM non-hypertable TO hypertable are NOT supported (TimescaleDB limitation). Audit each candidate's FK graph before cutover.
- **`ON CONFLICT (id) DO NOTHING`** upserts must change to `ON CONFLICT (id, ts) DO NOTHING` because the unique constraint is now composite.
- **Continuous aggregates** are where the real leverage lives — e.g. for `usage_events`, precompute hourly sums per `(subscription_id, metric_key)` and let the billing service read the aggregate view instead of the raw table.

## Prerequisites

- **TimescaleDB extension**: `CREATE EXTENSION IF NOT EXISTS timescaledb;` on each DB that hosts a candidate table. Requires the TSDB package in the Postgres image; the standard Bitnami Postgres image doesn't include it, so either switch to `timescale/timescaledb-ha` or `pgvecto/pgvectors-timescale` or install the extension yourself.
- **Per-service DB boundaries**: service-payment/billing and service-fintech/loans share a DB via the pooler? Confirm before running the `CREATE EXTENSION` migration; extensions are per-database.
- **Backup strategy**: hypertable chunks are regular tables under the hood; existing `pg_dump` works but is slower at scale. Velero snapshots of the PVC work fine.

## Suggested roll-out order

1. **`location_points`** — standalone, strictly append-only, no FKs from other tables; lowest-risk conversion and highest write-throughput win.
2. **`room_events`** — chat is a self-contained service; test continuous aggregates for "messages per room per day" dashboards.
3. **`event_log`** (trustage outbox) — adding compression + retention here prevents the outbox from eating disk.
4. **`audit_entries`** — regulator-grade retention model; wire up a retention policy that matches the legal requirement.
5. **`login_events`** — more conservative because the tenancy enrichment path queries this table during live login flows; verify chunk pruning works on the production query patterns.
6. **`notifications`** — paired with `notification_statuses`; needs both converted together for join locality.
7. Everything in Tier 2 and 3 as operational bandwidth allows.

## What this analysis does NOT cover

- **Postgres version + TimescaleDB version matrix** — verify before enabling the extension on the target DB.
- **Cost of the migration itself** — converting a non-empty table to a hypertable is an online operation but does a table rewrite under the hood. Schedule for a maintenance window on production.
- **Business-level retention requirements** — legal/regulatory constraints per domain (especially `audit_entries`, `repayments`, `disbursements`) dictate policy. This doc suggests defaults only.
