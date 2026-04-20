# Hypertables and column cleanup — Design

**Date:** 2026-04-20
**Owner:** Peter Bwire
**Status:** Design — approved, proceeding to plan
**Precondition:** Production cluster will be wiped; this ships with the migration standardization v2 baseline.

## Scope

1. Remove redundant time columns from models that are server-generated and strictly append-only; they duplicate `BaseModel.created_at`.
2. Rename two client-captured time columns to the standard `true_created_at` so offline-batched events remain correctly time-keyed.
3. Convert seven append-only high-volume tables to TimescaleDB hypertables.
4. Enable the TimescaleDB extension on the CloudNativePG cluster declaratively (no custom Postgres image).
5. Manage all hypertable conversion, compression, and retention from a shared Go package (no per-service SQL in migration files).

## Column changes

### Drop — use `BaseModel.created_at` directly

| Service | Table | Column to drop |
|---|---|---|
| service-fintech/loans | `repayments` | `received_at` |
| service-fintech/loans | `disbursements` | `disbursed_at` |
| service-fintech/loans | `penalties` | `applied_at` |
| service-fintech/loans | `reconciliations` | `reconciled_at` |
| service-fintech/loans | `loan_status_changes` | `changed_at` |
| service-files (storage) | `storage_stats` | `record_date` |

Every query, repository method, and index touching these columns must be rewritten to use `created_at`. All callers live inside the owning service.

### Rename — `true_created_at`

| Service | Table | From | To |
|---|---|---|---|
| service-profile/geolocation | `location_points` | `ts` | `true_created_at` |
| service-profile/geolocation | `geo_events` | `ts` | `true_created_at` |
| service-payment/billing | `usage_events` | `timestamp` | `true_created_at` |

These three tables receive client-captured timestamps that can diverge meaningfully from server ingest time (offline-first mobile uploads, SDK-batched metering). Keeping a distinct column is correctness-critical. Renaming standardizes the column name across domains.

## Hypertable scope — seven tables

| # | Service | Table | Time column | Chunk | Segment-by | Compress after | Retention |
|---|---|---|---|---|---|---|---|
| 1 | service-authentication | `login_events` | `created_at` | 7d | `partition_id, client_id` | 14d | 365d |
| 2 | service-authentication/audit | `audit_entries` | `created_at` | 7d | `partition_id, actor_id` | 14d | 2555d (7y) |
| 3 | service-chat | `room_events` | `created_at` | 1d | `partition_id, room_id` | 7d | — |
| 4 | service-trustage | `event_log` | `created_at` | 1d | `partition_id, event_type` | 3d | 30d |
| 5 | service-profile/geolocation | `location_points` | `true_created_at` | 1d | `partition_id, subject_id` | 7d | 90d |
| 6 | service-profile/geolocation | `geo_events` | `true_created_at` | 1d | `partition_id, subject_id` | 14d | 365d |
| 7 | service-payment/billing | `usage_events` | `true_created_at` | 7d | `partition_id, subscription_id` | 14d | 730d |

Every other candidate from the earlier analysis stays plain Postgres. Plain tables are fine for tables bounded by `users × events-per-user-per-day` at our current scale; hypertables add operational surface that isn't earned.

## Go package — `common/timescale`

A new package at `github.com/antinvestor/common/timescale` that every service imports. It owns the full hypertable lifecycle — extension check, hypertable creation, compression policy, retention policy — declaratively.

### API

```go
package timescale

type Hypertable struct {
    Table          string
    TimeColumn     string
    ChunkInterval  time.Duration
    SegmentBy      []string
    CompressAfter  time.Duration
    RetainFor      time.Duration // 0 = no retention policy
}

// Ensure is idempotent. Runs the full conversion + policy set.
// Safe to call on every service start; each operation is IF NOT EXISTS
// or a policy lookup-and-skip. No-ops with a warning if the
// timescaledb extension is not loaded in the target database.
func Ensure(ctx context.Context, db *gorm.DB, tables []Hypertable) error
```

### Wiring

Each owning service's `cmd/main.go` calls `timescale.Ensure(...)` after `frame` migrations but before `svc.Init`. The configs live next to the service's models:

```go
// apps/default/service/models/hypertables.go in service-authentication
package models

import (
    "time"
    "github.com/antinvestor/common/timescale"
)

var Hypertables = []timescale.Hypertable{
    {
        Table:         "login_events",
        TimeColumn:    "created_at",
        ChunkInterval: 7 * 24 * time.Hour,
        SegmentBy:     []string{"partition_id", "client_id"},
        CompressAfter: 14 * 24 * time.Hour,
        RetainFor:     365 * 24 * time.Hour,
    },
}
```

### Composite primary key

TimescaleDB requires the primary key to include the time column. `BaseModel` defines `id` as the primary key — that alone is insufficient for hypertables. Two options:

- **A. Add `true_created_at`/`created_at` to the PK** via a composite key on affected models only.
- **B. Drop the PK, add `UNIQUE (id, <time_col>)`** and rely on frame's xid-generated ids being globally unique.

We take **A** for the 7 hypertable-bound models. `common/timescale` does not touch non-hypertable models.

The 7 models get an override method in their Go struct:

```go
// service-authentication/apps/default/service/models/login_event.go
func (LoginEvent) TableName() string { return "login_events" }

// Override BaseModel's PK behaviour. The migration creates the table with
// a composite PK (id, created_at); GORM's default insertion path works
// because both columns are non-null.
```

The migration SQL uses `PRIMARY KEY (id, <time_col>)` instead of the default BaseModel single-column PK.

### Failure modes

- Extension missing: `Ensure` logs a WARN and skips ALL conversions. The service runs; tables stay plain; writes succeed. This makes local dev / CI without Timescale painless — just `make test` on a stock Postgres container and everything passes.
- Conversion error: `Ensure` returns the error; `main.go` treats it as fatal. The service refuses to start on a misconfigured DB rather than silently running without compression/retention.
- Policy already present: `add_compression_policy` and `add_retention_policy` both have `if_not_exists` options; `Ensure` uses them.

## CNPG cluster — declarative extension

Uses CloudNativePG's `postgresql.extensions` feature (available in CNPG 1.26+). Mounts the extension image as a volume at runtime; the base Postgres image stays official.

### `manifests/namespaces/datastore/cluster.yaml`

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: datastore
  namespace: datastore
spec:
  imageName: ghcr.io/cloudnative-pg/postgresql:16-bookworm
  instances: 3
  postgresql:
    shared_preload_libraries:
      - timescaledb
    parameters:
      timescaledb.max_background_workers: "16"
    extensions:
      - name: timescaledb
        image:
          reference: ghcr.io/cloudnative-pg/postgres-containerextensions/timescaledb:2.17-pg16
  bootstrap:
    initdb:
      postInitApplicationSQL:
        - CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
  managed:
    databases:
      - name: authentication
        extensions: [{name: timescaledb, ensure: present}]
      - name: audit
        extensions: [{name: timescaledb, ensure: present}]
      - name: chat
        extensions: [{name: timescaledb, ensure: present}]
      - name: trustage
        extensions: [{name: timescaledb, ensure: present}]
      - name: profile
        extensions: [{name: timescaledb, ensure: present}]
      - name: billing
        extensions: [{name: timescaledb, ensure: present}]
      # tenancy, files, notification, payment, fintech, commerce — no hypertables, extension not required
```

The per-database `managed.databases` entries trigger CNPG to run `CREATE EXTENSION timescaledb` on each database at creation. Databases without hypertables (tenancy, files, etc.) are not listed — they stay minimal.

## Rollout ordering

1. `common/timescale` package created and tagged (no consumers yet).
2. Custom Postgres image NOT built; CNPG extensions feature handles it.
3. Cluster spec change merged in deployments repo.
4. Seven owning services ship their hypertable registrations + composite-PK migration updates + `timescale.Ensure` call.
5. Cluster wiped per the previously-planned v2 migration rollout.
6. New cluster boots with TimescaleDB loaded; service migrations run; `timescale.Ensure` converts tables on first boot.

## Out of scope

- Continuous aggregates (materialized views over hypertables). Worth adding for `usage_events` and `login_events` once baseline is stable. Tracked separately.
- Hypertable conversion for tables beyond the seven listed. Re-evaluate after 6 months of production data.
- Changes to the Postgres backup strategy. `pg_dump` handles hypertables; Velero snapshots of the PVC work unchanged.

## Approval

Design approved by Peter Bwire (2026-04-20). Proceeds to implementation plan.
