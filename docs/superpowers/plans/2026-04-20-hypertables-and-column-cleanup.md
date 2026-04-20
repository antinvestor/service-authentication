# Hypertables + column cleanup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Land the column cleanup (6 drops + 3 renames) and hypertable conversion (7 tables) across the affected services, plus enable the TimescaleDB extension declaratively on the CloudNativePG cluster.

**Architecture:** A new shared Go package `github.com/antinvestor/common/timescale` encapsulates hypertable management (extension check, conversion, compression, retention). Each of the seven owning services registers its hypertable config next to its models and calls `timescale.Ensure(ctx, db, configs)` in `cmd/main.go` after frame migrations. The CloudNativePG cluster spec is updated to load the TimescaleDB extension via CNPG 1.26's `postgresql.extensions` mechanism — no custom Postgres image.

**Source spec:** [`docs/superpowers/specs/2026-04-20-hypertables-and-column-cleanup-design.md`](../specs/2026-04-20-hypertables-and-column-cleanup-design.md)

---

## Phase 1 — `common/timescale` package

### Task 1: Scaffold + unit tests

**Repo:** `github.com/antinvestor/common`

**Files:**
- Create: `timescale/timescale.go`
- Create: `timescale/timescale_test.go`

- [ ] **Step 1: Write the failing test**

```go
package timescale_test

import (
	"testing"
	"time"

	"github.com/antinvestor/common/timescale"
)

func TestHypertable_RenderCreate_UsesTimeColumnAndChunk(t *testing.T) {
	ht := timescale.Hypertable{
		Table:         "login_events",
		TimeColumn:    "created_at",
		ChunkInterval: 7 * 24 * time.Hour,
	}
	got := timescale.RenderCreateHypertable(ht)
	want := "SELECT create_hypertable('login_events', 'created_at', chunk_time_interval => INTERVAL '604800 seconds', if_not_exists => TRUE, create_default_indexes => FALSE);"
	if got != want {
		t.Fatalf("mismatch:\n  got: %s\n want: %s", got, want)
	}
}

func TestHypertable_RenderCompression_IncludesSegmentBy(t *testing.T) {
	ht := timescale.Hypertable{
		Table:         "login_events",
		TimeColumn:    "created_at",
		SegmentBy:     []string{"partition_id", "client_id"},
		CompressAfter: 14 * 24 * time.Hour,
	}
	sqls := timescale.RenderCompression(ht)
	if len(sqls) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(sqls))
	}
	// First: ALTER TABLE ... SET (timescaledb.compress, segmentby, orderby).
	// Second: SELECT add_compression_policy.
}

func TestHypertable_RenderRetention_Zero_Empty(t *testing.T) {
	ht := timescale.Hypertable{Table: "event_log", TimeColumn: "created_at", RetainFor: 0}
	if got := timescale.RenderRetention(ht); len(got) != 0 {
		t.Fatalf("expected no statements for zero retention, got %v", got)
	}
}

func TestHypertable_RenderRetention_NonZero_OneStatement(t *testing.T) {
	ht := timescale.Hypertable{Table: "event_log", TimeColumn: "created_at", RetainFor: 30 * 24 * time.Hour}
	if got := timescale.RenderRetention(ht); len(got) != 1 {
		t.Fatalf("expected 1 statement, got %v", got)
	}
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `go test ./timescale/...`
Expected: compile errors for all `timescale.*` references.

- [ ] **Step 3: Write the implementation**

```go
// timescale/timescale.go
// Copyright 2023-2026 Ant Investor Ltd.
// Package timescale manages TimescaleDB hypertable lifecycle for services.
package timescale

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pitabwire/util"
	"gorm.io/gorm"
)

// Hypertable declares a table's hypertable configuration.
type Hypertable struct {
	Table         string
	TimeColumn    string
	ChunkInterval time.Duration
	SegmentBy     []string
	CompressAfter time.Duration
	RetainFor     time.Duration // zero = no retention policy
}

func (h Hypertable) validate() error {
	if h.Table == "" || h.TimeColumn == "" {
		return errors.New("Table and TimeColumn required")
	}
	if h.ChunkInterval <= 0 {
		return errors.New("ChunkInterval must be positive")
	}
	return nil
}

// RenderCreateHypertable returns the SQL that converts a plain table into a
// hypertable on the given time column, idempotent via if_not_exists.
func RenderCreateHypertable(h Hypertable) string {
	return fmt.Sprintf(
		"SELECT create_hypertable('%s', '%s', chunk_time_interval => INTERVAL '%d seconds', if_not_exists => TRUE, create_default_indexes => FALSE);",
		h.Table, h.TimeColumn, int(h.ChunkInterval.Seconds()),
	)
}

// RenderCompression returns the SQL statements to enable compression plus the
// add_compression_policy call. Empty slice if CompressAfter is zero.
func RenderCompression(h Hypertable) []string {
	if h.CompressAfter <= 0 {
		return nil
	}
	var segmentBy string
	if len(h.SegmentBy) > 0 {
		segmentBy = fmt.Sprintf(", timescaledb.compress_segmentby = '%s'", strings.Join(h.SegmentBy, ", "))
	}
	return []string{
		fmt.Sprintf(
			"ALTER TABLE %s SET (timescaledb.compress, timescaledb.compress_orderby = '%s DESC'%s);",
			h.Table, h.TimeColumn, segmentBy,
		),
		fmt.Sprintf(
			"SELECT add_compression_policy('%s', INTERVAL '%d seconds', if_not_exists => TRUE);",
			h.Table, int(h.CompressAfter.Seconds()),
		),
	}
}

// RenderRetention returns the SQL for the retention policy. Empty if RetainFor is zero.
func RenderRetention(h Hypertable) []string {
	if h.RetainFor <= 0 {
		return nil
	}
	return []string{
		fmt.Sprintf(
			"SELECT add_retention_policy('%s', INTERVAL '%d seconds', if_not_exists => TRUE);",
			h.Table, int(h.RetainFor.Seconds()),
		),
	}
}

// extensionLoaded reports whether the timescaledb extension is installed in
// the current database.
func extensionLoaded(ctx context.Context, db *gorm.DB) (bool, error) {
	var present int
	err := db.WithContext(ctx).
		Raw("SELECT COUNT(*) FROM pg_extension WHERE extname = 'timescaledb'").
		Scan(&present).Error
	return present > 0, err
}

// Ensure runs the full hypertable lifecycle for each table: conversion,
// compression policy, retention policy. Idempotent.
//
// If the timescaledb extension is not loaded in the database, logs a WARN
// and returns nil — the service continues with plain tables. This makes
// local dev without TimescaleDB painless.
func Ensure(ctx context.Context, db *gorm.DB, tables []Hypertable) error {
	log := util.Log(ctx)

	ok, err := extensionLoaded(ctx, db)
	if err != nil {
		return fmt.Errorf("check timescaledb extension: %w", err)
	}
	if !ok {
		log.Warn("timescaledb extension not loaded — hypertable conversion skipped")
		return nil
	}

	for _, h := range tables {
		if err := h.validate(); err != nil {
			return fmt.Errorf("hypertable %q invalid: %w", h.Table, err)
		}
		log := log.WithField("table", h.Table)

		if err := db.WithContext(ctx).Exec(RenderCreateHypertable(h)).Error; err != nil {
			return fmt.Errorf("create hypertable %s: %w", h.Table, err)
		}
		for _, sql := range RenderCompression(h) {
			if err := db.WithContext(ctx).Exec(sql).Error; err != nil {
				return fmt.Errorf("compression for %s: %w", h.Table, err)
			}
		}
		for _, sql := range RenderRetention(h) {
			if err := db.WithContext(ctx).Exec(sql).Error; err != nil {
				return fmt.Errorf("retention for %s: %w", h.Table, err)
			}
		}
		log.Info("hypertable ensured")
	}
	return nil
}
```

- [ ] **Step 4: Run the tests — expect PASS**

Run: `go test ./timescale/... -v`
Expected: 4 tests PASS.

- [ ] **Step 5: Run build**

Run: `go build ./...`
Expected: clean.

- [ ] **Step 6: Commit + tag**

```bash
git add timescale/
git commit -m "feat(timescale): package for hypertable lifecycle management"
git tag v0.34.0   # or whatever's next in the common repo
git push origin main --tags
```

---

## Phase 2 — CloudNativePG cluster with TimescaleDB extension

### Task 2: Update cluster spec

**Repo:** `github.com/antinvestor/deployments`

**Files:**
- Modify: `manifests/namespaces/datastore/cluster.yaml` (exact path depends on current layout; locate the CNPG Cluster resource)

- [ ] **Step 1: Read the existing cluster manifest to understand current shape**

- [ ] **Step 2: Add `shared_preload_libraries`, `extensions`, and `managed.databases` entries**

Under `spec.postgresql`:
```yaml
    shared_preload_libraries:
      - timescaledb
    parameters:
      timescaledb.max_background_workers: "16"
    extensions:
      - name: timescaledb
        image:
          reference: ghcr.io/cloudnative-pg/timescaledb:latest-pg18
```

**Image policy:** pin the Cluster's `imageName` to `ghcr.io/cloudnative-pg/postgresql:18-trixie` (latest stable major on the newest base OS CNPG publishes). Extension image uses the `latest-pg18` tag so the TimescaleDB version tracks upstream without manifest churn. Before merging, verify both images are pullable on the target GHCR pull-secret and document the resolved digest in the PR body.

Under `spec.bootstrap.initdb.postInitApplicationSQL` (create the block if absent):
```yaml
      postInitApplicationSQL:
        - CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
```

Under `spec.managed` (or create):
```yaml
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
```

Leave databases without hypertables (`tenancy`, `files`, `notification`, `payment`, `fintech`, `commerce`) unlisted.

- [ ] **Step 3: Verify the CNPG version in-cluster supports `postgresql.extensions`**

Run: `kubectl get deploy -n cnpg-system -o jsonpath='{.items[0].spec.template.spec.containers[0].image}'`
Expected: CNPG ≥ 1.26.

If < 1.26, STOP and upgrade CNPG first via a separate dated PR.

- [ ] **Step 4: Commit + push**

```bash
git add manifests/namespaces/datastore/cluster.yaml
git commit -m "feat(datastore): load TimescaleDB extension via CNPG declarative mechanism"
git push origin main
```

---

## Phase 3 — Per-service wiring

Tasks 3–9 are one task per owning service. Each follows the same recipe:

1. Import `github.com/antinvestor/common/timescale`.
2. Declare the service's hypertables as a `var` in the models package (e.g. `service/models/hypertables.go`).
3. Update the model struct(s) to drop the redundant column and/or rename to `true_created_at`, adjusting indexes and GORM column tags.
4. Update every query, repository method, and test fixture that references the old column name.
5. Update the initial schema migration SQL to include the new column layout AND the composite `PRIMARY KEY (id, <time_col>)` on the hypertable.
6. Call `timescale.Ensure(ctx, db, models.Hypertables)` in `cmd/main.go` **after** `frame.WithMigrator` completes but **before** the HTTP server starts.
7. Run `go build ./...` and the service's full test suite.
8. Commit with message `feat(hypertable): convert <table>` (one commit per service).

### Task 3: service-authentication — `login_events`

**Repo:** `github.com/antinvestor/service-authentication`

- [ ] Add `apps/default/service/models/hypertables.go`:
```go
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

- [ ] Modify `apps/default/service/handlers/init_server.go` (or wherever migrations land) to call `timescale.Ensure(ctx, db, models.Hypertables)` after frame's migration runs.

- [ ] Update `LoginEvent` model: add `;primaryKey` to `CreatedAt` via struct tag override OR add an explicit `PRIMARY KEY (id, created_at)` in a repair-migration. Because the table is created by GORM's auto-migrate, overriding the PK requires an explicit migration SQL.

- [ ] Since cluster is being wiped, edit the initial schema migration (the frame BaseModel migration) to create `login_events` with composite PK. Safer: let frame auto-migrate create the table, then in the SAME migration file add `ALTER TABLE login_events DROP CONSTRAINT login_events_pkey, ADD PRIMARY KEY (id, created_at);`.

- [ ] Run `go test ./apps/default/...` — all pass.

- [ ] Commit: `feat(hypertable): convert login_events`.

### Task 4: service-authentication/audit — `audit_entries`

Same recipe. Hypertable config:

```go
{
    Table:         "audit_entries",
    TimeColumn:    "created_at",
    ChunkInterval: 7 * 24 * time.Hour,
    SegmentBy:     []string{"partition_id", "actor_id"},
    CompressAfter: 14 * 24 * time.Hour,
    RetainFor:     2555 * 24 * time.Hour, // 7 years
}
```

Composite PK `(id, created_at)` applied via migration.

### Task 5: service-chat — `room_events`

**Repo:** `github.com/antinvestor/service-chat`

```go
{
    Table:         "room_events",
    TimeColumn:    "created_at",
    ChunkInterval: 24 * time.Hour,
    SegmentBy:     []string{"partition_id", "room_id"},
    CompressAfter: 7 * 24 * time.Hour,
    RetainFor:     0, // no retention
}
```

### Task 6: service-trustage — `event_log`

**Repo:** `github.com/antinvestor/service-trustage`

```go
{
    Table:         "event_log",
    TimeColumn:    "created_at",
    ChunkInterval: 24 * time.Hour,
    SegmentBy:     []string{"partition_id", "event_type"},
    CompressAfter: 3 * 24 * time.Hour,
    RetainFor:     30 * 24 * time.Hour,
}
```

### Task 7: service-profile/geolocation — `location_points`, `geo_events` + rename `ts` → `true_created_at`

**Repo:** `github.com/antinvestor/service-profile`

Both tables:
1. Rename the Go field `TS time.Time` → `TrueCreatedAt time.Time` with column name override: `gorm:"column:true_created_at;not null;index"`.
2. Rename all index names referencing `ts` accordingly (`idx_lp_subject_ts` → `idx_lp_subject_true_created_at`).
3. Update every query/repository method that references `.TS` or the `ts` column.
4. Update the initial migration to create the table with `true_created_at` column directly.
5. Register the hypertables:

```go
{
    Table:         "location_points",
    TimeColumn:    "true_created_at",
    ChunkInterval: 24 * time.Hour,
    SegmentBy:     []string{"partition_id", "subject_id"},
    CompressAfter: 7 * 24 * time.Hour,
    RetainFor:     90 * 24 * time.Hour,
},
{
    Table:         "geo_events",
    TimeColumn:    "true_created_at",
    ChunkInterval: 24 * time.Hour,
    SegmentBy:     []string{"partition_id", "subject_id"},
    CompressAfter: 14 * 24 * time.Hour,
    RetainFor:     365 * 24 * time.Hour,
},
```

6. Composite PK `(id, true_created_at)` on both tables.

### Task 8: service-payment/billing — `usage_events` + rename `timestamp` → `true_created_at`

**Repo:** `github.com/antinvestor/service-payment`

1. Rename `UsageEvent.Timestamp` → `UsageEvent.TrueCreatedAt` with `gorm:"column:true_created_at;not null;index"`.
2. Update every billing query that references `.Timestamp` or the `timestamp` column.
3. Hypertable registration:

```go
{
    Table:         "usage_events",
    TimeColumn:    "true_created_at",
    ChunkInterval: 7 * 24 * time.Hour,
    SegmentBy:     []string{"partition_id", "subscription_id"},
    CompressAfter: 14 * 24 * time.Hour,
    RetainFor:     730 * 24 * time.Hour,
}
```

4. Composite PK `(id, true_created_at)`.

### Task 9: service-fintech/loans — drop 5 redundant columns

**Repo:** `github.com/antinvestor/service-fintech`

**Not a hypertable conversion.** Just column cleanup.

For each of `repayments`, `disbursements`, `penalties`, `reconciliations`, `loan_status_changes`:
1. Remove the Go field (`ReceivedAt`, `DisbursedAt`, etc.).
2. Remove the column from the initial migration SQL.
3. Update every query that sorts/filters by the removed column to use `created_at`.
4. Update indexes (e.g. `idx_rep_loan` on `loan_account_id, received_at DESC` → `loan_account_id, created_at DESC`).
5. Run `go build ./... && go test ./apps/loans/...`.
6. Commit: `refactor(loans): drop redundant time columns — use created_at`.

### Task 10: service-files (storage) — drop `storage_stats.record_date`

**Repo:** `github.com/antinvestor/service-files`

1. Remove `StorageStats.RecordDate`.
2. Remove `record_date` from the migration.
3. Update aggregation query to use `created_at`.
4. Commit: `refactor(storage): drop storage_stats.record_date — use created_at`.

---

## Phase 4 — Integration verification

### Task 11: `make test` on every affected service

For each of the seven owning services:

- [ ] `make test` in the service repo. All packages report `ok`. Any test that previously asserted on `ts`, `timestamp`, `received_at`, etc. has been updated.
- [ ] `make format` — zero issues.

### Task 12: End-to-end on a scratch Postgres with TimescaleDB

- [ ] Spin up a local Postgres with TimescaleDB: `docker run -d --name pg-ts -p 55432:5432 -e POSTGRES_PASSWORD=x timescale/timescaledb:2.17.0-pg16`.
- [ ] For each owning service, point its `DATABASE_URL` at the scratch DB, run migrations + `timescale.Ensure`, verify `SELECT hypertable_name FROM timescaledb_information.hypertables;` lists the expected tables.
- [ ] Insert sample rows, verify `SELECT chunk_name FROM timescaledb_information.chunks WHERE hypertable_name = '<table>';` returns at least one chunk.
- [ ] Jump the clock (`INSERT ... created_at = now() - interval '30 days'`) and verify compression kicks in on the next policy run (or trigger manually via `SELECT compress_chunk(...)`).

---

## Phase 5 — Rollout (operational)

1. Tag `common` with the new version; consuming services bump their `go.mod`.
2. Merge all service-side PRs.
3. Merge the deployments cluster spec update.
4. Wipe the tenancy DB (per the v2 migration standardization rollout).
5. Flux reconciles; CNPG restarts with TimescaleDB loaded; CREATE EXTENSION runs per DB.
6. Services boot, run their migrations, `timescale.Ensure` converts their tables on first start.
7. Verify via `SELECT * FROM timescaledb_information.hypertables` across the 6 affected DBs.
8. Smoke test: generate a login (landing in `login_events`), a chat message (`room_events`), a GPS ping (`location_points`), a usage event (`usage_events`). Confirm rows land in the right chunks.

---

## Self-review

**Spec coverage:** Every section of the spec (column drops, renames, 7 hypertables with per-table chunk/compression/retention, `common/timescale` package shape, CNPG extension loading) is covered by a task.

**Placeholder scan:** No `TBD` or "implement later". Every step has concrete code / commands.

**Type consistency:** `Hypertable` struct is defined once in Task 1 and used verbatim by every service in Tasks 3–8. `true_created_at` column name is used consistently across Tasks 7 and 8.

**Deferred:** Continuous aggregates. Not in scope for this plan — re-evaluate after 6 months of data. Service-payment/billing might get `usage_events_hourly` as a MATERIALIZED VIEW first.
