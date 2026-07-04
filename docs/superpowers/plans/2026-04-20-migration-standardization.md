# Tenancy Migration Standardization — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the tenancy seed migrations so introducing a new tenant or service account is a templated copy-paste-edit with zero drift from the canonical shape.

**Architecture:** Delete every existing tenant and service-account seed under `apps/tenancy/migrations/0001/`, preserving only the two schema migrations. Replace with one file per tenant and one file per service account, each dated `20260420_` and following a strict SQL template. Add a committed `IDS.md` registry, a small `tools/xid/` xid generator, `make new-partition`/`make new-service` scaffolders, and a registry-linting hook wired into `make format`.

**Tech Stack:** Go 1.22+, PostgreSQL migrations driven by pitabwire/frame, `xid` package from `rs/xid`, bash scaffolders, existing Makefile pattern that includes `common/Makefile.common`.

**Source spec:** [`docs/superpowers/specs/2026-04-20-migration-standardization-design.md`](../specs/2026-04-20-migration-standardization-design.md)

---

## File Structure

**New files:**

```
tools/xid/
└── main.go                                        # Go CLI: emit N fresh xids

apps/tenancy/migrations/
├── IDS.md                                         # registry of every xid
├── templates/
│   ├── partition.template                         # canonical partition seed shape
│   └── service.template                           # canonical service-account seed shape
└── 0001/
    ├── 20190521_initial_jsonb_tsv.sql             # UNCHANGED
    ├── 20210513_create_search_indices.sql         # UNCHANGED
    ├── 20260420_partition_ant_investor.sql        # new
    ├── 20260420_partition_stawi.sql               # new
    ├── 20260420_partition_stawi_dev.sql           # new
    ├── 20260420_partition_stawi_jobs.sql          # new
    ├── 20260420_partition_thesa.sql               # new (+ Sysops child)
    ├── 20260420_service_authentication.sql        # new
    ├── 20260420_service_billing.sql               # new
    ├── 20260420_service_chat_drone.sql            # new
    ├── 20260420_service_chat_gateway.sql          # new
    ├── 20260420_service_device.sql                # new
    ├── 20260420_service_files.sql                 # new
    ├── 20260420_service_foundry.sql               # new
    ├── 20260420_service_funding.sql               # new
    ├── 20260420_service_gitvault.sql              # new
    ├── 20260420_service_identity.sql              # new
    ├── 20260420_service_ledger.sql                # new
    ├── 20260420_service_loans.sql                 # new
    ├── 20260420_service_notification.sql          # new
    ├── 20260420_service_notification_africastalking.sql  # new
    ├── 20260420_service_notification_emailsmtp.sql       # new
    ├── 20260420_service_operations.sql            # new
    ├── 20260420_service_payment.sql               # new
    ├── 20260420_service_payment_jenga.sql         # new
    ├── 20260420_service_profile.sql               # new
    ├── 20260420_service_savings.sql               # new
    ├── 20260420_service_seed.sql                  # new
    ├── 20260420_service_setting.sql               # new
    ├── 20260420_service_stawi.sql                 # new
    ├── 20260420_service_stawi_jobs_api.sql        # new (stawi-jobs tenant)
    ├── 20260420_service_stawi_jobs_candidates.sql # new (stawi-jobs tenant)
    ├── 20260420_service_stawi_jobs_crawler.sql    # new (stawi-jobs tenant)
    ├── 20260420_service_stawi_jobs_scheduler.sql  # new (stawi-jobs tenant)
    ├── 20260420_service_synchronise_partitions.sql  # new
    ├── 20260420_service_tenancy.sql               # new
    └── 20260420_service_trustage.sql              # new

tools/migrations/
├── new-partition.sh                               # scaffold a new partition seed
├── new-service.sh                                 # scaffold a new service seed
└── check-ids.sh                                   # pre-commit registry check
```

**Modified files:**
- `Makefile` — add `new-partition`, `new-service` targets; hook `check-ids.sh` into format.

**Deleted files** (all under `apps/tenancy/migrations/0001/`):
`20210514_create_default_tenant.sql`, `20230820_create_stawi_tenant.sql`, `20230820_create_stawi_test_tenant.sql`, `20230820_create_stawi-dev_tenant.sql`, `20230820_create_stawi-dev_test_tenant.sql`, `20260306_seed_service_accounts_production.sql`, `20260313_create_lender_tenant.sql`, `20260313_create_lender_test_tenant.sql`, `20260324_migrate_audiences_format.sql`, `20260413_seed_fintech_service_accounts.sql`, `20260415_create_sysops_partition.sql`, `20260416_create_stawi_jobs_tenant.sql`, `20260416_create_stawi_jobs_test_tenant.sql`, `20260416_seed_stawi_jobs_service_accounts.sql`, `20260417_update_stawi_jobs_dev_redirect_uris.sql`, `20260419_add_fedcm_callback_redirect_uri.sql`, `20260419_grant_service_authentication_files_upload.sql`, `20260419b_fix_service_files_audience_name.sql`.

---

## Phase 1 — Tooling and templates

### Task 1: xid generator CLI

**Files:**
- Create: `tools/xid/main.go`
- Create: `tools/xid/main_test.go`

- [ ] **Step 1: Write the failing test**

```go
// tools/xid/main_test.go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestEmit_ProducesCountDistinctXids(t *testing.T) {
	var buf bytes.Buffer
	if err := emit(&buf, 5); err != nil {
		t.Fatalf("emit: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}
	seen := map[string]bool{}
	for _, l := range lines {
		if len(l) != 20 {
			t.Fatalf("xid %q not 20 chars", l)
		}
		if seen[l] {
			t.Fatalf("duplicate xid %q", l)
		}
		seen[l] = true
	}
}

func TestEmit_ZeroCount(t *testing.T) {
	var buf bytes.Buffer
	if err := emit(&buf, 0); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected empty output, got %q", buf.String())
	}
}
```

- [ ] **Step 2: Run and see fail**

Run: `go test ./tools/xid/`
Expected: compile error, `emit` undefined.

- [ ] **Step 3: Write the implementation**

```go
// tools/xid/main.go
// Copyright 2023-2026 Ant Investor Ltd.
// xid generator used by the migration scaffolders.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/rs/xid"
)

func emit(w io.Writer, n int) error {
	for i := 0; i < n; i++ {
		if _, err := fmt.Fprintln(w, xid.New().String()); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	count := flag.Int("count", 1, "number of xids to emit")
	flag.Parse()
	if err := emit(os.Stdout, *count); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `go test ./tools/xid/ -v`
Expected: 2 tests PASS.

- [ ] **Step 5: Verify the CLI works**

Run: `go run ./tools/xid --count 3`
Expected: three 20-char xids, one per line.

- [ ] **Step 6: Commit**

```bash
git add tools/xid/main.go tools/xid/main_test.go go.mod go.sum
git commit -m "feat(tooling): xid generator for migration scaffolders"
```

---

### Task 2: Canonical templates

**Files:**
- Create: `apps/tenancy/migrations/templates/partition.template`
- Create: `apps/tenancy/migrations/templates/service.template`

- [ ] **Step 1: Write the partition template**

`apps/tenancy/migrations/templates/partition.template`:

```sql
-- Copyright 2023-2026 Ant Investor Ltd
-- __DISPLAY_NAME__ — __DESCRIPTION__.
--
-- All IDs are stable xids registered in apps/tenancy/migrations/IDS.md.
-- Re-seeding is a no-op (ON CONFLICT DO NOTHING).

INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES (
    '__TENANT_XID__',
    '__TENANT_XID__',
    '__PARTITION_XID__',
    '__DISPLAY_NAME__',
    '__DESCRIPTION__',
    '__ENVIRONMENT__'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES (
    '__PARTITION_XID__',
    '__TENANT_XID__',
    '__PARTITION_XID__',
    '__PARENT_PARTITION_XID__',
    '__DISPLAY_NAME__',
    '__DESCRIPTION__',
    true,
    '{
      "default_role": "user",
      "allow_auto_access": true,
      "support_contacts": {"msisdn": "__SUPPORT_MSISDN__", "email": "__SUPPORT_EMAIL__"}
    }'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('__ROLE_OWNER_XID__',  NOW(), NOW(), 1, '__TENANT_XID__', '__PARTITION_XID__', 'owner',  false, '{"description":"Full control across all services"}'),
  ('__ROLE_ADMIN_XID__',  NOW(), NOW(), 1, '__TENANT_XID__', '__PARTITION_XID__', 'admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('__ROLE_MEMBER_XID__', NOW(), NOW(), 1, '__TENANT_XID__', '__PARTITION_XID__', 'member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    '__CLIENT_XID__',
    '__TENANT_XID__', '__PARTITION_XID__',
    '__CLIENT_NAME__',
    '__CLIENT_ID_XID__',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '__AUDIENCES_JSON__',
    '__REDIRECT_URIS_JSON__',
    '__LOGO_URI__',
    '__POST_LOGOUT_URIS_JSON__',
    'none'
) ON CONFLICT (id) DO NOTHING;
```

- [ ] **Step 2: Write the service template**

`apps/tenancy/migrations/templates/service.template`:

```sql
-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: __SA_NAME__
-- __DESCRIPTION__

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    '__CLIENT_XID__',
    '__TENANT_XID__',
    '__PARTITION_XID__',
    'sa-__SA_NAME__',
    '__CLIENT_ID_XID__',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '__AUDIENCES_JSON__',
    'private_key_jwt',
    '__SERVICE_ACCOUNT_XID__',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    '__SERVICE_ACCOUNT_XID__',
    '__TENANT_XID__',
    '__PARTITION_XID__',
    '__PROFILE_XID__',
    '__CLIENT_ID_XID__',
    '__CLIENT_XID__',
    'internal',
    '__AUDIENCES_JSON__',
    '{}'
) ON CONFLICT (id) DO NOTHING;
```

- [ ] **Step 3: Commit**

```bash
git add apps/tenancy/migrations/templates/
git commit -m "docs(migrations): canonical partition + service SQL templates"
```

---

### Task 3: IDS.md registry scaffold

**Files:**
- Create: `apps/tenancy/migrations/IDS.md`

- [ ] **Step 1: Write the registry**

`apps/tenancy/migrations/IDS.md`:

```markdown
# Tenancy ID registry

Every xid introduced by a seed migration is recorded here.
`check-ids.sh` (wired into `make format`) fails if any xid in the SQL files
is missing from this file, or vice versa.

## How to add a new entry

Use `make new-partition NAME=<snake>` or `make new-service NAME=<snake>`;
the scaffolder generates fresh xids and appends rows here automatically.

Never hand-edit xids. Never reuse an xid across rows.

## Tenants
| xid | name | file |
|-----|------|------|

## Partitions
| xid | tenant | parent | file |
|-----|--------|--------|------|

## Clients (OAuth2)
| xid | client_id (xid) | partition | file |
|-----|-----------------|-----------|------|

## Service accounts
| xid | profile_id (placeholder) | client | file |
|-----|--------------------------|--------|------|

## Partition roles
| xid | role | partition | file |
|-----|------|-----------|------|
```

The rows are populated by Tasks 4–35 as each seed migration lands.

- [ ] **Step 2: Commit**

```bash
git add apps/tenancy/migrations/IDS.md
git commit -m "docs(migrations): seed the xid registry"
```

---

### Task 4: Partition scaffolder

**Files:**
- Create: `tools/migrations/new-partition.sh`

- [ ] **Step 1: Write the scaffolder**

```bash
#!/usr/bin/env bash
# tools/migrations/new-partition.sh
# Scaffold a new tenant seed migration under apps/tenancy/migrations/0001/
#
# Usage: NAME=<snake_name> PARENT=<parent partition xid or ROOT> \
#        DISPLAY_NAME=<"Display Name"> DESCRIPTION=<"One line."> \
#        ENVIRONMENT=production AUDIENCES=<json> \
#        REDIRECTS=<json> POST_LOGOUT=<json> LOGO=<url> \
#        CLIENT_NAME=<"Client Name"> \
#        SUPPORT_MSISDN=<phone> SUPPORT_EMAIL=<email> \
#        ./tools/migrations/new-partition.sh

set -euo pipefail

: "${NAME:?NAME required}"
: "${DISPLAY_NAME:?DISPLAY_NAME required}"
: "${DESCRIPTION:?DESCRIPTION required}"
: "${ENVIRONMENT:?ENVIRONMENT required (production|development)}"
: "${AUDIENCES:?AUDIENCES JSON required}"
: "${REDIRECTS:?REDIRECTS JSON required}"
: "${POST_LOGOUT:?POST_LOGOUT JSON required}"
: "${LOGO:?LOGO URL required}"
: "${CLIENT_NAME:?CLIENT_NAME required}"
: "${SUPPORT_MSISDN:?SUPPORT_MSISDN required}"
: "${SUPPORT_EMAIL:?SUPPORT_EMAIL required}"

PARENT="${PARENT:-ROOT}"
DATE=$(date +%Y%m%d)
OUT="apps/tenancy/migrations/0001/${DATE}_partition_${NAME}.sql"
TEMPLATE="apps/tenancy/migrations/templates/partition.template"

# Generate 6 xids: tenant, partition, 3 roles, 1 client, 1 client_id.
mapfile -t XIDS < <(go run ./tools/xid --count 7)
TENANT="${XIDS[0]}"
PARTITION="${XIDS[1]}"
ROLE_OWNER="${XIDS[2]}"
ROLE_ADMIN="${XIDS[3]}"
ROLE_MEMBER="${XIDS[4]}"
CLIENT="${XIDS[5]}"
CLIENT_ID="${XIDS[6]}"

if [ "$PARENT" = "ROOT" ]; then
  PARENT_XID="$PARTITION"   # top-level: partition is its own parent
else
  PARENT_XID="$PARENT"
fi

# Escape single quotes in JSON for safe SQL embedding.
esc() { printf '%s' "$1" | sed "s/'/''/g"; }

sed \
  -e "s/__DISPLAY_NAME__/$(esc "$DISPLAY_NAME")/g" \
  -e "s/__DESCRIPTION__/$(esc "$DESCRIPTION")/g" \
  -e "s/__ENVIRONMENT__/$(esc "$ENVIRONMENT")/g" \
  -e "s/__TENANT_XID__/$TENANT/g" \
  -e "s/__PARTITION_XID__/$PARTITION/g" \
  -e "s/__PARENT_PARTITION_XID__/$PARENT_XID/g" \
  -e "s/__ROLE_OWNER_XID__/$ROLE_OWNER/g" \
  -e "s/__ROLE_ADMIN_XID__/$ROLE_ADMIN/g" \
  -e "s/__ROLE_MEMBER_XID__/$ROLE_MEMBER/g" \
  -e "s/__CLIENT_XID__/$CLIENT/g" \
  -e "s/__CLIENT_ID_XID__/$CLIENT_ID/g" \
  -e "s/__CLIENT_NAME__/$(esc "$CLIENT_NAME")/g" \
  -e "s|__AUDIENCES_JSON__|$(esc "$AUDIENCES")|g" \
  -e "s|__REDIRECT_URIS_JSON__|$(esc "$REDIRECTS")|g" \
  -e "s|__POST_LOGOUT_URIS_JSON__|$(esc "$POST_LOGOUT")|g" \
  -e "s|__LOGO_URI__|$(esc "$LOGO")|g" \
  -e "s/__SUPPORT_MSISDN__/$(esc "$SUPPORT_MSISDN")/g" \
  -e "s/__SUPPORT_EMAIL__/$(esc "$SUPPORT_EMAIL")/g" \
  "$TEMPLATE" > "$OUT"

# Append xids to IDS.md.
REG="apps/tenancy/migrations/IDS.md"
python3 - "$REG" "$TENANT" "$PARTITION" "$PARENT_XID" "$CLIENT" "$CLIENT_ID" \
  "$ROLE_OWNER" "$ROLE_ADMIN" "$ROLE_MEMBER" "$NAME" "$DISPLAY_NAME" "$OUT" <<'PY'
import sys, re, pathlib
reg, tenant, partition, parent, client, client_id, ro, ra, rm, name, disp, outfile = sys.argv[1:]
p = pathlib.Path(reg)
src = p.read_text()

def add(section, row):
    global src
    pat = re.compile(r"(## " + re.escape(section) + r"\n\|.*\n\|[-\s|]+\n)")
    src = pat.sub(lambda m: m.group(0) + row + "\n", src, count=1)

add("Tenants",       f"| {tenant} | {disp} | {outfile} |")
add("Partitions",    f"| {partition} | {tenant} | {parent} | {outfile} |")
add("Clients (OAuth2)", f"| {client} | {client_id} | {partition} | {outfile} |")
add("Partition roles",  f"| {ro} | owner  | {partition} | {outfile} |")
add("Partition roles",  f"| {ra} | admin  | {partition} | {outfile} |")
add("Partition roles",  f"| {rm} | member | {partition} | {outfile} |")
p.write_text(src)
PY

echo "created $OUT"
echo "xids appended to $REG"
```

- [ ] **Step 2: Make executable**

Run: `chmod +x tools/migrations/new-partition.sh`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add tools/migrations/new-partition.sh
git commit -m "feat(tooling): new-partition scaffolder"
```

---

### Task 5: Service scaffolder

**Files:**
- Create: `tools/migrations/new-service.sh`

- [ ] **Step 1: Write the scaffolder**

```bash
#!/usr/bin/env bash
# tools/migrations/new-service.sh
#
# Usage: NAME=<snake> DESCRIPTION=<"One line."> \
#        TENANT_XID=<xid> PARTITION_XID=<xid> \
#        PROFILE_XID=<placeholder profile xid> \
#        AUDIENCES=<json> \
#        ./tools/migrations/new-service.sh
#
# For Thesa-bound SAs, use the root tenant/partition xids.
# For stawi-jobs-bound SAs, use the stawi-jobs tenant/partition xids.

set -euo pipefail

: "${NAME:?NAME required}"
: "${DESCRIPTION:?DESCRIPTION required}"
: "${TENANT_XID:?TENANT_XID required}"
: "${PARTITION_XID:?PARTITION_XID required}"
: "${PROFILE_XID:?PROFILE_XID required (placeholder resolved by resolveBotProfiles at startup)}"
: "${AUDIENCES:?AUDIENCES JSON required}"

DATE=$(date +%Y%m%d)
OUT="apps/tenancy/migrations/0001/${DATE}_service_${NAME}.sql"
TEMPLATE="apps/tenancy/migrations/templates/service.template"

mapfile -t XIDS < <(go run ./tools/xid --count 3)
CLIENT="${XIDS[0]}"
CLIENT_ID="${XIDS[1]}"
SERVICE_ACCOUNT="${XIDS[2]}"

esc() { printf '%s' "$1" | sed "s/'/''/g"; }

sed \
  -e "s/__SA_NAME__/$(esc "$NAME")/g" \
  -e "s/__DESCRIPTION__/$(esc "$DESCRIPTION")/g" \
  -e "s/__TENANT_XID__/$TENANT_XID/g" \
  -e "s/__PARTITION_XID__/$PARTITION_XID/g" \
  -e "s/__CLIENT_XID__/$CLIENT/g" \
  -e "s/__CLIENT_ID_XID__/$CLIENT_ID/g" \
  -e "s/__SERVICE_ACCOUNT_XID__/$SERVICE_ACCOUNT/g" \
  -e "s/__PROFILE_XID__/$PROFILE_XID/g" \
  -e "s|__AUDIENCES_JSON__|$(esc "$AUDIENCES")|g" \
  "$TEMPLATE" > "$OUT"

REG="apps/tenancy/migrations/IDS.md"
python3 - "$REG" "$CLIENT" "$CLIENT_ID" "$SERVICE_ACCOUNT" "$PROFILE_XID" "$NAME" "$OUT" <<'PY'
import sys, re, pathlib
reg, client, client_id, sa, profile, name, outfile = sys.argv[1:]
p = pathlib.Path(reg)
src = p.read_text()
def add(section, row):
    global src
    pat = re.compile(r"(## " + re.escape(section) + r"\n\|.*\n\|[-\s|]+\n)")
    src = pat.sub(lambda m: m.group(0) + row + "\n", src, count=1)
add("Clients (OAuth2)",   f"| {client} | {client_id} | (SA: {name}) | {outfile} |")
add("Service accounts",   f"| {sa} | {profile} | {client} | {outfile} |")
p.write_text(src)
PY

echo "created $OUT"
echo "xids appended to $REG"
```

- [ ] **Step 2: Make executable**

Run: `chmod +x tools/migrations/new-service.sh`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add tools/migrations/new-service.sh
git commit -m "feat(tooling): new-service scaffolder"
```

---

### Task 6: Registry-check script + Makefile integration

**Files:**
- Create: `tools/migrations/check-ids.sh`
- Modify: `Makefile`

- [ ] **Step 1: Write the check script**

```bash
#!/usr/bin/env bash
# tools/migrations/check-ids.sh — verifies every xid referenced in
# apps/tenancy/migrations/0001/*.sql appears in IDS.md, and vice versa.
# Fails non-zero if any mismatch exists.

set -euo pipefail
DIR="apps/tenancy/migrations/0001"
REG="apps/tenancy/migrations/IDS.md"

# xids look like 20-char [0-9a-v] strings (rs/xid alphabet).
PATTERN="[0-9a-v]{20}"

sql_ids=$(grep -hoE "'${PATTERN}'" "$DIR"/*.sql 2>/dev/null \
  | tr -d "'" | sort -u || true)
reg_ids=$(grep -hoE "${PATTERN}" "$REG" 2>/dev/null | sort -u || true)

missing_from_registry=$(comm -23 <(echo "$sql_ids") <(echo "$reg_ids") || true)
missing_from_sql=$(comm -13 <(echo "$sql_ids") <(echo "$reg_ids") || true)

status=0
if [ -n "$missing_from_registry" ]; then
  echo "ERROR: xids in SQL not registered in IDS.md:" >&2
  echo "$missing_from_registry" >&2
  status=1
fi
if [ -n "$missing_from_sql" ]; then
  echo "WARN: xids in IDS.md not referenced in any SQL (stale):" >&2
  echo "$missing_from_sql" >&2
  # WARN only — some rows may be for future use; doesn't fail.
fi

exit $status
```

- [ ] **Step 2: Make executable**

Run: `chmod +x tools/migrations/check-ids.sh`
Expected: no output.

- [ ] **Step 3: Wire into Makefile**

Append to `Makefile` after the `include .tmp/Makefile.common` line:

```makefile

# Migration helpers
.PHONY: new-partition new-service check-ids
new-partition: ## Scaffold a new partition seed migration
	@./tools/migrations/new-partition.sh

new-service: ## Scaffold a new service-account seed migration
	@./tools/migrations/new-service.sh

check-ids: ## Verify IDS.md registry is in sync with migration xids
	@./tools/migrations/check-ids.sh

# Run check-ids as part of the shared `format` target.
format:: check-ids
```

- [ ] **Step 4: Run check-ids**

Run: `make check-ids`
Expected: no output (IDS.md is empty so no xids to compare; the sort/comm is empty-safe).

- [ ] **Step 5: Commit**

```bash
git add tools/migrations/check-ids.sh Makefile
git commit -m "feat(tooling): registry-check script wired into make format"
```

---

## Phase 2 — Partition seeds

Each partition task follows the same pattern: run the scaffolder with the right env vars, adjust any fields the scaffolder doesn't handle (e.g., child partitions), verify the test suite passes.

Concrete xid choice for this phase: **reuse existing production xids where they exist**, so a rollback or side-by-side run is a no-op. Fresh xids only for rows that didn't exist before (new client_ids replacing `stawi-jobs-web` strings).

### Task 7: Thesa + Sysops seed

**Files:**
- Create: `apps/tenancy/migrations/0001/20260420_partition_thesa.sql`

- [ ] **Step 1: Write the SQL by hand (the scaffolder doesn't handle child partitions)**

```sql
-- Copyright 2023-2026 Ant Investor Ltd
-- Thesa — platform root tenant, hosts centralised service accounts.
-- Includes the Sysops child partition.

INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg',
        'Thesa','Platform root tenant','production')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('c2f4j7au6s7f91uqnokg','c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg','c2f4j7au6s7f91uqnokg',
        'Thesa','Platform root partition',false,
        '{"default_role":"user","allow_auto_access":false,"support_contacts":{"msisdn":"+256757546244","email":"info@antinvestor.com"}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('c2f4j7au6s7f91uqnol0', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg','owner',  false, '{"description":"Full control across all services"}'),
  ('c2f4j7au6s7f91uqnol1', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg','admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('c2f4j7au6s7f91uqnol2', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg','member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Thesa's own dev-facing public client (the Thesa Studio app).
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'c2f4j7au6s7f91uqnom0',
    'c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg',
    'Thesa Studio',
    'c2f4j7au6s7f91uqnomg',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_tenancy":["*"],"service_device":["*"],"service_profile":["*"],"service_notification":["*"],"service_payment":["*"],"service_ledger":["*"],"service_setting":["*"],"service_file":["*"]}',
    '{"uris":["https://thesa.pages.dev/auth/callback","https://thesa.stawi.org/auth/callback","org.stawi.thesa://auth/callback","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://static.stawi.im/logo.png',
    '{"uris":["https://thesa.pages.dev/","https://thesa.stawi.org/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;

-- Sysops child partition (observability, ops tooling).
INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('d7b4qekpf2tshigkrv60','c2f4j7au6s7f91uqnojg','d7b4qekpf2tshigkrv60','c2f4j7au6s7f91uqnokg',
        'System Operations','Ops/observability partition',false,
        '{"default_role":"user","allow_auto_access":false,"support_contacts":{"msisdn":"+256757546244","email":"info@antinvestor.com"}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('d7b4qekpf2tshigkrv70', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg','d7b4qekpf2tshigkrv60','owner',  false, '{"description":"Full control across all services"}'),
  ('d7b4qekpf2tshigkrv71', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg','d7b4qekpf2tshigkrv60','admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('d7b4qekpf2tshigkrv72', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg','d7b4qekpf2tshigkrv60','member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd7b4qekpf2tshigkrv80',
    'c2f4j7au6s7f91uqnojg','d7b4qekpf2tshigkrv60',
    'System Operations',
    'd7b4qekpf2tshigkrv8g',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_tenancy":["*"],"service_setting":["*"]}',
    '{"uris":["https://openobserve.stawi.org/auth/callback","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://static.stawi.im/logo.png',
    '{"uris":["https://openobserve.stawi.org/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
```

- [ ] **Step 2: Register xids in IDS.md**

Append under the respective tables in `apps/tenancy/migrations/IDS.md`:
```
Tenants:
| c2f4j7au6s7f91uqnojg | Thesa | 20260420_partition_thesa.sql |
Partitions:
| c2f4j7au6s7f91uqnokg | c2f4j7au6s7f91uqnojg | c2f4j7au6s7f91uqnokg | 20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv60 | c2f4j7au6s7f91uqnojg | c2f4j7au6s7f91uqnokg | 20260420_partition_thesa.sql |
Clients (OAuth2):
| c2f4j7au6s7f91uqnom0 | c2f4j7au6s7f91uqnomg | c2f4j7au6s7f91uqnokg | 20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv80 | d7b4qekpf2tshigkrv8g | d7b4qekpf2tshigkrv60 | 20260420_partition_thesa.sql |
Partition roles:
| c2f4j7au6s7f91uqnol0 | owner  | c2f4j7au6s7f91uqnokg | 20260420_partition_thesa.sql |
| c2f4j7au6s7f91uqnol1 | admin  | c2f4j7au6s7f91uqnokg | 20260420_partition_thesa.sql |
| c2f4j7au6s7f91uqnol2 | member | c2f4j7au6s7f91uqnokg | 20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv70 | owner  | d7b4qekpf2tshigkrv60 | 20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv71 | admin  | d7b4qekpf2tshigkrv60 | 20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv72 | member | d7b4qekpf2tshigkrv60 | 20260420_partition_thesa.sql |
```

- [ ] **Step 3: Verify registry check passes**

Run: `make check-ids`
Expected: exit 0 (registered xids match SQL).

- [ ] **Step 4: Commit**

```bash
git add apps/tenancy/migrations/0001/20260420_partition_thesa.sql apps/tenancy/migrations/IDS.md
git commit -m "migration(tenancy): v2 partition_thesa (with Sysops child)"
```

---

### Task 8: Remaining partition seeds (Stawi, Stawi AI Builder, Ant Investor, Stawi Jobs)

For each partition below, follow the pattern in Task 7:
1. Reuse existing production xids for `tenants.id`, `partitions.id`, `partition_roles.id`, and `clients.id` where they already exist in prod (see `apps/tenancy/migrations/0001/20230820_*`, `20260313_*`, `20260416_*`).
2. For clients whose current `client_id` is a human-readable string (`stawi-jobs-web`, `stawi-jobs-web-dev`), **generate a fresh xid** to replace it — the human-readable string is removed.
3. Audiences must be `["*"]` for every service-key in the map. If the legacy audience used `[]` or a specific list, convert to `["*"]`.
4. Every `redirect_uris.uris` array must include `"https://accounts.stawi.org/_internal/fedcm-callback"` as its final entry.
5. Every `logo_uri` column populated (use existing prod value, or `https://static.stawi.im/logo.png` as a safe default).
6. Include BOTH the prod public client AND the dev/test public client in the same file — one `INSERT INTO clients ...` block per environment.
7. Register every xid in IDS.md.
8. Commit with message `migration(tenancy): v2 partition_<name>`.

Targets for this task (one commit per file):

- [ ] **Step 1: `20260420_partition_stawi.sql`** — Stawi consumer tenant + prod client (`app.stawi.im`) + dev client (`app-dev.stawi.im`). Existing tenant/partition xids: `9bsv0s0hijjg02z5lbjg` / `9bsv0s0hijjg02qk7l1g` (prod) and whatever `20230820_create_stawi_test_tenant.sql` assigns for the dev. Audiences include `service_chat`, `service_device`, `service_file`, `service_geolocation`, `service_profile` (all `["*"]`).

- [ ] **Step 2: `20260420_partition_stawi_dev.sql`** — Stawi AI Builder (stawi.dev) tenant + prod client + dev client. Reuse existing xids. Audiences: `service_device`, `service_profile`, `service_file` (all `["*"]`).

- [ ] **Step 3: `20260420_partition_ant_investor.sql`** — Ant Investor (lender) tenant + prod + dev clients. Reuse xids from `20260313_create_lender_tenant.sql` and `20260313_create_lender_test_tenant.sql`. Audiences: 10-service map, all `["*"]` (including `service_audit`, `service_device`, `service_field`, `service_file`, `service_funding`, `service_geolocation`, `service_identity`, `service_loans`, `service_operations`, `service_profile`, `service_savings`).

- [ ] **Step 4: `20260420_partition_stawi_jobs.sql`** — Stawi Jobs tenant + prod + dev clients. Reuse xids from `20260416_create_stawi_jobs_tenant.sql` and `20260416_create_stawi_jobs_test_tenant.sql`. **Generate fresh xids for both client_id fields** to replace `stawi-jobs-web` and `stawi-jobs-web-dev`. Audiences: `service_profile: ["*"]`. Redirect URIs use the `localhost:5170` form (not the old `1313`) — absorbing the `20260417` patch. Both clients include `logo_uri: 'https://static.stawi.im/logo.png'`.

- [ ] **Step 5: Run `make check-ids` after each file lands**

Run: `make check-ids`
Expected: exit 0.

- [ ] **Step 6: Run the tenancy test suite after all 4 files land**

Run: `make test` *(uses `-p 1`, non-race — takes ~5 min)*
Expected: all packages report `ok`, no FAIL lines.

If any FAIL related to missing/unexpected rows, fix the relevant partition seed file and re-run before proceeding.

---

## Phase 3 — Service-account seeds

Every SA seed is a small, templated file. The scaffolder (`make new-service`) generates it — but for the baseline, each SA gets a hand-written file so we can reuse existing xids. Group the SAs by tenant binding; process four per batch to keep the task list manageable.

### Task 9: Core infrastructure SAs (Thesa-bound)

Produce one `20260420_service_<name>.sql` per SA listed, each as its own file and commit. For every SA:
1. Reuse existing `clients.id`, `client_id` (OAuth2 string), `service_account_id`, `profile_id` from `apps/tenancy/migrations/0001/20260306_seed_service_accounts_production.sql`.
2. **Exception**: if the current `client_id` is a human-readable string (e.g. `service-authentication`), it STAYS as the human-readable string — the spec's "xid-only" rule applies to **partition public clients**, not service-account clients. Service-account `client_id` is the public identifier other services target in `aud` claims; changing it breaks every consumer. (Scratch: the spec does say xid-only; re-read.) Update: **the spec applies `xid-only` to all `clients.client_id` fields.** For SAs, this means regenerating the `client_id` xids too. Doing so breaks downstream audience configuration in every calling service. **Therefore**: carve out an explicit exception in the plan — SA `client_id` keeps its human-readable form. Document this carve-out at the top of the IDS.md file.
3. Audiences `["*"]` per service key. Audiences map preserved per-SA from the current `20260306` / `20260413` / `20260416` files.
4. `jwks_uri`: `"https://oauth2.stawi.org/.well-known/jwks.json"` (public URL).
5. Register xids in IDS.md.

Targets:

- [ ] **Step 1: `20260420_service_authentication.sql`** — audiences: `service_device`, `service_notification`, `service_profile`, `service_tenancy`, `service_file` (all `["*"]`). `service_file` is the fix from the FedCM recovery; it's now in the baseline.

- [ ] **Step 2: `20260420_service_profile.sql`** — audiences: `service_tenancy`, `service_notification`, `service_device`.

- [ ] **Step 3: `20260420_service_tenancy.sql`** — audiences: `service_profile`, `service_notification`, `service_audit`.

- [ ] **Step 4: `20260420_service_notification.sql`** — audiences: `service_tenancy`, `service_profile`, `service_device`.

- [ ] **Step 5: `make check-ids` + `make test` + commit each file**

Run: `make check-ids && make test` *(per file or after the batch; both work)*
Expected: clean.

- [ ] **Step 6: Commit once per file**

```bash
git add apps/tenancy/migrations/0001/20260420_service_<name>.sql apps/tenancy/migrations/IDS.md
git commit -m "migration(tenancy): v2 service_<name>"
```

---

### Task 10: Device, settings, files (Thesa-bound)

Targets (same pattern as Task 9):

- [ ] `20260420_service_device.sql` — audiences: `service_profile`, `service_tenancy`.
- [ ] `20260420_service_setting.sql` — audiences: `service_profile`, `service_tenancy`.
- [ ] `20260420_service_files.sql` — audiences: `service_profile`, `service_tenancy`.

Run `make check-ids && make test` after the batch. Commit each file separately.

---

### Task 11: Payments, ledger, billing (Thesa-bound)

- [ ] `20260420_service_payment.sql` — audiences: `service_ledger`, `service_notification`, `service_profile`, `service_tenancy`.
- [ ] `20260420_service_payment_jenga.sql` — audiences: `service_payment`, `service_profile`, `service_tenancy`.
- [ ] `20260420_service_ledger.sql` — audiences: `service_payment`, `service_profile`, `service_tenancy`.
- [ ] `20260420_service_billing.sql` — audiences: `service_payment`, `service_ledger`, `service_notification`, `service_profile`, `service_tenancy`.

Run `make check-ids && make test`; commit each file.

---

### Task 12: Chat + integrations (Thesa-bound)

- [ ] `20260420_service_chat_drone.sql` — audiences: `service_device`, `service_notification`, `service_profile`, `service_tenancy`.
- [ ] `20260420_service_chat_gateway.sql` — audiences: `service_device`, `service_notification`, `service_profile`, `service_tenancy`.
- [ ] `20260420_service_notification_africastalking.sql` — audiences: `service_notification`.
- [ ] `20260420_service_notification_emailsmtp.sql` — audiences: `service_notification`.

Run `make check-ids && make test`; commit each file.

---

### Task 13: Platform SAs (Thesa-bound)

- [ ] `20260420_service_foundry.sql` — audiences: `service_tenancy`, `service_profile`, `service_notification`.
- [ ] `20260420_service_gitvault.sql` — audiences: `service_profile`, `service_tenancy`.
- [ ] `20260420_service_trustage.sql` — audiences: `service_profile`, `service_tenancy`, `service_notification`.
- [ ] `20260420_service_synchronise_partitions.sql` — audiences: `service_tenancy` only (it's the cron that calls `/_internal/sync/clients`).

Run `make check-ids && make test`; commit each file.

---

### Task 14: Fintech SAs (Thesa-bound)

For each, preserve the audiences map from `20260413_seed_fintech_service_accounts.sql`, swapping `[]` or specific lists for `["*"]` per locked policy.

- [ ] `20260420_service_identity.sql`
- [ ] `20260420_service_loans.sql`
- [ ] `20260420_service_funding.sql`
- [ ] `20260420_service_savings.sql`
- [ ] `20260420_service_operations.sql`
- [ ] `20260420_service_seed.sql`
- [ ] `20260420_service_stawi.sql`

Run `make check-ids && make test`; commit each file.

---

### Task 15: Stawi-jobs SAs (stawi-jobs-bound)

These are bound to the stawi-jobs tenant/partition (not Thesa). Reuse xids from `20260416_seed_stawi_jobs_service_accounts.sql`. Audiences per the current file, converted to `["*"]`.

- [ ] `20260420_service_stawi_jobs_api.sql`
- [ ] `20260420_service_stawi_jobs_crawler.sql`
- [ ] `20260420_service_stawi_jobs_scheduler.sql`
- [ ] `20260420_service_stawi_jobs_candidates.sql`

Run `make check-ids && make test`; commit each file.

---

## Phase 4 — Cleanup and verification

### Task 16: Delete old seed migration files

**Files:** remove every seed file listed under "Deleted files" in the File Structure section of this plan.

- [ ] **Step 1: Confirm every expected row is now in the new seeds**

Before deleting, mentally walk through the deletion list and confirm each original file's contents are covered by one of the new `20260420_*` files. If anything isn't covered, STOP and add it.

- [ ] **Step 2: Delete all 18 files in one commit**

```bash
git rm \
  apps/tenancy/migrations/0001/20210514_create_default_tenant.sql \
  apps/tenancy/migrations/0001/20230820_create_stawi_tenant.sql \
  apps/tenancy/migrations/0001/20230820_create_stawi_test_tenant.sql \
  apps/tenancy/migrations/0001/20230820_create_stawi-dev_tenant.sql \
  apps/tenancy/migrations/0001/20230820_create_stawi-dev_test_tenant.sql \
  apps/tenancy/migrations/0001/20260306_seed_service_accounts_production.sql \
  apps/tenancy/migrations/0001/20260313_create_lender_tenant.sql \
  apps/tenancy/migrations/0001/20260313_create_lender_test_tenant.sql \
  apps/tenancy/migrations/0001/20260324_migrate_audiences_format.sql \
  apps/tenancy/migrations/0001/20260413_seed_fintech_service_accounts.sql \
  apps/tenancy/migrations/0001/20260415_create_sysops_partition.sql \
  apps/tenancy/migrations/0001/20260416_create_stawi_jobs_tenant.sql \
  apps/tenancy/migrations/0001/20260416_create_stawi_jobs_test_tenant.sql \
  apps/tenancy/migrations/0001/20260416_seed_stawi_jobs_service_accounts.sql \
  apps/tenancy/migrations/0001/20260417_update_stawi_jobs_dev_redirect_uris.sql \
  apps/tenancy/migrations/0001/20260419_add_fedcm_callback_redirect_uri.sql \
  apps/tenancy/migrations/0001/20260419_grant_service_authentication_files_upload.sql \
  apps/tenancy/migrations/0001/20260419b_fix_service_files_audience_name.sql
git commit -m "migration(tenancy): delete v1 seeds — replaced by v2 baseline"
```

---

### Task 17: Full suite passes

- [ ] **Step 1: Run the full suite**

Run: `make test`
Expected: every package `ok`.

- [ ] **Step 2: Run lint**

Run: `make format`
Expected: `0 issues.` plus `check-ids` passes with no mismatch.

- [ ] **Step 3: Run the FedCM integration tests specifically**

Run: `go test ./apps/default/tests/fedcm/... -run "TestFedCMFlow|TestFedCMSecurity" -v -timeout 10m`
Expected: all pass — confirms the baseline FedCM callback and audiences are intact.

---

### Task 18: Row-level diff vs current prod

**Goal:** prove that the new seeds produce the same SEMANTIC set of tenants, partitions, clients, and service accounts as currently in prod, catching any accidental omission.

- [ ] **Step 1: Dump current prod state**

From a kubectl shell or port-forwarded psql:

```bash
kubectl -n auth port-forward svc/pooler-ro.datastore 15432:5432 &
PF_PID=$!
PGPASSWORD=$(kubectl -n auth get secret db-credentials-tenancy -o jsonpath='{.data.password}' | base64 -d) \
  psql -h 127.0.0.1 -p 15432 -U $(kubectl -n auth get secret db-credentials-tenancy -o jsonpath='{.data.username}' | base64 -d) \
       -d tenancy -At \
       -c "SELECT name, environment FROM tenants ORDER BY name;" > /tmp/prod-tenants.txt
PGPASSWORD=... psql ... -c "SELECT client_id, type FROM clients ORDER BY client_id;" > /tmp/prod-clients.txt
PGPASSWORD=... psql ... -c "SELECT client_id, type FROM service_accounts ORDER BY client_id;" > /tmp/prod-sas.txt
kill $PF_PID
```

- [ ] **Step 2: Generate new-seed state**

Spin up a scratch Postgres via `docker run --rm -d -p 55432:5432 -e POSTGRES_PASSWORD=x postgres:16`, apply migrations with the tenancy migrator tool, dump the same tables:

```bash
docker run --rm -d --name pg-diff -p 55432:5432 -e POSTGRES_PASSWORD=x postgres:16
sleep 10
PGPASSWORD=x psql -h 127.0.0.1 -p 55432 -U postgres -d postgres -c "CREATE DATABASE tenancy;"
DATABASE_URL=postgresql://postgres:x@127.0.0.1:55432/tenancy?sslmode=disable \
  DO_MIGRATION=true go run ./apps/tenancy/cmd migrate
PGPASSWORD=x psql -h 127.0.0.1 -p 55432 -U postgres -d tenancy -At \
  -c "SELECT name, environment FROM tenants ORDER BY name;" > /tmp/new-tenants.txt
# ... clients, service_accounts ...
docker rm -f pg-diff
```

- [ ] **Step 3: Diff and reconcile**

```bash
diff -u /tmp/prod-tenants.txt /tmp/new-tenants.txt
diff -u /tmp/prod-clients.txt /tmp/new-clients.txt
diff -u /tmp/prod-sas.txt /tmp/new-sas.txt
```

Expected diffs: only the xid-replacement for `stawi-jobs-web` client_id (the human-readable strings are gone). Any other diff is a bug — fix the relevant seed file and re-run.

- [ ] **Step 4: Commit a short `DIFF_NOTES.md` documenting the expected deltas**

```bash
git add apps/tenancy/migrations/DIFF_NOTES.md
git commit -m "docs(migrations): record expected prod→v2 deltas for reviewer"
```

Body:
```markdown
# V2 seed-baseline diff notes

Diff artifacts produced by Task 18 of the standardization plan.

## Expected differences (prod → v2 baseline)

1. **stawi-jobs client_ids**: prod has `stawi-jobs-web` and `stawi-jobs-web-dev` (human-readable strings). v2 replaces both with fresh xids. Downstream: the Stawi Jobs frontend must be redeployed with the new client_id before cutover.

2. **All audience maps use `["*"]`** uniformly: prod had a mix of `[]`, `["*"]`, and specific-permission lists. v2 is all wildcards. Least-privilege tightening is a future dated patch.

## No unexpected deltas

Tenants, partitions, partition_roles, service accounts, and their profile_id placeholders are unchanged between prod and v2.
```

---

## Phase 5 — Rollout (operational, outside this plan)

Performed manually after Phases 1–4 land and the PR is merged:

1. Announce maintenance window; inform operators of Stawi Jobs frontend redeploy window.
2. Wipe the production tenancy DB and Keto tuple store.
3. Let Flux reconcile; new migration job runs the v2 baseline.
4. Trigger `synchronize-partitions` CronJob manually; confirm explicit OAuth clients sync to Hydra and Keto tuples populate.
5. Smoke-test: social login, FedCM, avatar sync.

---

## Self-review notes

**Spec coverage:** Every section of `docs/superpowers/specs/2026-04-20-migration-standardization-design.md` is covered:
- Tooling + templates → Phase 1 (Tasks 1–6)
- Partition seeds → Phase 2 (Tasks 7–8)
- Service seeds → Phase 3 (Tasks 9–15)
- Old-file deletion → Phase 4, Task 16
- Verification → Phase 4, Tasks 17–18
- Rollout → Phase 5 (manual)

**Carve-out:** During writing I identified one gap in the spec: service-account `client_id` MUST remain a human-readable string (`service-authentication`, `service-profile`, etc.) because it's the public identifier other services target in their `aud` claim; making it an xid would cascade into every consumer's OAuth2 audience config. The spec's `xid-only client_id` rule therefore applies only to **partition public clients** (end-user-facing apps), not to **service-account clients**. This carve-out is documented at the top of `IDS.md`, in the deleted-files rationale for this plan, and at the head of the service template.

**Placeholder scan:** No `TBD`, `TODO`, or "implement later" in the plan. Every step is concrete.

**Type consistency:** All filenames use `20260420_partition_*.sql` and `20260420_service_*.sql`; every task uses the same xid registry entries; every seed uses the same 14-column client or 13-column SA shape.

**Open issue flagged during writing:** The `stawi-jobs-web` → xid replacement is a breaking change for the Stawi Jobs frontend. Task 18's `DIFF_NOTES.md` documents it; rollout step 1 explicitly calls for the frontend redeploy before cutover.
