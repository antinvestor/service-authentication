# Tenancy Migration Standardization — Design

**Date:** 2026-04-20
**Owner:** Peter Bwire
**Status:** Design — awaiting implementation plan
**Precondition:** Production cluster will be wiped and re-seeded from scratch.

## Scope

Rewrite the tenancy seed migrations so introducing a new tenant or new service account is a copy-paste-edit of a uniform template with no surprises. Lock the repeatability with policies (audiences, xids, conflict policy, client shape) so future additions can't reintroduce the asymmetries that have accumulated in the current set.

**Explicitly in scope:**
- `apps/tenancy/migrations/0001/` — the tenancy DB seeds.
- A committed xid registry and `make` scaffolds so nobody hand-types identifiers.

**Explicitly out of scope:**
- Schema migrations (`20190521_initial_jsonb_tsv.sql`, `20210513_create_search_indices.sql`). Stay as-is.
- OPL/Keto namespace registration flow (a separate subsystem issue surfaced during recovery; tracked separately).
- Any non-tenancy migration path (Hydra, Keto's own store).

## Goals

1. **One file per tenant, one file per service account.** Copy-paste a file and edit three xids + URIs → new tenant or service.
2. **Uniform shape.** Every partition seed has identical columns, structure, property keys; every service-account seed same.
3. **Idempotent replay.** All inserts `ON CONFLICT DO NOTHING`. Mutations go through a dated patch migration.
4. **No post-seed patches in the baseline.** Every patch migration that could be reconciled into a seed file IS reconciled.
5. **Xid-only identifiers.** No human-readable client_ids. Collisions prevented by a committed registry plus tooling.
6. **Public URLs where external services care.** `jwks_uri` on service accounts is `https://oauth2.stawi.org/.well-known/jwks.json`. `redirect_uris` use the public accounts origin.

## Non-goals

- Preserving the current file history. Current seed files are deleted; git log preserves the past.
- Backward compatibility with clusters that were seeded before this change. The cluster is being wiped.
- Collapsing schema migrations. They stay on their original dates.

## Architecture overview

```
apps/tenancy/migrations/0001/
├── 20190521_initial_jsonb_tsv.sql          (unchanged)
├── 20210513_create_search_indices.sql      (unchanged)
├── 20260420_partition_ant_investor.sql     (new, templated)
├── 20260420_partition_stawi.sql            (new, templated)
├── 20260420_partition_stawi_dev.sql        (new, templated)
├── 20260420_partition_stawi_jobs.sql       (new, templated)
├── 20260420_partition_thesa.sql            (new, templated — includes Sysops child partition)
├── 20260420_service_authentication.sql     (new, templated)
├── 20260420_service_billing.sql            (new, templated)
├── …                                        (one file per service account)
└── 20260420_service_trustage.sql           (new, templated)
```

- Files within the date are alphabetically ordered; `partition_*` sorts before `service_*`, so dependencies resolve naturally.
- Child partitions (e.g. Sysops under Thesa) live inside their parent's file — they can't exist independently, and having them in the same file keeps the dependency local.
- New tenants or services introduced later use the current date as prefix, naturally sorting after the baseline.

## Partition template

Every `20260420_partition_<name>.sql` follows this recipe:

```sql
-- Copyright 2023-2026 Ant Investor Ltd
-- <Tenant display name> — <one-line purpose>.
--
-- All IDs are stable xids registered in IDS.md.
-- Re-seeding is a no-op (ON CONFLICT DO NOTHING).

-- 1. Tenant row (present only for top-level tenants; child-only partition files skip).
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES (
    '<tenant xid>',
    '<tenant xid>',
    '<partition xid>',
    '<Display name>',
    '<One-line description>',
    'production'                                           -- or 'development' for *_dev tenants
)
ON CONFLICT (id) DO NOTHING;

-- 2. Root partition of the tenant.
INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES (
    '<partition xid>',
    '<tenant xid>',
    '<partition xid>',
    '<parent partition xid or NULL>',
    '<Display name>',
    '<One-line description>',
    true,
    '{
      "default_role": "user",
      "allow_auto_access": true,
      "support_contacts": {"msisdn": "<phone>", "email": "<email>"}
    }'
)
ON CONFLICT (id) DO NOTHING;

-- 3. Three standard roles. `member` is the default (is_default=true).
INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('<role_owner_xid>',  NOW(), NOW(), 1, '<tenant_xid>', '<partition_xid>', 'owner',  false, '{"description":"Full control across all services"}'),
  ('<role_admin_xid>',  NOW(), NOW(), 1, '<tenant_xid>', '<partition_xid>', 'admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('<role_member_xid>', NOW(), NOW(), 1, '<tenant_xid>', '<partition_xid>', 'member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- 4. Production public client (authorization_code + refresh_token, PKCE, xid client_id).
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    '<client xid>',
    '<tenant xid>', '<partition xid>',
    '<Client display name>',
    '<client_id xid>',                                     -- xid only, no human-readable strings
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"<service_x>": ["*"], "<service_y>": ["*"]}',        -- wildcard ["*"] always
    '{"uris": [
        "https://app.example.com/auth/callback",
        "com.example.app://auth/callback",                 -- native-scheme URI only if app exists
        "https://accounts.stawi.org/_internal/fedcm-callback"
    ]}',
    'https://static.example.com/logo.png',
    '{"uris": ["https://app.example.com/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;

-- 5. Optional development/staging client (same shape, dev URIs).
-- Present when the tenant has a dev environment. Omit the block entirely otherwise.

-- 6. Optional child partition blocks.
-- For parents with children (Thesa → Sysops), repeat steps 2–4 for the child with its own xids,
-- using parent_id = the parent's partition xid.
```

**Locked policies enforced by this template:**
- `["*"]` audiences only; no `[]`, no specific-permission lists in partition clients.
- xid-only `client_id` column; no `stawi-jobs-web`-style strings.
- `ON CONFLICT (id) DO NOTHING` on every insert.
- All 14 client columns supplied on every client row; `logo_uri` and `post_logout_redirect_uris` always populated (never NULL, never empty when an app exists).
- FedCM callback URI baked in from day one; no later patch.

## Service-account template

Every `20260420_service_<name>.sql` follows this recipe:

```sql
-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: <service-name>
-- <One-line purpose.>

-- 1. OAuth2 client (client_credentials, private_key_jwt).
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    '<client xid>',
    '<thesa tenant xid>',                                  -- SAs live under Thesa root, except stawi-jobs-*
    '<thesa partition xid>',
    'sa-<service_name>',
    '<client_id xid>',
    '',                                                     -- client_secret empty (private_key_jwt signs)
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"<service_x>": ["*"], "<service_y>": ["*"]}',        -- wildcard ["*"] always
    'private_key_jwt',
    '<service_account xid>',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

-- 2. service_accounts row (paired with the client row above).
INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    '<service_account xid>',
    '<thesa tenant xid>',
    '<thesa partition xid>',
    '<profile xid from profile service seed>',             -- placeholder xid; resolveBotProfiles swaps at startup
    '<client_id xid>',                                      -- same as clients.client_id
    '<client xid>',                                         -- FK to clients.id
    'internal',
    '{"<service_x>": ["*"], "<service_y>": ["*"]}',        -- mirror of clients.audiences
    '{}'
) ON CONFLICT (id) DO NOTHING;
```

**Stawi-jobs-bound SAs (stawi-jobs-api, stawi-jobs-crawler, stawi-jobs-scheduler, stawi-jobs-candidates)** use the same template but with the stawi-jobs tenant/partition xid instead of Thesa's. They're bound to that tenant because their access scope is limited to stawi-jobs resources.

**Locked policies enforced:**
- `client_credentials` + `private_key_jwt` + `scopes='system_int openid'` on every SA.
- `jwks_uri = https://oauth2.stawi.org/.well-known/jwks.json` (public, not cluster-internal).
- `audiences` map identical between the `clients` row and the `service_accounts` row (the authz projection reads from `service_accounts`; drift is a silent permission bug).
- `["*"]` audiences only.

## Xid management

### IDS.md registry

A committed file `apps/tenancy/migrations/IDS.md` enumerates every xid allocated by every seed file, grouped by entity type:

```markdown
# Tenancy ID registry

Every xid introduced by a seed migration is recorded here. Collisions and
unregistered references fail a pre-commit grep check.

## Tenants
| xid                    | name           | file                              |
|------------------------|----------------|-----------------------------------|
| c2f4j7au6s7f91uqnojg   | Thesa          | 20260420_partition_thesa.sql      |
| 9bsv0s0hijjg02z5lbjg   | Stawi          | 20260420_partition_stawi.sql      |
| …                      | …              | …                                 |

## Partitions
| xid | tenant | parent | file |
| …   | …      | …      | …    |

## Clients
| xid | client_id | partition | file |

## Service accounts
| xid | profile_id (placeholder) | client | file |

## Partition roles
| xid | name | partition | file |
```

### `make` scaffolds

Two new `Makefile` targets:

- `make new-partition NAME=<snake_name> PARENT=<xid or root>` — writes `apps/tenancy/migrations/0001/<today>_partition_<name>.sql` from the template, substitutes a fresh set of xids (5: tenant, partition, 3 roles, 1 client, 1 client_id — see template), appends the xids to `IDS.md`, and prints the file path.
- `make new-service NAME=<snake_name>` — writes `<today>_service_<name>.sql`, substitutes 3 xids (client, client_id, service_account) plus the SA's profile_id placeholder, appends to `IDS.md`, and prints the file path.

Both targets delegate xid generation to a tiny helper under `tools/xid/` (50-line Go program, `go run ./tools/xid --count N`). No external dependency on the `xid` CLI.

### Pre-commit check

`make lint` (wrapping `make format`) adds a Python/sh check that:
1. Extracts every xid referenced inside `apps/tenancy/migrations/0001/*.sql` (grep by pattern).
2. Extracts every xid listed in `IDS.md`.
3. Fails if any SQL xid is missing from `IDS.md`.

Unregistered xids never merge. Registry drift is caught at PR time.

## Migration file-level changes

**Files deleted by this design** (reconciled into templated seeds):

| File | Why deleted |
|---|---|
| `20210514_create_default_tenant.sql` | Replaced by `20260420_partition_thesa.sql` |
| `20230820_create_stawi_tenant.sql` | Replaced by `20260420_partition_stawi.sql` |
| `20230820_create_stawi_test_tenant.sql` | Merged into `20260420_partition_stawi.sql` as the dev client block |
| `20230820_create_stawi-dev_tenant.sql` | Replaced by `20260420_partition_stawi_dev.sql` |
| `20230820_create_stawi-dev_test_tenant.sql` | Merged into `20260420_partition_stawi_dev.sql` |
| `20260306_seed_service_accounts_production.sql` | Exploded into one `20260420_service_*.sql` per SA |
| `20260313_create_lender_tenant.sql` | Replaced by `20260420_partition_ant_investor.sql` |
| `20260313_create_lender_test_tenant.sql` | Merged into `20260420_partition_ant_investor.sql` |
| `20260324_migrate_audiences_format.sql` | Legacy format migration; dead code on a fresh cluster |
| `20260413_seed_fintech_service_accounts.sql` | Exploded into `20260420_service_*.sql` per fintech SA |
| `20260415_create_sysops_partition.sql` | Folded into `20260420_partition_thesa.sql` as child partition |
| `20260416_create_stawi_jobs_tenant.sql` | Replaced by `20260420_partition_stawi_jobs.sql` |
| `20260416_create_stawi_jobs_test_tenant.sql` | Merged into `20260420_partition_stawi_jobs.sql` |
| `20260416_seed_stawi_jobs_service_accounts.sql` | Exploded into 4 `20260420_service_stawi_jobs_*.sql` |
| `20260417_update_stawi_jobs_dev_redirect_uris.sql` | Absorbed into stawi_jobs seed |
| `20260419_add_fedcm_callback_redirect_uri.sql` | FedCM URI baked into every partition seed's `redirect_uris` |
| `20260419_grant_service_authentication_files_upload.sql` | `service_file: ["content_upload"]` baked into service_authentication seed |
| `20260419b_fix_service_files_audience_name.sql` | The bug never exists in the rewritten seeds |

**Files kept unchanged:**
- `20190521_initial_jsonb_tsv.sql`
- `20210513_create_search_indices.sql`

**Files created:** ~5 partition seeds + ~24 service-account seeds (final count determined during the plan phase based on `IDS.md`).

## Content of the seeded data

### Tenants introduced by the baseline

1. **Thesa** (root, `c2f4j7au6s7f91uqnojg`) — the platform root tenant. Hosts all centralised service accounts. Sysops is a child partition here.
2. **Stawi** (production `9bsv0s0hijjg02z5lbjg`) — production consumer-facing partition. File includes both prod and dev clients.
3. **Stawi AI Builder** (`stawi_dev`) — the stawi.dev product. File includes both prod and dev clients.
4. **Ant Investor (lender)** — fintech-wide tenant. File includes both prod and dev clients.
5. **Stawi Jobs** — jobs product. File includes both prod and dev clients.

### Service accounts introduced by the baseline

Under Thesa: `service-authentication`, `service-profile`, `service-tenancy`, `service-notification`, `service-device`, `service-setting`, `service-payment`, `service-payment-jenga`, `service-ledger`, `service-billing`, `service-files`, `service-chat-drone`, `service-chat-gateway`, `foundry`, `gitvault`, `trustage`, `service-notification-integration-africastalking`, `service-notification-integration-emailsmtp`, `synchronise-partitions`, `service-identity`, `service-loans`, `service-funding`, `service-savings`, `service-operations`, `service-seed`, `service-stawi`.

Under Stawi Jobs tenant: `stawi-jobs-api`, `stawi-jobs-crawler`, `stawi-jobs-scheduler`, `stawi-jobs-candidates`.

Final SA list and their audience maps are enumerated in the plan phase — the plan diffs every SA against the current prod DB to make sure no permission is silently dropped.

### Specific fixes baked into the baseline

- `service-authentication`'s `service_files` audience key → corrected to `service_file: ["*"]`. (Note: during recovery we used `["content_upload"]` as the least-privilege explicit permission. Per locked policy, baseline uses `["*"]`. If least-privilege is desired later, a dated patch migration can scope it back.)
- FedCM internal callback URI (`https://accounts.stawi.org/_internal/fedcm-callback`) present in every authorization_code client's `redirect_uris`.
- Ant Investor and Sysops seeds use `ON CONFLICT DO NOTHING` like everything else — no more `DO UPDATE SET` exceptions.
- `stawi-jobs-web` client_id replaced with a fresh xid; the human-readable string is gone.
- All tenant support_contacts populate both `msisdn` and `email`. No more email-only entries.

## Verification before rollout

Mandatory steps before the plan phase is declared complete:

1. **Row-level diff.** Enumerate every row in `tenants`, `partitions`, `partition_roles`, `clients`, `service_accounts` in prod. Enumerate every row produced by running the new migrations against an empty DB. Three-way diff (prod / new seeds / existing test-harness expectations). Every discrepancy is either:
   - Intentional (fixing a known bug — FedCM URI, service_file name, etc.) and documented in the plan phase.
   - Or resolved before ship.
2. **`go test ./apps/tenancy/...` passes** against the rewritten migrations.
3. **Integration tests in `apps/default/tests/`** (handlers, fedcm) pass against the rewritten migrations.
4. **Dry-run in a scratch cluster** before the production cluster is wiped. Confirms:
   - All migrations apply cleanly on an empty DB.
   - `synchronize-partitions` cron populates Keto tuples correctly.
   - A test social-login flow succeeds end-to-end.

Only after all four steps pass do we wipe and re-seed prod.

## Out-of-scope follow-ups flagged during exploration

Not part of this spec, but surfaced during the investigation and worth tracking:

- **OPL namespace registration pipeline.** Services are expected to POST their permission manifests at migration time (via frame's `WithPermissionRegistration`). In the current prod state only `service_chat` registered successfully; everything else was unregistered, which is why our authz sync failed during the social-login incident. The fresh cluster should see this work for every service — worth verifying during dry-run.
- **The tenancy `DO_MIGRATION` pattern.** Helm upgrade currently runs migration as a Job, but the image update for v1.29.11 did not auto-trigger a new migration Job in prod (we ran it manually). Worth understanding whether the chart needs a hook.
- **Permission-list guarantee for each SA.** Today each service's OPL file lives in its own repo. The tenancy migration template uses `["*"]` wildcards which is always broad. Future least-privilege tightening can be done per-SA via dated patches without touching the baseline.

## Approval

Design approved by Peter Bwire (2026-04-20). Proceeds to implementation plan.
