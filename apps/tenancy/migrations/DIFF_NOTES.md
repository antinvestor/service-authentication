# V2 baseline diff notes

Documents the intentional differences between the v1 seed state and the v2 squashed baseline. Read this before reviewing or rolling out the new migrations.

## Summary

The v2 baseline is a transcription of every v1 tenant, partition, role, client, and service-account row into a uniform template. Every v1 xid is preserved; only two `clients.client_id` values change (the `stawi-jobs-web*` human-readable strings). All other deltas are systematic transformations applied uniformly.

## Intentional deltas

### 1. All `audiences` values use `["*"]`

v1 used a mix of `[]` (empty), `["*"]` (wildcard), and specific-permission lists. v2 uniformly uses `["*"]` for every service key on every client and service_account row. This is Rule 4 from the standardization spec.

**Impact:** broader permission for service-account-to-service RPC calls. If least-privilege tightening is desired later, a dated patch migration can scope specific SAs.

### 2. FedCM internal callback URI baked into every public client

Every `redirect_uris.uris` array now includes `"https://accounts.stawi.org/_internal/fedcm-callback"` as its final entry. The separate `20260419_add_fedcm_callback_redirect_uri.sql` patch is deleted; its effect is absorbed into the seeds.

### 3. `stawi-jobs-web` / `stawi-jobs-web-dev` client_ids replaced with xids

The two human-readable strings are replaced by fresh xids:
- Prod client_id: `d7is2kspf2t7cl19qlp0`
- Dev client_id:  `d7is2kspf2t7cl19qlpg`

Partition public clients MUST use xids for their `client_id` column per the v2 policy. Service-account clients retain their human-readable `client_id` strings because they're the public identifier other services target in `aud` claims (documented carve-out at the top of `IDS.md`).

**Impact:** the Stawi Jobs frontend must be redeployed with the new client_id before the cluster is wiped and re-seeded. This is noted in the rollout checklist.

### 4. Ant Investor `ON CONFLICT` policy

v1 used `DO UPDATE SET audiences, redirect_uris` on the Ant Investor prod and dev clients. v2 uses `DO NOTHING` uniformly per Rule 9.

**Impact:** the clients still get inserted on a fresh cluster; re-running the migration on an existing row is a no-op instead of a silent overwrite. Mutations now require a dated patch migration — intentional.

### 5. System Operations (Sysops) folded into `partition_thesa.sql`

v1 had `20260415_create_sysops_partition.sql` as a standalone file. v2 folds it into `20260420_partition_thesa.sql` because Sysops is a child partition of Thesa — it can't exist without the parent and the grouping makes the dependency local.

### 6. Service-file audience name correction

v1 had a bug where `service-authentication`'s audiences map used the key `"service_files"` (plural). The real Keto/OPL namespace and service-files jwtVerifyAudience are both `"service_file"` (singular). v2 uses the correct singular key for all service_file references.

### 7. Stawi-jobs service-account `scopes`

v1 stawi-jobs SAs used `scopes = 'internal openid'`. v2 uniformly uses `'system_int openid'` per the v2 convention (matching the Thesa-bound SAs).

**Impact:** should be semantically equivalent — both scopes denote internal service-account callers — but worth a smoke test on a stawi-jobs SA token after re-seed.

### 8. Stawi-jobs dev redirect URIs

v1 had a two-step history: initial `20260416_create_stawi_jobs_test_tenant.sql` with `localhost:1313` URIs, then `20260417_update_stawi_jobs_dev_redirect_uris.sql` patching to `localhost:5170`. v2 bakes the post-patch URIs into the seed directly; the patch file is deleted.

### 9. All service-account `jwks_uri` uses the public URL

v1 had `"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"` (cluster-internal). v2 uniformly uses `"https://oauth2.stawi.org/.well-known/jwks.json"` (public).

**Impact:** external JWKS consumers can now reach it directly; in-cluster callers resolve the public URL to the gateway and come back in — slightly longer but works everywhere.

### 10. `20260324_migrate_audiences_format.sql` deleted

This file exists only to convert a legacy `{"namespaces": [...]}` audience shape to the current map form. The fresh cluster never has the legacy shape, so the migration is dead code.

## Operator checklist before cluster wipe

1. **Stawi Jobs frontend**: redeploy with new client_ids (`d7is2kspf2t7cl19qlp0` prod, `d7is2kspf2t7cl19qlpg` dev). This MUST happen before cutover or jobs users can't sign in.
2. **Every platform service's migration job runs on cluster bring-up** — each service (profile, tenancy, device, notification, files, audit, chat, etc.) has `frame.WithPermissionRegistration` wired into its migration entrypoint, which POSTs its permission manifest to `http://service-tenancy.auth.svc/_internal/register/permissions`. The resulting rows in tenancy's `service_namespaces` table are the ONLY source of truth for the Keto OPL. Make sure `PERMISSIONS_REGISTRATION_URL` + `DO_MIGRATION=true` are set on every service's migration Job. If one service doesn't run its migration, its namespace won't exist, and that service's authz sync will fail downstream.
3. **`keto-namespace-combined` ConfigMap is cluster-derived, not hand-authored.** The Flux kustomization at `manifests/namespaces/auth/authorization/` has `http://service-tenancy.auth.svc/_internal/opl?domain=platform&name=keto-namespace-combined&namespace=auth` as a `resources:` entry. Flux re-fetches on each reconciliation. Do NOT `kubectl apply` the ConfigMap manually — Flux will revert it on its next pass. To force a refresh after registrations land, run `flux reconcile kustomization auth-authorization --with-source` so kustomize pulls the freshly-generated OPL.
4. **`SYNCHRONISE_PRIMARY_PARTITIONS=True`** on the tenancy service — confirms Hydra clients are re-synced from the new seed after migration.
5. **`synchronize-partitions` cron** — hourly, but trigger manually on cutover to write the Keto tuples for service-authentication + every other SA straight away.
6. Smoke-test: one social login (avatar sync should fire), one FedCM flow, one service-to-service RPC (e.g. auth → profile).

## Things that did NOT change

- Every `tenants.id`, `partitions.id`, `partition_roles.id`, `clients.id` (except stawi-jobs client_id column), `service_accounts.id` is preserved from v1.
- Every `profile_id` placeholder is preserved — `resolveBotProfiles` resolves them to real profile-service IDs at tenancy startup.
- Every SA's list of target services (audience keys) is preserved — only the permission values were converted to wildcard.
- Every tenant's display name, environment, support_contacts are preserved from v1.
