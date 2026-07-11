# Permission Manifest Registration

How services register namespaces, permissions, and role bindings with tenancy
(and how that drives Keto) — **configuration only**, no per-service custom
bootstrap code.

## Design goals

1. **Declare once** in proto (`service_permissions` + `method_permissions`).
2. **Register automatically** at process start (Frame + colony).
3. **Grant via SA policy** (auth-contract / SA config), not imperative scripts.
4. **Materialise to Keto** via the existing SA reconcile event pipeline.
5. **No per-app goroutines**, no one-off bootstrap hooks, no copy-paste.

## Plug-and-play checklist (every service)

| Step | Where | What |
|------|-------|------|
| 1 | Proto | `option (common.v1.service_permissions) = { namespace, permissions, role_bindings }` |
| 2 | Proto | `method_permissions` on each RPC |
| 3 | `cmd/main.go` | `frame.WithPermissionRegistration(serviceDescriptor)` once |
| 4 | Deploy (colony) | Default `PERMISSIONS_REGISTRATION_URL` → tenancy |
| 5 | Deploy (colony) | `oauth2.requestedAudiencePaths` = **business** deps only; colony auto-adds `/tenancy` when registration is enabled |
| 6 | Platform SA | Auth-contract policy lists which namespaces/permissions this SA needs |
| 7 | Owning SA | Root internal SA name/client matches namespace (`service-devices` ↔ `service_device`) |

That is the entire service-side contract. Everything else is platform plumbing.

## End-to-end flow

```
┌──────────────────┐   proto annotations    ┌────────────────────────────┐
│ Service binary   │ ─────────────────────► │ Frame PermissionRegistration│
│ (devices, files…)│   startup             │ POST manifest to tenancy   │
└──────────────────┘                        └─────────────┬──────────────┘
                                                          │ JWT (internal SA)
                                                          ▼
┌──────────────────┐   ownership check      ┌────────────────────────────┐
│ Service SA policy│ ◄── re-queue ───────── │ Tenancy register endpoint  │
│ (grants in DB)   │                        │ Upsert service_namespaces  │
└────────┬─────────┘                        └────────────────────────────┘
         │ EventKeyAuthzServiceAccountSync
         ▼
┌──────────────────┐
│ Keto granted_*   │  e.g. service_device:t/p#granted_device_manage ← profile_id
└──────────────────┘
```

### Critical distinction

| Concern | Config | Not |
|---------|--------|-----|
| OAuth token **audience** (who can call me / who I call) | Hydra client + `oauth_client_recipients` + `requestedAudiencePaths` | Keto grants |
| **Functional ReBAC** (what I may do) | SA authorization policy grants/permissions | OAuth audiences alone |
| **Namespace schema** (what permissions exist) | Proto → registration | Hand-edited Keto OPL alone |

Auth already **declares** `service_device:device_manage` and `service_file:content_upload` in its SA policy. Those grants stay **pending** until the owning service registers the namespace.

## Token claims required for registration

Service-account access-token extras (token webhook) **must** include:

| Claim | Purpose |
|-------|---------|
| `profile_id` | Actor identity (sub after Frame normalize) |
| `service_account_id` | Ownership binding for registration |
| `roles` | Must include `internal` |
| `tenant_id` / `partition_id` | Tenancy path (usually root) |
| `aud` | Must include tenancy resource URL when calling registration |

Colony injects `/tenancy` into `OAUTH2_REQUESTED_AUDIENCES` when
`permissionsRegistrationUrl` is set so services do not list it by hand.

Hydra must allow top-level claim mirroring for `service_account_id` (see
`oauth2.allowed_top_level_claims` / `mirror_top_level_claims` on the Hydra
release).

## Ownership rules (secure)

An SA may register namespace `N` only if all hold:

1. Authenticated with internal role  
2. `service_account_id` present and exists  
3. SA `type = internal`, not deleted  
4. SA `partition_id` = platform root partition  
5. SA `Name == N` **or** `ClientID` with `-`→`_` equals `N`  
   (e.g. `service-devices` owns `service_device`)

## Reliability

- Registration is an **idempotent upsert** keyed by namespace.
- Frame retries with backoff when tenancy/token signing is briefly unavailable.
- After registration, pending SA policies for that namespace are **re-queued**
  so Keto tuples catch up without manual intervention.
- Plane-1 `#service` for bot profiles is maintained by platform bootstrap on
  tenancy (not by each app).

## Debugging permission_denied (e.g. ShowConsent / device_manage)

Error shape:

```text
d75qclkpf2t1uum8ij40 cannot device_manage on service_device:tenant/partition
```

Actor is **profile_id** of the calling SA (auth bot). Check in order:

1. **Namespace registered?**  
   `SELECT namespace FROM service_namespaces WHERE namespace = 'service_device';`  
   If missing → owning service (`service-devices`) failed registration (usually
   missing tenancy audience → 403 on register).

2. **SA policy includes the grant?**  
   `service_account_authorization_grants` + `_permissions` for the caller SA.

3. **Policy applied?**  
   `status = applied` and `applied_generation = generation`.  
   If `failed` with `namespace "…" is not registered` → fix (1) then re-sync.

4. **Keto tuple exists?**  
   `service_device:t/p#granted_device_manage` subject = **profile_id**.

Do **not** add ad-hoc grants in app code or random startup goroutines. Fix
registration and SA policy config; the event pipeline is the framework.

## Related code

| Area | Location |
|------|----------|
| Frame publisher | `frame.WithPermissionRegistration` |
| Colony auto `/tenancy` audience | `charts/colony` ≥ 2.0.1 |
| Endpoint | `apps/tenancy/.../handlers/permissions.go` |
| Business rules | `apps/tenancy/.../business/permission_registry.go` |
| SA claims | `apps/default/.../handlers/webhook.go` |
| SA Keto sync | `apps/tenancy/.../events/authz_service_account_sync.go` |
| Proto annotations | `common/v1/permissions.proto` + per-service protos |
