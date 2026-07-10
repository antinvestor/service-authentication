# Permission Manifest Registration

How services register namespaces, permissions, and role bindings with tenancy
(and how that drives Keto), securely and reliably.

## Invariant

- **Actor** for ReBAC is always `profile_id` (`JWT sub` after Frame normalize).
- **Permission namespaces** (e.g. `service_profile`) are owned by the matching
  **internal root service account** (`Name` / `ClientID` map to that namespace).
- Registration is **authenticated machine-to-machine** — not an open admin API.

## Startup flow (every service)

```
1. cmd/main.go: frame.WithPermissionRegistration(serviceDescriptor)
2. PERMISSIONS_REGISTRATION_URL points at tenancy:
     http://service-tenancy.../_internal/register/permissions
3. PreStart publishes proto service_permissions annotation as JSON manifest
4. Frame HTTP client uses the service's OAuth2 client_credentials token
5. Tenancy AuthenticationMiddleware validates JWT
6. Handler requires:
     - roles include "internal"
     - claims carry service_account_id (flat claim, not nested ext.ext)
     - SA is internal, on root partition, and owns the namespace
7. Upsert service_namespaces; re-queue SA policy sync + partition authz sync
8. AuthzServiceAccountSyncEvent materialises Keto granted_* for SAs that
   declare the namespace in their audiences
```

Colony chart injects `PERMISSIONS_REGISTRATION_URL` by default for all services.

## Token claims required for registration

Service-account access-token extras (token webhook) **must** include:

| Claim | Purpose |
|-------|---------|
| `profile_id` | Actor identity (sub after normalize) |
| `service_account_id` | Ownership binding for registration |
| `roles` | Must include `internal` |
| `tenant_id` / `partition_id` | Tenancy path (usually root) |

**Do not nest** `service_account_id` under a nested `ext` object inside the
access-token map — Hydra already places the whole map under JWT `ext`.

## Ownership rules (secure)

An SA may register namespace `N` only if all hold:

1. Authenticated with internal role
2. `service_account_id` present and exists
3. SA `type = internal`, not deleted
4. SA `partition_id` = platform root partition
5. SA `Name == N` **or** `ClientID` with `-`→`_` equals `N`  
   (e.g. `service-profile` owns `service_profile`)

## Reliability

- Registration is an **idempotent upsert** keyed by namespace.
- Frame retries with backoff when tenancy/token signing is briefly unavailable
  (auth cold start).
- After registration, pending SA authorization policies for that namespace are
  re-queued so Keto tuples catch up without manual intervention.
- Service bot Plane-1 bootstrap (`EnsureServiceBotTenancyAccess`) runs on
  tenancy start so `#service` exists even before individual SA policy sync.

## Service checklist

Every production binary that owns a `service_permissions` proto must:

1. Call `frame.WithPermissionRegistration(sd)` for each service descriptor
2. Run with `PERMISSIONS_REGISTRATION_URL` set (colony default)
3. Use frame ≥ **v2.0.5** so `sub === profile_id` after auth
4. Have a root internal SA whose name/client matches the namespace
5. Declare needed audiences on that SA so Plane-2 `granted_*` are written

## Debugging 403 on registration

| Symptom | Cause | Fix |
|---------|-------|-----|
| `service-account identity is required` | Missing `service_account_id` in token | Token webhook flat claim (not nested) |
| `internal service-account token is required` | No/invalid internal role | Webhook sets `roles: ["internal"]` |
| `cannot register this namespace` | SA name/client ≠ namespace, or not root/internal | Fix SA seed/name or client_id |
| Endless retry, status 503 | Token endpoint cold | Wait; retries continue |
| Registered but Keto still denies | SA policy not reconciled / missing audience | Trigger SA sync; check audiences |

## Related code

| Area | Location |
|------|----------|
| Frame publisher | `frame.WithPermissionRegistration` |
| Endpoint | `apps/tenancy/.../handlers/permissions.go` |
| Business rules | `apps/tenancy/.../business/permission_registry.go` |
| SA claims | `apps/default/.../handlers/webhook.go` `buildServiceAccountClaims` |
| SA Keto sync | `apps/tenancy/.../events/authz_service_account_sync.go` |
| Bot Plane-1 bootstrap | `apps/tenancy/.../business/bootstrap_service_bots.go` |
