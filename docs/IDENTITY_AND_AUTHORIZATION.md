# Identity and Authorization Model

**Canonical reference.** Prefer this document over ad-hoc comments when reasoning
about who is acting, what `client_id` means, and how Keto grants are keyed.

## Do not conflate these identifiers

| Identifier | What it is | Used for | **Not** used for |
|------------|------------|----------|------------------|
| **`profile_id`** | The **acting principal** (person or bot profile) | Keto subjects on all authorization planes; audit of “who did this” | Naming OAuth clients |
| **`client_id`** | OAuth2 client (often the partition’s public client, or a service account’s machine client) | Login / token issuance; resolving which **partition** the flow belongs to; Hydra client admin | Keto relation subjects; “who is requesting a resource” |
| **JWT `sub`** | OAuth2 subject claim | Wire-level JWT field | Sole authority for ReBAC when `profile_id` is present |

### Rules

1. **Permissions are granted against `profile_id`.**  
   Users and service accounts both act as profiles. Service accounts have a bot
   `profile_id`; that profile is the Keto subject for Plane 1 (`tenancy_access`)
   and Plane 2 (`granted_*` in service namespaces).

2. **`client_id` is for login and partition binding.**  
   During authorization-code or client-credentials flows, `client_id` tells us
   which OAuth client (and thus which partition / tenancy path) the token is
   for. It is **not** the actor requesting profile, tenancy, or other resources.

3. **JWT `sub` may differ from `profile_id` for machine tokens.**  
   Ory Hydra sets `sub` to the OAuth2 `client_id` for `client_credentials` and
   does not reliably allow the token hook to override `sub`. The token hook
   **must** still put `profile_id` in access-token claims. Frame resolves the
   actor via `GetProfileID()` (prefers `profile_id` claim over JWT `sub`).

4. **Never write Keto grants with `client_id` as the subject** “because JWT sub
   is the client_id.” That confuses OAuth client identity with the acting
   profile and will drift every time Hydra’s `sub` behaviour changes.

## End-to-end paths

### User (authorization code)

1. User authenticates; consent sets JWT `sub` = user `profile_id`.
2. Claims include `tenant_id`, `partition_id` from the **RP client** (`client_id`).
3. ReBAC checks: subject = `profile_id`, object path = `tenant_id/partition_id`.

### Service account (client_credentials)

1. Service authenticates as OAuth client (`client_id` = e.g. `service-authentication`).
2. Token webhook loads Hydra client metadata → bot `profile_id`, tenancy, roles.
3. Access token claims include `profile_id` (actor), `tenant_id`, `partition_id`, `roles`.
4. JWT `sub` may still be `client_id` (Hydra). Frame `GetProfileID()` uses claim.
5. Keto grants for that bot were written as subject = **`profile_id`**.

## Where grants are written

| Mechanism | Subject |
|-----------|---------|
| `AuthzServiceAccountSyncEvent` | `sa.ProfileID` |
| `EnsureServiceBotTenancyAccess` (bootstrap) | `sa.ProfileID` |
| User access / roles | user `profile_id` |

## Debugging checklist

1. Is the error subject a **client_id** (e.g. `service-authentication`)?  
   → Frame version may still be using JWT `sub` instead of `profile_id`.  
   → Upgrade frame; do **not** re-key Keto to client_id.
2. Does the access token carry `profile_id` (top-level or under `ext`)?  
   → Fix token enrichment if missing.
3. Does Keto have `#service` / `granted_*` for that **profile_id** on the path?  
   → Run SA policy sync / service-bot bootstrap; check audiences.

## Related code

- Frame: `security.AuthenticationClaims.GetProfileID`, tenancy/function checkers
- Token hook: `writeTokenHookResponseWithSubject` (always sets `profile_id`)
- SA sync: `apps/tenancy/service/events/authz_service_account_sync.go`
- Bot bootstrap: `apps/tenancy/service/business/bootstrap_service_bots.go`
- Overview: `CLAUDE.md`, `docs/TOKEN_ENRICHMENT.md`
