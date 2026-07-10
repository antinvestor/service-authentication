# Identity and Authorization Model

**Canonical reference.** Prefer this document over ad-hoc comments when reasoning
about who is acting, what `client_id` means, and how Keto grants are keyed.

## Invariant

```text
JWT sub  ===  profile_id  ===  ReBAC subject
```

Always. For users and for service accounts. There is no case where `client_id`
is the acting subject for authorization.

## Do not conflate these identifiers

| Identifier | What it is | Used for | **Not** used for |
|------------|------------|----------|------------------|
| **`profile_id` / JWT `sub`** | The **acting principal** (person or bot profile) | Keto subjects on all planes; audit of “who did this” | Naming OAuth clients |
| **`client_id`** | OAuth2 client (RP app or service-account machine client) | Login / token issuance; resolving which **partition** the flow belongs to | Keto relation subjects; actor identity |

### Rules

1. **`sub` is always `profile_id`.**  
   Consent sets this for users. For service accounts, the token enrichment hook
   sets `profile_id` and requests subject override. After authentication, Frame
   `NormalizeIdentity()` ensures in-process claims have `Subject = profile_id`
   even if the wire JWT still has Hydra’s default `sub` for
   `client_credentials`.

2. **Permissions are granted against `profile_id`.**  
   Service accounts have a bot `profile_id`; that profile is the Keto subject.

3. **`client_id` is for login and partition binding only.**  
   It selects the OAuth client (and thus tenant/partition) for the token family.
   It is never the actor requesting resources.

4. **Never write Keto grants with `client_id` as the subject.**

## Hydra note (implementation detail, not a model exception)

Ory Hydra v26 sets wire JWT `sub` to the OAuth `client_id` for
`client_credentials` and the token hook cannot change that field. That is a
Hydra limitation, not a platform design choice.

Our compensation:

1. Token hook always writes `profile_id` into access-token claims (and best-effort
   top-level `subject`).
2. Frame `NormalizeIdentity()` rewrites `RegisteredClaims.Subject` to
   `profile_id` after JWT validation so **every service** sees
   `sub === profile_id`.

Do not “fix” this by keying Keto on `client_id`.

## End-to-end paths

### User (authorization code)

1. User authenticates; consent sets JWT `sub` = user `profile_id`.
2. Claims include `tenant_id`, `partition_id` from the RP `client_id`.
3. ReBAC: subject = `profile_id`, path = `tenant_id/partition_id`.

### Service account (client_credentials)

1. Service authenticates as OAuth client (`client_id` e.g. `service-authentication`).
2. Token webhook loads metadata → bot `profile_id`, tenancy, roles.
3. Claims include `profile_id` (actor). Wire `sub` may still be `client_id`.
4. Frame normalizes → `Subject` / `GetProfileID()` / `GetSubject()` = bot `profile_id`.
5. Keto grants for that bot use subject = **`profile_id`**.

## Where grants are written

| Mechanism | Subject |
|-----------|---------|
| `AuthzServiceAccountSyncEvent` | `sa.ProfileID` |
| `EnsureServiceBotTenancyAccess` | `sa.ProfileID` |
| User access / roles | user `profile_id` |

## Debugging checklist

1. Error subject looks like a **client_id** (`service-authentication`)?  
   → Frame is not normalizing (upgrade frame). Do **not** re-key Keto to client_id.
2. Token missing `profile_id` claim?  
   → Fix token enrichment webhook.
3. Keto missing `#service` / `granted_*` for the **profile_id**?  
   → SA policy sync / service-bot bootstrap.

## Related code

- Frame: `NormalizeIdentity`, `GetProfileID`, tenancy/function checkers
- Token hook: `writeTokenHookResponseWithSubject` (sets `profile_id` + subject)
- SA sync / bot bootstrap under `apps/tenancy/`
- `CLAUDE.md`, `docs/TOKEN_ENRICHMENT.md`
