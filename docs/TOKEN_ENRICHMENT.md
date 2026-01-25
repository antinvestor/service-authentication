# Token Enrichment Strategy

## Overview

This document describes how tokens are enriched with claims in the authentication service and the design decisions behind the current implementation.

## Token Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        INITIAL TOKEN ISSUANCE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. User authenticates (login.go, login_verification.go)                    │
│     • Login event created with device/session info                          │
│     • Stored in cache for consent stage                                     │
│                                                                              │
│  2. Hydra accepts login, redirects to consent                               │
│                                                                              │
│  3. Consent handler runs (consent.go)                                       │
│     • Fetches partition info (tenant_id, partition_id)                      │
│     • Fetches/creates device record (device_id)                             │
│     • Builds token claims map                                               │
│     • Accepts consent with claims in AccessTokenExtras & IdTokenExtras      │
│                                                                              │
│  4. Hydra stores consent session with claims                                │
│                                                                              │
│  5. Hydra calls webhook (webhook.go)                                        │
│     • API keys: Re-fetch claims from database                               │
│     • System internal: Add system roles                                     │
│     • Regular users: Pass-through (use consent claims)                      │
│                                                                              │
│  6. Hydra issues tokens with final claims                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           TOKEN REFRESH                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Client sends refresh_token to Hydra                                     │
│                                                                              │
│  2. Hydra retrieves stored consent session                                  │
│     • Contains original claims from consent                                 │
│                                                                              │
│  3. Hydra calls webhook with session data                                   │
│     • API keys: Re-fetch from database (tenant, partition, roles)          │
│     • System internal: Add system roles                                     │
│     • Regular users: Pass-through (claims unchanged)                        │
│                                                                              │
│  4. Hydra issues new tokens                                                 │
│     • Access token: Short-lived, with claims                               │
│     • Refresh token: Long-lived, for getting new access tokens             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Claim Categories

### 1. Session-Bound Claims (Immutable)

These claims represent the session that created the token family and **should not change** during refresh:

| Claim | Description | Why Immutable |
|-------|-------------|---------------|
| `device_id` | Device that initiated login | Tracks which device authenticated |
| `login_id` | Session ID at login time | Links to specific login session |

**Rationale:** If a user logs in from Device A, tokens should continue to indicate Device A even after refresh. This is important for:
- Security auditing ("which device made this request?")
- Session revocation ("revoke all tokens from Device A")
- Device-based access policies

### 2. Identity Claims (Stable)

These identify the user and rarely change:

| Claim | Description |
|-------|-------------|
| `profile_id` | User's profile identifier |
| `profile_contact` | User's contact (currently same as profile_id) |

### 3. Tenancy Claims (Client-Bound)

These are determined by the OAuth2 client, not the user:

| Claim | Description |
|-------|-------------|
| `tenant_id` | Tenant the client belongs to |
| `partition_id` | Partition (same as client_id) |

**Note:** These are stable for a given client. A client doesn't change tenants.

### 4. Authorization Claims (Could Be Dynamic)

| Claim | Description | Current Behavior |
|-------|-------------|------------------|
| `roles` | User's roles | Hardcoded to `["user"]` |

**Current Limitation:** Roles are not dynamic. If a user's roles change, they must re-authenticate.

## Why Regular Users Use Pass-Through

During token refresh, we cannot re-enrich regular user tokens because:

1. **No login_event available** - The login event is only cached during initial authentication
2. **Device context unavailable** - Refresh happens without user interaction
3. **Session data sufficient** - Hydra preserves the original claims in consent session

### What If We Need Dynamic Roles?

Options to consider:

#### Option A: Accept Current Behavior
- Roles are set at login
- Changes require re-authentication
- Common pattern in many OAuth2 systems

#### Option B: Introspection-Based Roles
- Don't embed roles in token
- Backend services call role service at request time
- Token just identifies user; roles checked separately

#### Option C: Short Token Lifetime
- Configure Hydra for 5-15 minute access tokens
- Users re-authenticate more frequently
- More overhead but fresher claims

#### Option D: Extract Subject and Refresh Roles
- Parse `profile_id` from existing session claims
- Fetch current roles at webhook time
- Add complexity but enables dynamic roles

## API Key Enrichment

API keys are different - they **do** get re-enriched on every token issuance:

```go
// webhook.go
if strings.HasPrefix(clientID, constApiKeyIDPrefix) {
    apiKeyModel, _ := h.apiKeyRepo.GetByKey(ctx, clientID)

    tokenMap := map[string]any{
        "tenant_id":    apiKeyModel.TenantID,
        "partition_id": apiKeyModel.PartitionID,
        "roles":        parseRoles(apiKeyModel.Scope),
    }
    // ... set on response
}
```

**Why?**
- API keys are system credentials, not user sessions
- No device/session context to preserve
- Database lookup is acceptable (service-to-service calls are less frequent)
- Scope/role changes should take effect immediately

## Recommendations

### For This Service

1. **Keep current pass-through for regular users** - It's correct for session semantics
2. **Document that role changes require re-auth** - Set appropriate expectations
3. **Consider short access token lifetime** - 15 minutes is reasonable
4. **API key behavior is correct** - Re-fetching is appropriate

### For Dynamic Roles (If Needed in Future)

1. Add role service client to `AuthServer`
2. In `webhook.go`, for regular users:
   ```go
   // Extract subject from existing claims
   existingAccessToken := sessionData["access_token"].(map[string]any)
   profileID := existingAccessToken["profile_id"].(string)

   // Fetch current roles
   roles := h.fetchUserRoles(ctx, profileID)

   // Update only roles, keep other claims
   existingAccessToken["roles"] = roles
   ```
3. Handle errors gracefully (fall back to existing roles)

### Security Considerations

1. **Webhook has no authentication** - Relies on network isolation
2. **Consider adding webhook authentication** - API key or mTLS
3. **Log all enrichment operations** - For security auditing
4. **Monitor for unusual patterns** - Excessive refresh, claim changes

## Testing Token Claims

To verify token claims:

```bash
# Get tokens via OAuth2 flow
# Then decode the JWT:
echo $ACCESS_TOKEN | cut -d. -f2 | base64 -d | jq .

# Expected claims:
{
  "tenant_id": "...",
  "partition_id": "...",
  "contact_id": "...",
  "roles": ["user"],
  "device_id": "...",
  "session_id": "...",
  "profile_id": "...",
  "profile_contact": "..."
}
```

## Related Files

- `apps/default/service/handlers/consent.go` - Initial claim enrichment
- `apps/default/service/handlers/webhook.go` - Refresh-time enrichment
- `apps/default/service/hydra/callback_v25.go` - Hydra client
