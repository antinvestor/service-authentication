# FedCM Identity Provider — Design

**Date:** 2026-04-18
**Owner:** Peter Bwire
**Status:** Design — awaiting implementation plan

## Scope

Make the authentication service a [Federated Credential Management](https://fedidcg.github.io/FedCM/) (FedCM) compliant Identity Provider (IdP), serving all current Hydra-backed OAuth2 clients. Ship as a complete feature; no feature flag.

**Explicitly out of scope** (separate follow-up specs):
- FedCM-based Google sign-in on `/s/login` (subproject 2).
- UI streamlining of the `stawi.dev` profile widget (subproject 3).

The `stawi.dev` widget's existing `shared/auth-runtime/src/fedcm.ts` code path already calls the endpoints defined here and is expected to work without client-side changes once this spec lands.

## Goals

1. Expose a conformant FedCM IdP at a single global origin (e.g. `auth.stawi.org`).
2. Issue tokens through Hydra so there is exactly one source of truth for access/refresh tokens, claims, and audit — no parallel issuance path.
3. Support multiple signed-in accounts per browser, matching Google's FedCM UX.
4. Preserve every existing flow (contact+verify, social Google via OAuth redirect, consent auto-approval, service accounts, webhook enrichment) with zero regression.
5. Keep security posture at or above the current bar: encrypted cookies, origin binding, nonce passthrough, rate limits, no token leakage.

## Non-goals

- Supporting FedCM for service-to-service (client_credentials) flows.
- Replacing Hydra's OAuth2 endpoints.
- Cross-device or cross-browser account portability beyond what FedCM natively provides.
- Password/contact-change event emission from the profile service (only a consumer hook is added here).

## Architecture

One global FedCM IdP origin. Tenant is resolved per-request from the RP-supplied `client_id`, exactly like the existing OAuth2 flow. All FedCM routes live in the default app alongside existing handlers. A new package `apps/default/service/fedcm/` holds pure logic (session, origin validation, branding, headless driver). A new `models/idp_session_entry.go` holds the session-entry shape.

```
Browser (RP context)                   Auth Service (IdP)                 Hydra
   │                                        │                               │
   │── GET /.well-known/web-identity ───────▶│                               │
   │◀───────── config.json URL ──────────────│                               │
   │── GET /fedcm/config.json ──────────────▶│                               │
   │◀──────── IdP endpoint URLs ─────────────│                               │
   │── GET /fedcm/accounts (idp_session) ───▶│                               │
   │◀──────── accounts list ─────────────────│                               │
   │── GET /fedcm/client_metadata ──────────▶│ (partition.Properties)        │
   │◀──────── ToS/privacy/branding ──────────│                               │
   │── POST /fedcm/id-assertion ────────────▶│── internal authorization_code,│
   │        {client_id, nonce, account_id}  │   prompt=none, admin accept ──▶│
   │                                        │◀─── code ─────────────────────│
   │                                        │── token exchange ────────────▶│
   │                                        │◀─── id_token/access/refresh ──│
   │◀──────── {token: id_token} ─────────────│                               │
   │── POST /fedcm/token-exchange ──────────▶│                               │
   │◀──────── access + refresh tokens ───────│                               │
```

## Endpoints

All routes registered in `apps/default/service/handlers/routing.go`.

| Method | Path | Purpose | Auth / validation |
|---|---|---|---|
| GET | `/.well-known/web-identity` | Advertises FedCM config location | Public, static JSON |
| GET | `/fedcm/config.json` | IdP config per FedCM spec | Public, static JSON |
| GET | `/fedcm/accounts` | Accounts in caller's `idp_session` | `idp_session` cookie; `Sec-Fetch-Dest: webidentity` |
| GET | `/fedcm/client_metadata` | Branding/ToS/privacy for the RP | CORS to RP origin; `Sec-Fetch-Dest: webidentity` |
| POST | `/fedcm/id-assertion` | Headless Hydra flow → id_token | `idp_session` + origin + `Sec-Fetch-Dest` |
| POST | `/fedcm/token-exchange` | One-shot swap: id_token → access+refresh | Fresh id_token (≤60s) + PKCE verifier |
| POST | `/fedcm/disconnect` | Remove account + revoke Hydra consent | `idp_session` + `Sec-Fetch-Dest` |
| POST | `/s/login/{loginEventId}/fedcm-complete` | Consumes a FedCM id_token on `/s/login` and accepts the Hydra login challenge | `login_challenge` + id_token freshness |
| GET/POST | `/s/fedcm/login` | Cold-start login popup | Rate-limited per IP + contact |

**Changed routes:**
- `GET /s/login` — refactored to FedCM-first (see [Login UI](#login-ui-convergence)); fully backward compatible for browsers without FedCM.
- `GET /s/logout` — also removes the current `profile_id` from `idp_session` and writes a revocation-list entry.

All other routes unchanged.

## Package layout (new code)

```
apps/default/service/
├── handlers/
│   ├── fedcm_wellknown.go        # /.well-known/web-identity, /fedcm/config.json
│   ├── fedcm_accounts.go         # GET /fedcm/accounts
│   ├── fedcm_client_metadata.go  # GET /fedcm/client_metadata
│   ├── fedcm_assertion.go        # POST /fedcm/id-assertion
│   ├── fedcm_token_exchange.go   # POST /fedcm/token-exchange
│   ├── fedcm_disconnect.go       # POST /fedcm/disconnect
│   └── fedcm_login.go            # /s/fedcm/login
├── fedcm/
│   ├── session.go                # idp_session cookie encode/decode, upsert, evict
│   ├── headless.go               # headless Hydra authorization_code driver
│   ├── origin.go                 # origin→client validation
│   ├── branding.go               # partition Properties → client metadata
│   ├── revocation.go             # cache-backed revocation list
│   └── ratelimit.go              # FedCM-specific rate limits
└── models/
    └── idp_session_entry.go      # one entry per signed-in account
```

Static assets:
- `apps/default/static/js/fedcm.js` — browser-side FedCM probe used from `/s/login` and `/s/fedcm/login`.

Templates:
- `apps/default/tmpl/login.html` — updated to include FedCM probe.
- `apps/default/tmpl/fedcm_login.html` — new narrow cold-start template.
- `apps/default/tmpl/fedcm_close.html` — new tiny stub page that calls `IdentityProvider.close()` on success.

## IdP session model

The `idp_session` cookie is a new persistent cookie, separate from every existing cookie.

**Attributes:** `HttpOnly; Secure; SameSite=None; Path=/; Domain=<idp-origin>`. `SameSite=None` is required for cross-site FedCM calls; compensating controls are origin binding, `Sec-Fetch-Dest` validation, short sliding lifetime, and the revocation list.

**Encryption:** AES-256-GCM via the existing `providers.StateCodec`, keys from `SECURE_COOKIE_BLOCK_KEY`. No PII on the wire in plaintext.

**Payload:**

```go
type IdPSession struct {
    Version    int
    Entries    []IdPSessionEntry
    CreatedAt  time.Time
    LastActive time.Time
}

type IdPSessionEntry struct {
    ProfileID    string
    Contact      string    // email OR phone
    ContactType  string    // "email" | "phone"
    Name         string
    AvatarURL    string
    AddedAt      time.Time
    LastUsedAt   time.Time
    LoginEventID string
    DeviceID     string
    AuthMethod   string    // "contact_verify" | "social:google" | ...
}
```

Bounded at 5 entries; oldest (by `LastUsedAt`) evicted on overflow.

### Contact-to-FedCM mapping

FedCM spec expects `email`/`name`/`picture` in the accounts response. Map per entry:

- `ContactType == "email"`: populate FedCM `email = Contact`, `name = Name`.
- `ContactType == "phone"`: omit FedCM `email`, set `name = Name` (and include phone in a display-only synthesized label — see `fedcm_accounts.go` for formatting).

### Lifecycle

| Event | Effect |
|---|---|
| Fresh login at `/s/fedcm/login` or `/s/login` | Upsert entry for the authenticated `profile_id`; evict oldest if `len > 5` |
| FedCM `id_assertion` | Touch `LastUsedAt` + `LastActive`; extend sliding expiry |
| `POST /fedcm/disconnect` | Remove entry; if `Entries` empty, clear cookie |
| `GET /s/logout` | Remove current `profile_id` entry; write revocation list |
| Password / contact change (consumer hook) | Write revocation list for that `profile_id` across all clients |
| Cookie age > 90d | Reject on decode; force full re-login |
| `LastActive` > 30d | Reject on decode; force full re-login |

### Seeding rule

On rollout, existing users do **not** get auto-populated from `remember_me_storage`. Every user must complete one fresh login before FedCM is available. This is intentional and confirmed with the product owner.

## Headless Hydra flow (`id_assertion_endpoint`)

This is the mechanism that makes FedCM issue Hydra-authoritative tokens. When the browser POSTs `{client_id, nonce, account_id, disclosure_text_shown, params...}`:

**Step 1 — Validate.**
- `Sec-Fetch-Dest: webidentity` present.
- `Origin` matches a registered redirect URI origin for `client_id`.
- `account_id` is present in decoded `idp_session` cookie.
- Revocation list empty for `(account_id, client_id)`.
- `client_id` resolves to an active partition via existing `resolvePartitionByClientID`.
- `nonce` is a ≤128-char opaque string.

**Step 2 — Resolve.**
- Select the matching `IdPSessionEntry`.
- Load the profile from the Profile Service (same client used during regular consent).

**Step 3 — Drive Hydra authorization server-to-server.**

The handler performs an HTTP GET against Hydra's public `/oauth2/auth` with:

```
response_type=code
client_id=<RP's client_id>
redirect_uri=<internal FedCM callback URI registered for this client>
scope=<client's registered default scopes>
nonce=<passed through from FedCM>
state=<random, bound to a cache entry (Step 4)>
code_challenge=<generated PKCE challenge>
code_challenge_method=S256
prompt=none
```

Hydra redirects to our configured login URL (`/s/login?login_challenge=...`). The handler follows the redirect chain **server-side** using a dedicated HTTP client with a custom `CheckRedirect` that inspects each hop rather than following blindly. When it sees Hydra's login-challenge URL, it pauses and moves to Step 4.

**Step 4 — Auto-accept via Hydra admin API.**

- `GET /admin/oauth2/auth/requests/login?login_challenge=...` → fetch request details.
- `PUT /admin/oauth2/auth/requests/login/accept` with:
  - `subject: profile_id`
  - `remember: false` (our `idp_session` is the remember mechanism; Hydra's remember is irrelevant)
  - `acr: "fedcm"`
  - `amr: [<original auth method from entry>]`
- Follow Hydra's redirect to the consent challenge.
- `GET /admin/oauth2/auth/requests/consent?consent_challenge=...`.
- `PUT /admin/oauth2/auth/requests/consent/accept` — **reusing the same claims-building logic** as the existing `/s/consent` handler (`buildTokenClaims` logic in `login_step_4_consent.go`, extracted into a reusable function): `tenant_id`, `partition_id`, `roles: ["user"]`, `device_id`, `login_id`, `profile_id`, plus any standard OIDC claims from the profile.

This reuse is critical: **no duplicated claims logic, no divergence between FedCM and regular login**.

**Device enrollment during headless flow (E1):** Before the consent-accept call, the handler reads the `device_storage` cookie presented on the FedCM request. If present and valid, its `device_id` is reused and included in the token claims. If missing, a new device is enrolled via the Device Service (same code path as the regular consent handler), the resulting `device_id` is set into the response as a `device_storage` cookie AND included in the token claims. Net effect: FedCM sign-in enrolls devices identically to regular sign-in; the `device_id` in every FedCM-issued token is always a real, enrolled device.

**Step 5 — Complete code exchange.**
- Hydra redirects to the internal `fedcm-callback` URI with `code` and `state`.
- Verify `state` against the cache entry; extract `code_verifier`.
- `POST /oauth2/token` with `grant_type=authorization_code`, `code`, `code_verifier`, `client_id`, and the partition's registered `client_secret` (server-side only — never leaves the service).
- Receive `{access_token, id_token, refresh_token}` from Hydra.

**Step 6 — Return to browser.**
- Per FedCM spec, respond with `{"token": "<id_token>"}`.
- Write a one-shot cache entry `fedcm:exchange:<hash(id_token)>` containing `{access_token, refresh_token, profile_id, client_id, expires_at}` with a 60s TTL. The browser follows with `POST /fedcm/token-exchange` to retrieve these.

**Concurrency:** `fedcm:lock:<profile_id>:<client_id>` cache lock with 5s TTL serializes concurrent id_assertion calls for the same (profile, client) pair, preventing Hydra challenge-state races. Lock contention returns HTTP 409 with a hint header; clients retry once.

**Client-secret handling:** The internal code-exchange call uses the partition's registered OAuth2 `client_secret`. This is acceptable because it happens server-to-server inside the auth service; the secret never transits the browser. PKCE is still enforced end-to-end.

## Token-exchange endpoint (`POST /fedcm/token-exchange`)

Separate from FedCM's id_assertion to keep the spec-conformant response shape clean, and to give us a clear security boundary for minting long-lived tokens.

**Request:**
```json
{
  "id_token": "<the id_token just received from /fedcm/id-assertion>",
  "code_verifier": "<PKCE verifier the client generated BEFORE /fedcm/id-assertion>"
}
```

**Validation:**
- Hash `id_token`, look up `fedcm:exchange:<hash>` in cache. Miss or expired → 401.
- Compare `code_verifier` hash to the one stored in Step 6. Mismatch → 401.
- DELETE the cache entry before responding (one-shot).
- Enforce `Sec-Fetch-Dest: empty` (follow-up XHR) and Origin == same origin the id_assertion was served to.

**Response:**
```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

All subsequent refreshes use Hydra's standard `refresh_token` grant; this endpoint is one-shot.

## Login UI convergence

### `/s/login` (modified)

The page renders:
1. Branding (from partition).
2. Inline FedCM probe (via `/static/js/fedcm.js`) — on page load:
   - If `"IdentityCredential" in window`, call `navigator.credentials.get({identity: {providers: [{configURL: "/fedcm/config.json", clientId: <from login_challenge>, nonce: <server-generated>}]}, mediation: "optional"})`.
   - On success, POST the id_token to `/s/login/{loginEventId}/fedcm-complete` — new handler that validates the id_token and accepts Hydra's login challenge using the same subject/claims logic.
   - On dismiss or unsupported, the form is already visible underneath; user proceeds normally.
3. Contact input (unchanged from today).
4. Single "Continue with Google" button (visually de-emphasized). Google FedCM integration is deferred to subproject 2 — this button keeps the existing OAuth redirect path for now.
5. Submit → `POST /s/login/{loginEventId}/post` (unchanged).

Zero regression: browsers without FedCM see exactly today's flow.

### `/s/fedcm/login` (new)

Narrow cold-start popup. Used when `accounts_endpoint` returns empty and the browser opens `login_url`.

- No `login_challenge` context (the RP's Hydra challenge is queued elsewhere).
- Renders a "Sign in to continue" heading with minimal branding.
- Contact + verification-code flow (reuses existing `VerificationEndpointShow`/`Submit` with a different post-success path that appends to `idp_session`).
- No social providers on this page (keeps the cold-start surface minimal; users who need Google go through the main `/s/login`).
- On success: append to `idp_session`, render `fedcm_close.html` which calls `IdentityProvider.close()` to close the popup and re-invoke the RP's request.

### Templates

- `login.html` — modified: remove any multi-provider clutter beyond Google; add FedCM probe script reference.
- `fedcm_login.html` — new: narrow cold-start layout.
- `fedcm_close.html` — new: stub page calling `IdentityProvider.close()`.
- `workspace_selector.html`, `access_instructions.html`, `contact_verification.html`, `login_complete.html`, `error.html`, `not_found.html` — unchanged.

### UI principles

- Single column, 400px max-width (existing `css/auth.css` already supports).
- One primary action visible at a time.
- No "remember me" checkbox on FedCM paths — `idp_session` is the remember mechanism. Non-FedCM flow keeps existing `remember_me_storage` behavior unchanged.
- Inline error states, not modals.
- Strict CSP; no inline scripts.

## Client metadata

`GET /fedcm/client_metadata?client_id=...` returns:

```json
{
  "privacy_policy_url": "...",
  "terms_of_service_url": "...",
  "icon_url": "...",
  "background_color": "..."
}
```

Values resolved from `Partition.Properties` (existing map). Resolution order:
1. Partition's own Properties (`privacy_policy_url`, `terms_of_service_url`, `branding_icon_url`, `branding_background_color`).
2. Parent tenant's Properties.
3. Service-level default from config (`FEDCM_DEFAULT_*`).

No schema change required.

## Security posture

### Request-level validation (every FedCM endpoint)

- `Sec-Fetch-Dest: webidentity` required on `/fedcm/accounts`, `/fedcm/client_metadata`, `/fedcm/id-assertion`, `/fedcm/disconnect`. Rejection → 400.
- `Origin` header required. For `accounts`, `id-assertion`, and `disconnect`, Origin must match a registered redirect URI origin for `client_id`. For `/fedcm/config.json` and `/.well-known/web-identity`, no origin check (public static).
- `Referer` NOT trusted for any decision.
- CORS: `client_metadata_endpoint` returns `Access-Control-Allow-Origin: <RP origin>` + `Access-Control-Allow-Credentials: true`. Other endpoints rely on same-origin enforcement from the browser's FedCM implementation.

### Cookie hardening

- `idp_session` — `HttpOnly; Secure; SameSite=None; Path=/`.
- AES-256-GCM encrypted. Same codec as existing cookies.

### Replay / CSRF

- RP nonce passed through into the Hydra id_token claim; RP verifies.
- Internal `state` parameter bound to a short-lived (60s) cache entry keyed on `(idp_session_hash, client_id, code_verifier_hash)`. Mismatch → abort.

### Token minting safeguards

- `id_assertion_endpoint` reachable only by the browser (enforced by `Sec-Fetch-Dest` + cookie combination).
- Internal code exchange uses partition's registered `client_secret` + PKCE, server-side.
- Response body returned only to the initiating browser context (browser enforces same-origin).
- Follow-up `token-exchange` is single-shot, 60s TTL, requires PKCE verifier match.

### Revocation & session hygiene

- Revocation list checked before every id_assertion.
- `/s/logout` writes revocation entries for the current `profile_id` across all its known `(profile_id, client_id)` pairs.
- Consumer hook for profile-change events (no-op if no events arrive — real emission is a follow-up in the profile service).

### Rate limiting (new package `fedcm/ratelimit.go`, reuses existing middleware)

- `id_assertion_endpoint`: ≤10/min per (idp_session_hash, client_id), burst 3.
- `/fedcm/disconnect`: ≤5/min per idp_session_hash.
- `/s/fedcm/login`: reuses existing per-IP + per-contact rate limit middleware.

### CSP

- `/s/login` and `/s/fedcm/login` maintain strict CSP with `script-src 'self'`; no inline scripts.

### Audit & logging

- Every FedCM request logged with `correlation_id`, `client_id`, outcome, latency, and validation result.
- No plaintext `idp_session`, nonce, or token in logs (hashes OK where useful).
- Emits the same audit event shape as regular login with `method: "fedcm"`, `acr: "fedcm"`.

## Data model and storage

No new Postgres tables.

Cache keys (using existing `CACHE_URI` infra — NATS JetStream KV or memory):

| Key | Purpose | TTL |
|---|---|---|
| `fedcm:flowstate:<hash>` | Headless-flow state binding | 60s |
| `fedcm:exchange:<id_token_hash>` | Token-exchange one-shot gate | 60s (deleted on consume) |
| `fedcm:revocation:<profile_id>:<client_id>` | Revocation list entry | 90d |
| `fedcm:lock:<profile_id>:<client_id>` | Serialization lock | 5s |

## Error handling

Internal conditions → FedCM-conformant responses:

| Internal condition | Response |
|---|---|
| Missing / invalid `Sec-Fetch-Dest` | 400, no body |
| Origin not registered for client | 403, `{"error": "invalid_request"}` |
| `idp_session` missing / expired | 401, `{"error": "not_signed_in"}` |
| `account_id` not in session | 401, `{"error": "not_signed_in"}` |
| Revocation list hit | 403, `{"error": "access_denied"}` |
| Hydra `prompt=none` → `login_required` | 401, `{"error": "not_signed_in"}` |
| Partition resolution failure | 500, `{"error": "server_error"}` + alert |
| Rate limit exceeded | 429, `{"error": "too_many_requests"}` |
| Flow state mismatch (CSRF) | 400, `{"error": "invalid_request"}` |
| Lock contention (concurrent id_assertion) | 409, client retries once |

All errors logged with `correlation_id`. No stack traces in responses even when `EXPOSE_ERRORS=true`.

## Testing strategy

Follows existing `BaseTestSuite` conventions and `testing-go` skill rules (testcontainers for owned infra, real integration over mocks, race detection, context-aware).

### Unit tests

- `fedcm/session.go` — cookie encode/decode, upsert semantics, eviction on overflow, TTL checks.
- `fedcm/origin.go` — origin-to-client matching across multiple registered redirect URIs.
- `fedcm/branding.go` — Properties resolution with tenant fallback and service default.
- `fedcm/revocation.go` — write/read/expire semantics via a fake cache.

### Integration tests (`apps/default/tests/fedcm/`)

Real Hydra + Postgres + cache via testcontainers. Scenarios:

- Cold start: no `idp_session` → `accounts_endpoint` empty → `/s/fedcm/login` → success → accounts_endpoint returns 1 → id_assertion succeeds → token-exchange yields valid access+refresh tokens.
- Multi-account: add second account via `/s/fedcm/login` → accounts_endpoint returns 2 → disconnect first → revocation honored on next id_assertion for that account.
- `Sec-Fetch-Dest` missing → all FedCM endpoints return 400.
- Origin mismatch → 403.
- Concurrent id_assertion for same `(profile_id, client_id)` → serialized; no duplicate tokens.
- Hydra rejects `prompt=none` (no session on Hydra's side) → handler returns `not_signed_in`.
- Token-exchange replay → second call returns 401.
- id_token claims verification: issued id_token validates against Hydra's JWKS and contains `tenant_id`, `partition_id`, `device_id`, `login_id`, `profile_id`, `roles: ["user"]`, `acr: "fedcm"`, correct `amr`.
- Logout removes the account from `idp_session` AND writes revocation.

### Regression (existing flows)

- Full existing login (contact+verify) works end-to-end with FedCM code present.
- Social Google via current OAuth redirect works end-to-end.
- `/s/consent` auto-accept unchanged.
- Service-account `client_credentials` + webhook enrichment unchanged.

### Coverage

New FedCM handlers and `fedcm/` package: ≥80% line coverage with integration tests driving the headless flow end-to-end.

## Rollout

No feature flag. Ship as a complete, polished feature.

1. Merge and deploy to staging.
2. Validate end-to-end with the stawi.dev widget pointed at staging IdP (widget already has FedCM client code; no widget changes required).
3. Smoke test all regression scenarios in staging.
4. Deploy to prod in a single release.
5. Monitor: FedCM endpoint latency p50/p99, error rates by response code, `idp_session` cookie set/decode failures, revocation-list hit rate, Hydra admin-API error rate.

Per-partition degradation is graceful: if a partition's Properties lacks FedCM branding keys, `client_metadata_endpoint` returns service-level defaults and the feature still works with generic branding.

## Open implementation details (planner resolves)

- Exact wire format for `idp_session` cookie serialization (JSON vs protobuf vs gob).
- Whether to consolidate the internal FedCM callback URI per-client or use a single global one with HMAC-bound state.
- Extraction of `buildTokenClaims` into a shared function without regressing the existing `/s/consent` handler.
- Specific `acr`/`amr` value mapping for each original `AuthMethod`.
- Cache-lock primitives available on the current `CACHE_URI` backend (NATS KV supports CAS; memory backend may need a mutex wrapper).

These are for the implementation plan, not the design.

## References

- [FedCM W3C spec (editor's draft)](https://fedidcg.github.io/FedCM/)
- Existing consent handler: `apps/default/service/handlers/login_step_4_consent.go`
- Existing Hydra client: `apps/default/service/hydra/callback_v25.go`
- Existing secure cookie setup: `apps/default/service/handlers/init_server.go:212–237`
- Existing login flow caching: `apps/default/service/handlers/login_step_1.go:43`
- Token enrichment webhook: `apps/default/service/handlers/webhook.go`
- `stawi.dev` widget FedCM consumer: `shared/auth-runtime/src/fedcm.ts`
