# Native credentials (Apple + Google) — backend operator guide

**Audience:** `service-authentication` backend operators and IdP admins
who need to make the Flutter `antinvestor_auth_runtime` v0.2+ native
sign-in path work end-to-end.

**Scope:** what the Ory Hydra (or equivalent) IdP must accept for the
Flutter runtime to exchange Apple / Google ID tokens into Antinvestor
sessions via RFC 8693.

**Status:** this is a **future enablement**. The Flutter runtime already
ships the client side in v0.2. The Go service may need additional
changes before it can honour the token-exchange grant end-to-end —
track progress under `TODO track in Jira/issue` (replace with the
actual issue ID once filed).

---

## 1. Prerequisites

- Ory Hydra ≥ **v2.2** (first release with token-exchange grant
  support), or an equivalent OAuth 2.0 authorization server.
- OAuth clients are already provisioned for the mobile apps
  (`antinvestor-mobile`, `antinvestor-chat-mobile`,
  `antinvestor-fintech-mobile`, …) with the `authorization_code` and
  `refresh_token` grants enabled.
- Ability to update client registrations via Hydra's admin API or
  equivalent tenancy config.
- A trusted-issuer registry the auth service consults during
  token-exchange: either a first-class Hydra feature or a thin shim in
  front of `/oauth2/token`.

## 2. Enable the token-exchange grant

The mobile OAuth client's `grant_types` must include:

```
urn:ietf:params:oauth:grant-type:token-exchange
```

Example (Hydra admin API):

```http
PATCH /admin/clients/{client_id}
Content-Type: application/json

[
  {
    "op": "add",
    "path": "/grant_types/-",
    "value": "urn:ietf:params:oauth:grant-type:token-exchange"
  }
]
```

The client also needs `offline_access` in its allowed scopes so the
exchanged session can be rotated via refresh tokens (already required
for the v0.1 authorization-code path).

## 3. Register Apple as a trusted subject issuer

| Field            | Value                                                       |
|------------------|-------------------------------------------------------------|
| JWKS URI         | `https://appleid.apple.com/auth/keys`                       |
| Issuer (`iss`)   | `https://appleid.apple.com`                                 |
| Audience (`aud`) | The app's **Services ID** (per-app, documented on registration). |
| Signing algs     | `RS256`, `ES256` (whatever Apple publishes in their JWKS).  |

**Services ID per app:** each Antinvestor Flutter app registers its own
Services ID at developer.apple.com. Maintain a mapping in your IdP
configuration such as:

```yaml
trusted_issuers:
  apple:
    issuer: https://appleid.apple.com
    jwks_uri: https://appleid.apple.com/auth/keys
    audiences:
      antinvestor-mobile: com.antinvestor.myapp.auth
      antinvestor-chat-mobile: com.antinvestor.chat.auth
      antinvestor-fintech-mobile: com.antinvestor.fintech.auth
```

At exchange time, validate `subject_token.aud` matches the expected
Services ID for the requesting `client_id`.

## 4. Register Google as a trusted subject issuer

| Field            | Value                                                       |
|------------------|-------------------------------------------------------------|
| JWKS URI         | `https://www.googleapis.com/oauth2/v3/certs`                |
| Issuer (`iss`)   | `https://accounts.google.com` (also accept `accounts.google.com` without scheme, per Google's own docs). |
| Audience (`aud`) | The **server client ID** registered in Google Cloud Console (OAuth client of type "Web application"). |
| Signing algs     | `RS256`.                                                    |

Keep the Google server client ID in the same per-app mapping as Apple:

```yaml
trusted_issuers:
  google:
    issuer: https://accounts.google.com
    jwks_uri: https://www.googleapis.com/oauth2/v3/certs
    audiences:
      antinvestor-mobile: 123.apps.googleusercontent.com
      antinvestor-chat-mobile: 456.apps.googleusercontent.com
```

## 5. Claim-mapping rules

When the exchange succeeds, the IdP mints a fresh Antinvestor session
backed by the subject token's claims:

| Source (subject token) | Target (Antinvestor user / ID token) |
|------------------------|--------------------------------------|
| `sub`                  | Primary user identity. Use a provider-scoped lookup (`apple:<sub>`, `google:<sub>`) to avoid collisions. If no user exists, create one; if one exists, attach the session. |
| `email` + `email_verified` | User profile `email` — only set when `email_verified == true`. |
| `name`, `given_name`, `family_name` | User profile display name. |
| `picture`              | User profile avatar URL (Google only; Apple does not return it). |

**Privacy note:** Apple's `email` claim may be a private-relay address
(`@privaterelay.appleid.com`). Treat these as first-class — users can
still receive email via the relay.

**Apple's name quirk:** Apple only returns `given_name` / `family_name`
on the very first sign-in, and only if the app requested the `name`
scope. Subsequent sign-ins return `sub` and `email` only. Persist the
name on first sight; do not overwrite with nulls on repeat exchanges.

## 6. Security hardening

- **Freshness:** reject `subject_token` whose `iat` is older than
  **5 minutes** (plus a small clock-skew tolerance, e.g. ±30 s). Apple
  and Google issue short-lived ID tokens by design.
- **Signature verification:** fetch the provider's JWKS, honour the
  `kid` header, cache JWKS responses for 15 minutes to bound the blast
  radius of a rolled key. Do **not** delegate signature validation to
  the Flutter runtime — the runtime trusts the OS platform APIs, not
  the IdP.
- **Audience pinning:** reject when `aud` does not match the expected
  Services ID / server client ID for the requesting OAuth
  `client_id`.
- **Issuer pinning:** reject when `iss` does not match the
  `subject_issuer` form parameter (defense in depth; the Flutter
  runtime already sends `subject_issuer` explicitly).
- **Nonce binding:** enforced by the **RP (Flutter runtime)** — the
  runtime generates a random nonce, binds it into the provider's
  authorize call, and rejects the ID token if the `nonce` claim does
  not match. The IdP cannot verify this because Apple's `nonce` claim
  is SHA-256 of the raw value and Google's is the raw value; the
  runtime handles both shapes. The IdP should therefore **not**
  re-verify the nonce — doing so would reject Apple tokens.
- **Replay protection:** the auth service should record the
  `subject_token` `jti` (or `iat+sub` when `jti` is absent, as with
  Apple tokens) in a short-lived cache (≥ token freshness window) and
  reject duplicates.

## 7. Rate limiting

Add a per-client, per-IP rate limit on the token-exchange endpoint.
Suggested budget: **30 requests per minute per client** — more than
enough for legitimate first-time sign-ins, tight enough to blunt
credential-stuffing attempts that bypass `/oauth2/auth`.

Log 429s and feed them into the existing auth-service dashboards
alongside `/oauth2/token` errors.

## 8. Testing checklist

Before cutting over a production tenancy:

- [ ] Client listed in `grant_types` includes
      `urn:ietf:params:oauth:grant-type:token-exchange`.
- [ ] Apple trusted issuer registered with correct Services ID per
      consuming app.
- [ ] Google trusted issuer registered with correct server client ID
      per consuming app.
- [ ] JWKS URIs reachable from the IdP and cached.
- [ ] A token-exchange with a **freshly-minted Apple ID token** (via
      the Flutter runtime's native path) completes with a 200 and
      returns an Antinvestor access + refresh token.
- [ ] Same for Google.
- [ ] A token-exchange with a **stale** (> 5 min) subject token is
      rejected with `400 invalid_grant`.
- [ ] A token-exchange with a forged / unsigned subject token is
      rejected.
- [ ] A token-exchange with a mismatched `aud` is rejected.
- [ ] The issued session is interchangeable with the existing
      authorization-code path — it refreshes, it logs out, it
      participates in reuse-detection.
- [ ] Rate limit returns 429 at the configured budget.

---

## References

- RFC 8693 — OAuth 2.0 Token Exchange: <https://www.rfc-editor.org/rfc/rfc8693>
- Apple — Sign in with Apple REST API: <https://developer.apple.com/documentation/sign_in_with_apple>
- Google — Authenticating with a backend server: <https://developers.google.com/identity/sign-in/android/backend-auth>
- Ory Hydra — Token Exchange (when released): <https://www.ory.sh/docs/hydra>
