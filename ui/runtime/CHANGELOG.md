# Changelog

All notable changes to `antinvestor_auth_runtime` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.1 — 2026-04-20

### Added
- `runtime.fetch` / `runtime.upload` accept fully-qualified `https://...` URLs; when the path starts with `http://` or `https://`, the runtime uses it directly and skips `apiBaseUrl` prepending. Unblocks consumers that talk to multiple service domains with a single OAuth client.

## 0.3.0 — 2026-04-20

### Added
- `AuthConfig.audiences` — optional resource audience hints passed to authorize + token-exchange. Addresses service-thesa's 9-element audiences array use case.
- `AuthConfig.redirectUri` — explicit override of the OAuth redirect URI; takes precedence over `redirectScheme`. Supports desktop loopback flows (`http://localhost:5173/auth`).
- `UserClaims.contactId`, `tenantId`, `partitionId` typed getters for Antinvestor-specific claims; plus `customClaims` escape hatch for bespoke per-app claims.
- `AuthRuntime.getUserClaims()` — typed wrapper around `getClaims()`.
- `AuthRuntime.isAuthenticated` — synchronous getter for background-task pre-check.

### Changed
- None. Purely additive; existing v0.2 callers are unaffected.

## 0.2.0 — 2026-04-20

### Added
- Native sign-in providers: `AppleCredentialProvider` (Sign in with Apple via `sign_in_with_apple`) and `GoogleCredentialProvider` (via `google_sign_in` v7; Android backed by CredentialManager).
- `NativeCredentialProvider` abstraction — consumers can ship custom providers for enterprise IdPs.
- OIDC token-exchange grant support (RFC 8693) in `TokenExchange` and `TokenWorker.completeNativeCredential`.
- Native → OAuth2 sign-in waterfall: proactive silent attempt on mount; interactive attempt on sign-in click; OAuth2 fallback when all native providers decline.
- `AuthRuntime.availableNativeProviders()` helper + `credentialEventStream` telemetry.
- `authNativeProvidersProvider` Riverpod override hook.
- Four new `AuthErrorCode` values: `nativeCredentialCancelled`, `nativeCredentialUnavailable`, `nativeCredentialIssuerMismatch`, `nativeCredentialExchangeFailed`.
- IdP operator guide: `docs/auth-runtime-native-credentials.md`.

### Changed
- `createAuthRuntime` now accepts an optional `nativeProviders` parameter. Existing callers are unaffected.
- `logout()` calls `signOut()` on each configured native provider before the server revocation/end-session path.

### Security
- Provider-issued ID tokens are validated for issuer match before exchange (trust boundary not delegated to the provider).
- Per-attempt nonce binding with Apple's SHA-256 hashing accommodated.

## 0.1.0 — 2026-04-19

Initial public release.

### Added
- `AuthRuntime` public contract and `createAuthRuntime` factory.
- OAuth2 + PKCE sign-in via `flutter_appauth`, wrapped in a testable
  `OAuthFlow` abstraction.
- OIDC discovery with in-memory caching, timeout, and in-flight
  deduplication.
- Adaptive DPoP: ES256 proofs, `DPoP-Nonce` challenge retry, clock-skew
  compensation via `Date` header.
- Token exchange with rotating refresh tokens + reuse detection.
- Authenticated `fetch` + `upload` with automatic 401-refresh retry.
- `TokenWorker` with secure-storage-backed session persistence:
  root key → wrap key → DPoP private key + refresh token encryption
  chain over AES-GCM-256.
- Optional Isolate-backed worker (`createAuthRuntime(useIsolate: true)`)
  — scaffolding in v0.1; data-plane methods land in a follow-up.
- Riverpod providers: `authRuntimeProvider`, `authStateProvider`,
  `isAuthenticatedProvider`, `userClaimsProvider`, `rolesProvider`,
  `securityEventsProvider`.
- `AuthRuntimeScope` for non-Riverpod consumers.
- Material widgets: `AuthGate`, `AuthStateBuilder`, `AuthEventListener`,
  `SignInButton`, `SignOutButton`, `ProfileAvatar`.
- `SecurityEvent` hierarchy surfaces refresh reuse, storage corruption,
  and related signals.
- End-to-end integration tests against a `shelf`-backed mock IdP.
- Comprehensive README and integration guide for consuming apps.
