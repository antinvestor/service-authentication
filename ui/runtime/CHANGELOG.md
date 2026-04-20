# Changelog

All notable changes to `antinvestor_auth_runtime` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
