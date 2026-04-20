# `antinvestor_auth_runtime` v0.2.0 — native credentials

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** add native silent-sign-in fast paths for Sign in with Apple (iOS/macOS) and Google (Android via Credential Manager + iOS via Google Sign-In SDK), mirroring the FedCM pattern from the JS runtime — as an additive layer on top of v0.1.0's OAuth2 popup flow. No breaking changes to the `AuthRuntime` public surface.

**Branch:** `feat/auth-runtime-v0.2-native-credentials` — stacked on `feat/auth-runtime-flutter` (v0.1.0 branch). Rebases onto main after v0.1.0 merges.

**Spec reference:** `docs/superpowers/specs/2026-04-19-auth-runtime-flutter-design.md` §14 lists these as future work; this plan delivers them.

## Architecture — additive

Current v0.1.0 sign-in flow:
```
unauthenticated → OAuth popup → code+verifier → /token (DPoP) → authenticated
```

v0.2.0 with native credentials:
```
unauthenticated
  ├─ proactive silent: try Apple (iOS/macOS) or Google CM (Android)
  │    ↳ got id_token → /token (token-exchange grant + DPoP) → authenticated (fast path)
  │    ↳ no session / user never signed in → fall through
  └─ on user click:
       ├─ interactive native attempt (button-mode)
       │    ↳ success → token-exchange → authenticated
       │    ↳ decline/cancel → fall through
       └─ OAuth2 popup (existing path) → authenticated
```

## Backend dependency (must be coordinated with service-authentication Go service)

The IdP (Ory Hydra) must accept:
- `grant_type: urn:ietf:params:oauth:grant-type:token-exchange`
- `subject_token_type: urn:ietf:params:oauth:token-type:id_token`
- `subject_issuer`: Apple (`https://appleid.apple.com`) or Google (`https://accounts.google.com`)

Issuer verification + JWKS validation + audience mapping happens server-side. Unsigned/wrong-issuer tokens MUST be rejected with 400 `invalid_grant`.

Coordinate with service-authentication Go team before enabling in production; for this plan's tests the mock IdP accepts any well-formed ID token with the correct `iss`.

## Library decisions

- **Apple:** `sign_in_with_apple: ^6.1.x` — official Flutter wrapper over `AuthenticationServices.framework`. Supports iOS 13+, macOS 10.15+, Web (via JS redirect — we do not use).
- **Google:** `google_sign_in: ^7.1.x` — v7 uses Android CredentialManager under the hood and will remain the official path. Works on Android 4.4+, iOS 12+. Do NOT use `credential_manager` package (3rd-party wrapper; unstable API).

Both libraries issue provider-side ID tokens. We exchange them via OIDC token-exchange grant.

## Forward-looking guard — Web support deferred

Sign-in-with-Apple has a Web flavor. `google_sign_in` also supports Web. We do NOT wire Web in this PR (spec defers Web to v1.1). When Web lands, it must use `dart:js_interop` + `package:web` — not `dart:js` / `dart:js_util` / `package:js` / `dart:html`.

## Task breakdown (10 commits)

### Task N.1 — Pubspec + error codes + NativeCredentialProvider abstraction

**Commit:** `feat(auth-runtime): NativeCredentialProvider abstraction + credential error codes`

- Add dependencies to `pubspec.yaml`: `sign_in_with_apple: ^6.1.2`, `google_sign_in: ^7.1.1`.
- Extend `AuthErrorCode` with: `nativeCredentialCancelled`, `nativeCredentialUnavailable`, `nativeCredentialIssuerMismatch`, `nativeCredentialExchangeFailed`.
  - Non-retryable: `nativeCredentialIssuerMismatch`.
- Create `lib/src/credentials/native_credential.dart`:
  ```dart
  enum NativeCredentialProviderKind { apple, google }

  class NativeCredentialResult {
    final NativeCredentialProviderKind provider;
    final String idToken;
    final String? authorizationCode;   // Apple gives this, Google doesn't
    final String? nonce;                // what we passed in; mirrored for verification
    final bool autoSelected;            // true if silent / hinted return
  }

  sealed class NativeCredentialOutcome {
    const factory NativeCredentialOutcome.ok(NativeCredentialResult result) = _Ok;
    const factory NativeCredentialOutcome.noSession() = _NoSession;
    const factory NativeCredentialOutcome.cancelled() = _Cancelled;
    const factory NativeCredentialOutcome.unavailable(String reason) = _Unavail;
    const factory NativeCredentialOutcome.error(AuthError error) = _Err;
  }

  abstract class NativeCredentialProvider {
    NativeCredentialProviderKind get kind;
    Future<bool> isAvailable();
    /// Attempts silent sign-in. Returns noSession() if no cached credential.
    Future<NativeCredentialOutcome> attemptSilent({required String nonce});
    /// Explicit user-gesture sign-in (button press).
    Future<NativeCredentialOutcome> attemptInteractive({required String nonce});
    /// Called during logout to remove the cached credential.
    Future<void> signOut();
  }
  ```
- `test/credentials/native_credential_test.dart` — type sanity + serialization if any.

### Task N.2 — `AppleCredentialProvider`

**Commit:** `feat(auth-runtime): AppleCredentialProvider via sign_in_with_apple`

- `lib/src/credentials/apple_credential_provider.dart`.
- `isAvailable()` via `SignInWithApple.isAvailable()` (guards non-iOS/macOS platforms).
- `attemptSilent`: Apple does not expose a silent API that matches Google's. Return `noSession()` — we only invoke Apple on explicit user click. Document this.
- `attemptInteractive({nonce})`:
  - Generate a SHA-256 hash of the passed-in nonce (Apple requires the hash, not the raw nonce).
  - Call `SignInWithApple.getAppleIDCredential(scopes: [email, fullName], nonce: sha256Hex(nonce), webAuthenticationOptions: null)`.
  - On success → `NativeCredentialResult(provider: apple, idToken: credential.identityToken, authorizationCode: credential.authorizationCode, nonce: nonce, autoSelected: false)`.
  - Map exceptions: user cancel → `cancelled()`; `SignInWithAppleAuthorizationException` non-cancel → `error(AuthError(nativeCredentialCancelled|unavailable))`.
- `signOut()`: Apple doesn't require client-side sign-out (IdP handles sessions). No-op.
- Test with `mocktail`-stubbed `SignInWithApple` surface via a thin `SignInWithAppleAdapter` seam.

### Task N.3 — `GoogleCredentialProvider`

**Commit:** `feat(auth-runtime): GoogleCredentialProvider via google_sign_in v7 (CredentialManager on Android)`

- `lib/src/credentials/google_credential_provider.dart`.
- Constructor takes `clientId` (the audience — Google client ID from Google Cloud Console).
- `isAvailable()` — returns true on Android and iOS, false elsewhere.
- `attemptSilent({nonce})`:
  - `GoogleSignIn.signInSilently()` — returns cached credential if user previously signed in.
  - If null: `noSession()`.
  - Otherwise extract `authentication.idToken`; wrap in `NativeCredentialResult(autoSelected: true)`.
- `attemptInteractive({nonce})`:
  - `GoogleSignIn.authenticate()` (v7 API; replaces `signIn()`).
  - Extract ID token; set `autoSelected: false`.
- `signOut()`: `GoogleSignIn.signOut()` (clears cached credential; the IdP session at Google is independent and requires Google's Account page to revoke).
- **Nonce quirk:** Google Sign-In for Flutter v7 accepts a `nonce` parameter on authentication calls; echo it into the returned ID token's `nonce` claim. If not supported in the concrete library version the subagent uses, document and move on — the server's token-exchange step still binds by `sub` + `iss`.
- Test with `mocktail` against a `GoogleSignInAdapter` seam.

### Task N.4 — Worker: `completeNativeCredential`

**Commit:** `feat(auth-runtime): TokenWorker.completeNativeCredential via OIDC token-exchange grant`

- Extend `TokenWorker` with:
  ```dart
  Future<void> completeNativeCredential({
    required NativeCredentialResult credential,
    required String expectedNonce,
  }) async { ... }
  ```
- Flow:
  1. Decode ID token locally (`decodeJwtPayload`).
  2. Assert `iss` is one of: `https://appleid.apple.com`, `https://accounts.google.com` — match by `credential.provider`.
  3. Assert `claims['nonce'] == expectedNonce` (or `sha256(expectedNonce)` for Apple). The check is unconditional when `expectedNonce` is passed — the runtime always passes one.
  4. Assert `aud == cfg.clientId` (for Google; Apple's `aud` is the app's services ID which may differ — document and accept).
  5. POST to `/token` with:
     ```
     grant_type=urn:ietf:params:oauth:grant-type:token-exchange
     client_id=<cfg.clientId>
     subject_token=<idToken>
     subject_token_type=urn:ietf:params:oauth:token-type:id_token
     subject_issuer=<matching iss>
     ```
     Plus `DPoP` header if DPoP mode.
  6. Parse token response; persist; emit `signInDone`.
  7. On any failure: emit `signInFail` with typed `AuthError`; do NOT silently swallow.

- Add `WorkerRequest.completeNativeCredential` message variant + corresponding event.
- Test using the existing `MockIdp` extended with a token-exchange handler that accepts any well-formed ID token with correct iss.

### Task N.5 — MockIdp extension

**Commit:** `test(auth-runtime): MockIdp accepts token-exchange grant`

- Extend `test/integration/mock_idp.dart` `/token` handler to accept `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with `subject_token_type=urn:ietf:params:oauth:token-type:id_token`.
- Parse the subject token, verify structure, echo `sub` back into the issued access token, issue a fresh refresh token, include DPoP support.
- Reject if `subject_issuer` is missing or not in the allowed list (configurable per test).

### Task N.6 — Runtime wiring

**Commit:** `feat(auth-runtime): runtime orchestrates native → OAuth2 sign-in waterfall`

- `AuthRuntimeImpl` accepts an optional list of `NativeCredentialProvider`s at construction:
  ```dart
  AuthRuntime createAuthRuntime(
    AuthConfig config, {
    bool useIsolate = false,
    List<NativeCredentialProvider> nativeProviders = const [],
  });
  ```
- On mount: if any provider `isAvailable()`, schedule a proactive silent attempt via `scheduleMicrotask` (not blocking) — roughly equivalent to JS `requestIdleCallback`.
- In `ensureAuthenticated()`:
  1. If state is already `authenticated`, return.
  2. Generate a fresh nonce (crypto random).
  3. Try each provider in declaration order via `attemptInteractive({nonce: nonce})`.
  4. On any provider's `ok` outcome: call `worker.completeNativeCredential(credential: ..., expectedNonce: nonce)`; if success, return.
  5. On all providers' `cancelled`/`noSession`/`error`: fall through to existing OAuth2 popup path.
- On `logout()`: call `signOut()` on every provider before the existing revocation/end-session flow.

- Add `onCredentialEvent(cb)` callback (analogous to JS `onFedcmEvent`) — fires `probe`, `silent-attempt`, `interactive-attempt`, `outcome`, `sign-out` events per provider.
- Expose `AuthRuntime.nativeProvidersAvailable()` helper returning the set of kinds currently `isAvailable()`.

### Task N.7 — Riverpod + factory integration

**Commit:** `feat(auth-runtime): factory surfaces nativeProviders parameter`

- Update `factory.dart` and `createAuthRuntime` signature + docs.
- Expose a small Riverpod helper: `authNativeProvidersProvider = Provider<List<NativeCredentialProvider>>((ref) => [])` — consumers override at app root.
- Update README with the new API.

### Task N.8 — Integration tests

**Commit:** `test(auth-runtime): native-credential waterfall end-to-end`

- `test/integration/native_credential_flow_test.dart`:
  - **silent-fast-path:** stubbed `FakeNativeCredentialProvider` returns `ok` on `attemptSilent`; MockIdp accepts token-exchange; runtime transitions `unauthenticated → authenticated` without any browser invocation.
  - **interactive-success:** silent returns `noSession`, interactive returns `ok`; flow completes.
  - **native-fall-through:** interactive returns `cancelled`; runtime falls through to OAuth2 popup (stubbed OAuthFlow).
  - **issuer-mismatch:** provider returns ID token with wrong `iss`; worker rejects with `nativeCredentialIssuerMismatch`; state stays `unauthenticated`; no token-exchange request reaches the server.
  - **logout-signs-out-providers:** authenticate via native, call `logout()`, assert `signOut()` was called on each provider.

### Task N.9 — Docs

**Commit:** `docs(auth-runtime): Apple and Google sign-in platform setup + backend requirements`

- `README.md` — new section "Native sign-in (Apple / Google)":
  - Platform setup: iOS entitlement (Sign In with Apple capability), Info.plist URL schemes for Google; Android SHA-256 fingerprint registration, `google-services.json` placement.
  - Consumer code example: construct providers, pass to `createAuthRuntime(nativeProviders: [...])`.
  - Failure-mode table: each `NativeCredentialProviderOutcome` → observable effect.
- New `docs/auth-runtime-native-credentials.md` — backend operator guide:
  - Ory Hydra configuration for token-exchange grant
  - Registering Apple + Google as trusted issuers (JWKS URIs)
  - Audience + claim mapping
  - Security considerations: nonce binding, iss pinning, token TTL

### Task N.10 — Version + changelog

**Commit:** `chore(auth-runtime): bump to v0.2.0`

- `pubspec.yaml`: `version: 0.2.0`.
- `CHANGELOG.md` — v0.2.0 section listing: native credential fast paths; Apple provider; Google provider; token-exchange grant support; new error codes; no breaking changes.
- Run `flutter test --coverage` and `flutter pub publish --dry-run`.
- Push branch.

## Test baseline

- v0.1.0 ends at 227 tests passing, 86.4% line coverage.
- v0.2.0 target: ≥ 240 tests; coverage ≥ 85%.

## Self-review checklist

1. No breaking change in `AuthRuntime` public surface (additive only).
2. `NativeCredentialProvider` is pluggable — consumers can ship their own for enterprise IdPs.
3. All four new `AuthErrorCode` values handled.
4. Nonce binding on both providers where the platform supports it; documented otherwise.
5. Issuer pinning enforced in the worker (trust boundary not delegated to the provider).
6. Providers called on logout.
7. No Web-specific code (deferred).
8. `flutter analyze` clean.
9. `flutter pub publish --dry-run` clean.
