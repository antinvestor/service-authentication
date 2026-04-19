# `antinvestor_auth_runtime` implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Each task is TDD: failing test first → run → implement → run → commit. Steps use `- [ ]` checkboxes.

**Goal:** ship `antinvestor_auth_runtime` v0.1.0 at `service-authentication/ui/runtime/` — Flutter package implementing the Stawi auth protocol (OAuth+PKCE+adaptive DPoP+rotation+reuse-detection) with Isolate-isolated tokens, `flutter_secure_storage`-backed persistence, `flutter_appauth` OAuth, Riverpod 3.3 providers, and a Material widget set.

**Spec:** `docs/superpowers/specs/2026-04-19-auth-runtime-flutter-design.md`.

**Branch:** `feat/auth-runtime-flutter` (already checked out).

**Package name:** `antinvestor_auth_runtime` — matches existing `antinvestor_ui_*` convention, name reflects its role as infrastructure rather than pure UI.

## Conventions

- TDD every task.
- `analysis_options.yaml`: `include: package:flutter_lints/flutter.yaml`.
- Imports: `package:antinvestor_auth_runtime/...`.
- Commit messages: Conventional Commits (`feat(auth-runtime): ...`).
- One commit per task.
- After each task, run `flutter test` from the package dir; must pass.

## Task groups

### F-A — Foundation (3 tasks)

#### F-A.1: Package skeleton

**Files:**
- Create: `service-authentication/ui/runtime/pubspec.yaml`, `README.md`, `CHANGELOG.md`, `LICENSE`, `analysis_options.yaml`
- Create: `service-authentication/ui/runtime/lib/antinvestor_auth_runtime.dart` (empty barrel)

Steps:

- [ ] Scaffold directory + `pubspec.yaml`:

```yaml
name: antinvestor_auth_runtime
description: >
  Auth runtime for Antinvestor Flutter apps. OAuth2 + PKCE, adaptive DPoP,
  rotating refresh tokens with reuse detection, Isolate-isolated tokens,
  hardware-backed storage, Riverpod providers, Material widgets.
version: 0.1.0
repository: https://github.com/antinvestor/service-authentication
homepage: https://github.com/antinvestor/service-authentication/tree/main/ui/runtime
issue_tracker: https://github.com/antinvestor/service-authentication/issues
topics:
  - flutter
  - authentication
  - oauth2
  - dpop
  - antinvestor

environment:
  sdk: ^3.11.0
  flutter: ">=3.24.0"

dependencies:
  flutter:
    sdk: flutter
  flutter_riverpod: ^3.3.1
  flutter_secure_storage: ^9.2.2
  flutter_appauth: ^8.0.0+1
  cryptography: ^2.7.0
  http: ^1.2.2
  crypto: ^3.0.6
  async: ^2.11.0
  equatable: ^2.0.7
  uuid: ^4.5.1
  meta: ^1.15.0
  collection: ^1.18.0

dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^6.0.0
  mocktail: ^1.0.4
  shelf: ^1.4.1
  shelf_router: ^1.1.4

flutter:
  uses-material-design: true
```

- [ ] `analysis_options.yaml`:
```yaml
include: package:flutter_lints/flutter.yaml
linter:
  rules:
    prefer_const_constructors: true
    prefer_final_locals: true
    avoid_print: true
    public_member_api_docs: false
```
- [ ] `LICENSE`: copy from a sibling package (MIT from `ui/auth/LICENSE`).
- [ ] `lib/antinvestor_auth_runtime.dart`: `library antinvestor_auth_runtime;` placeholder.
- [ ] Run `flutter pub get` from `service-authentication/ui/runtime/`.
- [ ] Commit: `chore(auth-runtime): scaffold antinvestor_auth_runtime package`

#### F-A.2: Models

**Files:**
- `lib/src/models/{auth_state,token_set,user_claims,security_event,api_response}.dart`
- `lib/src/errors/auth_error.dart`
- `test/models/auth_error_test.dart`

- [ ] Test first:

```dart
// test/models/auth_error_test.dart
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('AuthError preserves code/message/cause and computes retryable', () {
    final e = AuthError(AuthErrorCode.networkTimeout, 'boom', cause: StateError('x'));
    expect(e.code, AuthErrorCode.networkTimeout);
    expect(e.message, 'boom');
    expect(e.cause, isA<StateError>());
    expect(e.retryable, isTrue);
  });
  test('non-retryable codes flagged', () {
    for (final c in const [
      AuthErrorCode.invalidConfig,
      AuthErrorCode.refreshReuseDetected,
      AuthErrorCode.cryptoUnsupported,
      AuthErrorCode.deepLinkMismatch,
      AuthErrorCode.securityWipe,
    ]) {
      expect(AuthError(c, 'm').retryable, isFalse, reason: c.name);
    }
  });
}
```

- [ ] Implement `AuthError` + `AuthErrorCode` per spec §4. Mark six non-retryable codes in a static set.
- [ ] Implement `AuthState`, `TokenSet`, `UserClaims`, `SecurityEvent` (sealed class with 4 factory constructors), `ApiResponse`.
- [ ] Run `flutter test test/models/` — PASS.
- [ ] Commit: `feat(auth-runtime): models and error taxonomy`

#### F-A.3: AuthConfig + resolveConfig

**Files:**
- `lib/src/config/auth_config.dart`, `lib/src/config/resolve_config.dart`
- `test/config/resolve_config_test.dart`

- [ ] Test:

```dart
import 'package:antinvestor_auth_runtime/src/config/auth_config.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('throws invalidConfig when clientId is empty', () {
    expect(
      () => resolveConfig(const AuthConfig(clientId: '', idpBaseUrl: 'https://i', apiBaseUrl: 'https://a', redirectScheme: 'x')),
      throwsA(isA<AuthError>().having((e) => e.code, 'code', AuthErrorCode.invalidConfig)),
    );
  });
  test('strips trailing slashes and namespaces', () {
    final cfg = resolveConfig(const AuthConfig(
      clientId: 'c', idpBaseUrl: 'https://i/', apiBaseUrl: 'https://a/', redirectScheme: 'com.example.app',
    ));
    expect(cfg.idpBaseUrl, 'https://i');
    expect(cfg.apiBaseUrl, 'https://a');
    expect(cfg.namespace, 'c::https://i');
    expect(cfg.scopes, contains('offline_access'));
  });
  test('honors timeout overrides partially', () {
    final cfg = resolveConfig(AuthConfig(
      clientId: 'c', idpBaseUrl: 'https://i', apiBaseUrl: 'https://a', redirectScheme: 'x',
      apiTimeout: const Duration(seconds: 5),
    ));
    expect(cfg.apiTimeout, const Duration(seconds: 5));
    expect(cfg.tokenTimeout, const Duration(seconds: 10));
  });
}
```

- [ ] Implement `AuthConfig` (immutable, `Equatable`), `ResolvedConfig` (strips trailing `/`, adds defaults, computes `namespace`).
- [ ] Run tests — PASS.
- [ ] Commit: `feat(auth-runtime): AuthConfig + resolveConfig with namespace and defaults`

---

### F-B — Protocol (6 tasks)

#### F-B.1: PKCE

**Files:** `lib/src/protocol/pkce.dart`, `test/protocol/pkce_test.dart`

- [ ] Test:

```dart
import 'package:antinvestor_auth_runtime/src/protocol/pkce.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('verifier is 43–128 url-safe chars', () async {
    final pair = await generatePkcePair();
    expect(RegExp(r'^[A-Za-z0-9_-]{43,128}$').hasMatch(pair.verifier), true);
    expect(RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(pair.challenge), true);
  });
  test('challenge is deterministic from verifier', () async {
    final a = await generatePkcePair();
    expect(await computeChallenge(a.verifier), a.challenge);
  });
}
```

- [ ] Implement with `crypto` (SHA-256) + `Random.secure()` (not `dart:math` `Random`), base64url-no-pad.
- [ ] Commit: `feat(auth-runtime): PKCE S256 verifier/challenge generation`

#### F-B.2: JWT payload decoder with padding fix

**Files:** `lib/src/protocol/jwt.dart`, `test/protocol/jwt_test.dart`

- [ ] Test: encode payloads of various lengths (1–20 chars), assert decode round-trips. Test `extractRolesFromToken` handles direct `roles` array and `realm_access.roles`.
- [ ] Implement `decodeJwtPayload(String token) → Map<String, dynamic>` with base64url padding (`%4` → add `=`s). Implement `extractRolesFromToken`.
- [ ] Commit: `feat(auth-runtime): JWT payload decode with padded base64url; role extraction`

#### F-B.3: OIDC Discovery with timeout + cache

**Files:** `lib/src/protocol/discovery.dart`, `test/protocol/discovery_test.dart`

Test with `MockClient` from `package:http/testing.dart`. Cover: 200 JSON → parsed; 404 → `AuthError(discoveryFailed)`; non-JSON → `AuthError(discoveryFailed)`; cache persists across calls; failures not cached; DPoP detected from `dpop_signing_alg_values_supported`.

- [ ] Implement `Discovery` class with `getDiscovery(String idpBaseUrl, Duration timeout, {http.Client? client})`. Module-level `Map<String, OidcDiscovery>` cache + in-flight dedup via `Completer`.
- [ ] Expose `supportsDpop(OidcDiscovery)`.
- [ ] Commit: `feat(auth-runtime): OIDC discovery with timeout, cache, DPoP capability detection`

#### F-B.4: DPoP proof builder + nonce cache + clock offset

**Files:** `lib/src/protocol/dpop.dart`, `test/protocol/dpop_test.dart`

Dart `cryptography` package provides ECDSA P-256 signing. Key generated via `Ecdsa.p256(Sha256())`.

- [ ] Test: generate key pair; build proof for `POST https://i/token`; decode resulting JWT; assert header = `{typ:"dpop+jwt", alg:"ES256", jwk:{kty:"EC", crv:"P-256", x:..., y:...}}`; payload = `{htm, htu, iat, jti}` with `iat` in seconds; optional `ath` when `accessToken` given = sha256(accessToken) base64url; optional `nonce` when set via `rememberNonce(headers)`.
- [ ] Implement:
```dart
class DpopContext {
  final SimpleKeyPair privateKey;
  final JsonWebKey publicJwk;
  int clockOffsetMs = 0;
  final Map<String, String> nonceByOrigin = {};
}

Future<DpopContext> makeDpopContext(SimpleKeyPair kp);
Future<String> buildProof(DpopContext ctx, {required String htm, required String htu, String? accessToken});
void rememberNonce(DpopContext ctx, String audienceUrl, Map<String, String> headers);
void rememberClockOffset(DpopContext ctx, Map<String, String> headers);
```
- [ ] Commit: `feat(auth-runtime): DPoP proof builder with nonce + clock offset`

#### F-B.5: Token exchange + refresh

**Files:** `lib/src/protocol/token_exchange.dart`, `test/protocol/token_exchange_test.dart`

- [ ] Test with `MockClient`: successful auth-code exchange; DPoP-nonce challenge retry; clock-skew retry on `invalid_dpop_proof`; refresh rotates; refresh reuse-detection returns `RefreshOutcome.reuseDetected`.
- [ ] Implement:
```dart
class TokenExchange {
  TokenExchange({http.Client? client, required Duration timeout});
  Future<TokenSet> exchangeCode(ResolvedConfig cfg, DpopContext ctx, {required String code, required String verifier});
  Future<RefreshOutcome> refresh(ResolvedConfig cfg, DpopContext ctx, String refreshToken);
}

sealed class RefreshOutcome {
  const factory RefreshOutcome.rotated(TokenSet tokens) = _Rotated;
  const factory RefreshOutcome.reuseDetected() = _Reuse;
  const factory RefreshOutcome.networkError(AuthError error) = _NetErr;
}
```
- [ ] Commit: `feat(auth-runtime): token exchange and refresh with DPoP/nonce/clock-skew/reuse-detection`

#### F-B.6: API proxy (DPoP + 401-refresh retry)

**Files:** `lib/src/protocol/api_proxy.dart`, `test/protocol/api_proxy_test.dart`

Matching the JS `api-proxy.ts` behavior.

- [ ] Test: attaches `Authorization: DPoP <token>` + `DPoP: <proof>` in DPoP mode; attaches `Authorization: Bearer <token>` otherwise; 401 triggers forced refresh + retry once; 204 returns empty body; typed error mapping (401→apiUnauthorized, 403→apiForbidden, 404→apiNotFound, 5xx→apiServerError).
- [ ] Implement `ApiProxy.fetch(...)` and `ApiProxy.upload(...)` taking a `TokenProvider` callback interface (matches JS design).
- [ ] Commit: `feat(auth-runtime): API proxy with DPoP, nonce retry, and 401-refresh retry`

---

### F-C — Crypto & Storage (2 tasks)

#### F-C.1: KeyManager

**Files:** `lib/src/crypto/key_manager.dart`, `lib/src/crypto/dart_crypto_key_manager.dart`, `test/crypto/key_manager_test.dart`

- [ ] Test: generateDpopKey returns valid P-256 key pair; exported public JWK has kty=EC, crv=P-256, x, y; generateWrapKey returns 32-byte AES key; encrypt/decrypt round-trips; different encrypt calls produce different ciphertexts (fresh IV).
- [ ] Implement `KeyManager` interface + `DartCryptographyKeyManager` using `package:cryptography`:
  - `Ecdsa.p256(Sha256())` for DPoP
  - `AesGcm.with256bits()` for wrap
  - `exportJwk(publicKey)` returning Map<String, dynamic>
- [ ] Commit: `feat(auth-runtime): KeyManager with package:cryptography backend`

#### F-C.2: TokenStore

**Files:** `lib/src/storage/token_store.dart`, `lib/src/storage/secure_token_store.dart`, `test/storage/secure_token_store_test.dart`

Use `flutter_secure_storage`'s `FakeSecureStorage` for tests (official pattern).

- [ ] Test: round-trip save/load with namespace isolation; clear removes; corrupt JSON treated as null.
- [ ] Implement `TokenStore` interface + `SecureTokenStore`. Values JSON-encoded with base64 for bytes. Keys: `"{namespace}::session"`.
- [ ] Commit: `feat(auth-runtime): TokenStore with flutter_secure_storage backend`

---

### F-D — State machine & Coordination (2 tasks)

#### F-D.1: State machine

**Files:** `lib/src/runtime/state_machine.dart`, `test/runtime/state_machine_test.dart`

- [ ] Test all transitions from spec §14 (JS `auth-protocol-design` §14).
- [ ] Implement pure reducer `AuthState reduce(AuthState s, _Input i)`.
- [ ] Commit: `feat(auth-runtime): pure state-machine reducer`

#### F-D.2: Refresh lock

**Files:** `lib/src/runtime/refresh_lock.dart`, `test/runtime/refresh_lock_test.dart`

- [ ] Test: two concurrent calls to `withLock(fn)` serialize; unhandled throw doesn't permanently hold the lock.
- [ ] Implement via `package:async` `Lock`.
- [ ] Commit: `feat(auth-runtime): refresh lock wrapper`

---

### F-E — Worker / Isolate (2 tasks)

#### F-E.1: Message types

**Files:** `lib/src/worker/messages.dart`, `test/worker/messages_test.dart`

- [ ] Define `WorkerRequest` + `WorkerEvent` sealed classes — matches JS `rpc.ts` shape (init, prepareAuth, completeAuth, fetch, upload, getRoles, getClaims, logout, destroy) and events (ready, state, response, error, securityEvent).
- [ ] Serialization test (toJson/fromJson round-trip).
- [ ] Commit: `feat(auth-runtime): worker message types`

#### F-E.2: TokenWorker core

**Files:** `lib/src/worker/token_worker.dart`, `test/worker/token_worker_test.dart`

The `TokenWorker` is a pure class (not yet an Isolate) that holds tokens + keys + performs RPC. We wire it to an actual Isolate in F-G.

- [ ] Test: fresh worker starts unauthenticated (no session); `completeAuth(code, verifier, nonce)` exchanges tokens + persists session; `refresh()` rotates; reuse detection wipes; `fetch(path)` adds auth headers; `logout()` clears + broadcasts.
- [ ] Implement `TokenWorker` taking injected `KeyManager`, `TokenStore`, `Discovery`, `TokenExchange`, `ApiProxy`, `Clock`. Use `_Input` + `reduce(...)` internally. Emit events to an injected sink.
- [ ] Commit: `feat(auth-runtime): TokenWorker core (init, auth, refresh, fetch, logout, wipe)`

---

### F-F — OAuth Flow (1 task)

#### F-F.1: OAuth via flutter_appauth

**Files:** `lib/src/oauth/oauth_flow.dart`, `test/oauth/oauth_flow_test.dart`

- [ ] Test with mocked `FlutterAppAuth`: success path returns `AuthorizationResponse` with code + verifier; user cancel maps to `oauthUserCanceled`; unavailable browser maps to `oauthBrowserUnavailable`.
- [ ] Implement `OAuthFlow.authorize(cfg, nonce) → Future<{code, verifier, state}>` calling `FlutterAppAuth.authorize` (code flow w/ PKCE handled by the plugin).
- [ ] Commit: `feat(auth-runtime): OAuth flow via flutter_appauth`

---

### F-G — Runtime proxy (2 tasks)

#### F-G.1: AuthRuntime interface + in-thread impl

**Files:** `lib/src/auth_runtime.dart`, `lib/src/auth_runtime_impl.dart`, `test/auth_runtime_test.dart`

v0.1.0 uses in-thread (same-Isolate) impl. Public API design keeps migration to a dedicated Isolate invisible to consumers.

- [ ] Test: createAuthRuntime returns runtime; starts in initializing → unauthenticated (no session); `ensureAuthenticated` calls OAuthFlow and completes via TokenWorker; `fetch` returns ApiResponse; `logout` clears; `dispose` cleans up streams.
- [ ] Implement `AuthRuntimeImpl` wiring TokenWorker + OAuthFlow + KeyManager + TokenStore. Expose streams.
- [ ] Commit: `feat(auth-runtime): AuthRuntime proxy with in-thread worker (v0.1 baseline)`

#### F-G.2: Isolate-backed variant (scaffolding)

**Files:** `lib/src/worker/token_isolate.dart` + glue in `AuthRuntimeImpl`

v0.1.0 does NOT enable the Isolate by default (to keep surface small), but the code is present. A `createAuthRuntime(config, useIsolate: true)` flag spawns the Isolate.

- [ ] Test: with `useIsolate: true`, a sign-in flow completes end-to-end using a real `Isolate.spawn`. The main thread never receives a raw token (verified by intercepting messages).
- [ ] Implement `TokenIsolateHandle` that wraps `Isolate.spawn` + `ReceivePort`. Messages serialized via `messages.dart`.
- [ ] Commit: `feat(auth-runtime): optional Isolate-backed worker for defense-in-depth token isolation`

---

### F-H — Riverpod bindings (1 task)

**Files:** `lib/src/providers/auth_providers.dart`, `lib/src/providers/auth_runtime_scope.dart`, `test/providers/auth_providers_test.dart`

- [ ] Test: overriding `authRuntimeProvider` works; `authStateProvider` streams state transitions; `isAuthenticatedProvider` reflects state; `userClaimsProvider` returns empty when unauthenticated.
- [ ] Implement per spec §4.2. Also export `AuthRuntimeScope` InheritedWidget for apps not using Riverpod at the root.
- [ ] Commit: `feat(auth-runtime): Riverpod providers and AuthRuntimeScope`

---

### F-I — Widgets (3 tasks)

#### F-I.1: AuthStateBuilder + AuthGate

**Files:** `lib/src/widgets/auth_state_builder.dart`, `lib/src/widgets/auth_gate.dart`, tests.

- [ ] Widget test: `AuthGate` shows `loadingBuilder` in initializing; `unauthenticatedBuilder` in unauthenticated (defaults to `SignInButton` if null); child in authenticated; `errorBuilder` in error.
- [ ] Implement both.
- [ ] Commit: `feat(auth-runtime): AuthStateBuilder + AuthGate widgets`

#### F-I.2: SignInButton / SignOutButton / ProfileAvatar

**Files:** widgets + tests.

- [ ] Widget tests for each.
- [ ] Implement:
  - `SignInButton` — ElevatedButton that calls `runtime.ensureAuthenticated()`, disables while pending, shows error via `onError` callback.
  - `SignOutButton` — ElevatedButton that calls `runtime.logout()`, fires `onSignedOut`.
  - `ProfileAvatar` — CircleAvatar loading `claims['picture']` if present, else initials from `claims['name']` or `claims['email']`.
- [ ] Commit: `feat(auth-runtime): SignInButton, SignOutButton, ProfileAvatar widgets`

#### F-I.3: AuthEventListener

**Files:** `lib/src/widgets/auth_event_listener.dart`, test.

- [ ] Test: shows SnackBar on each SecurityEvent via Messenger; configurable builder for custom UI.
- [ ] Implement.
- [ ] Commit: `feat(auth-runtime): AuthEventListener for security event UX integration`

---

### F-J — Integration tests + mock IdP (1 task)

**Files:** `test/integration/mock_idp.dart`, `test/integration/sign_in_flow_test.dart`, `test/integration/refresh_flow_test.dart`, `test/integration/logout_flow_test.dart`, `test/integration/reuse_detection_test.dart`, `test/integration/dpop_nonce_test.dart`

- [ ] Implement `MockIdp` with `package:shelf` + `shelf_router`:
  - `GET /.well-known/openid-configuration` → discovery doc advertising `authorization_endpoint`, `token_endpoint`, `end_session_endpoint`, `revocation_endpoint`, `dpop_signing_alg_values_supported: ["ES256"]`.
  - `POST /token` → accepts `authorization_code`, `refresh_token` grants. Honors DPoP. Rotates refresh on every call. Tracks used refresh tokens per family; reuse returns `{error: "invalid_grant", error_description: "refresh token reuse detected"}`.
  - `POST /revocation` → 204.
  - `POST /end_session` → 204.
- [ ] Integration tests using a mock `OAuthFlow` that short-circuits the browser round-trip and returns a pre-crafted code. The token exchange then hits the real MockIdp.
- [ ] Coverage: sign-in, refresh, reuse-detection wipe + security event emitted, logout, DPoP-nonce challenge (MockIdp returns 401 with `DPoP-Nonce` on first call then 200), clock-skew recovery.
- [ ] Commit: `test(auth-runtime): shelf-based mock IdP and end-to-end integration tests`

---

### F-K — Documentation (2 tasks)

#### F-K.1: README

**Files:** `service-authentication/ui/runtime/README.md`

- [ ] Comprehensive README covering: install, platform setup (iOS `Info.plist`, Android `AndroidManifest.xml`, macOS entitlements), quick start (Riverpod + widgets), full API reference, theming, security posture, migration from ad-hoc token management, troubleshooting.
- [ ] Commit: `docs(auth-runtime): comprehensive README`

#### F-K.2: Integration guide

**Files:** `docs/auth-runtime-integration.md` (at repo root docs/)

- [ ] Step-by-step guide for adding the package to service-chat and service-fintech. Include exact AuthConfig, deep-link scheme setup, providers override at app root, example of `AuthGate` wrapping the router.
- [ ] Commit: `docs: auth-runtime integration guide for consuming apps`

---

### F-L — Release (1 task)

#### F-L.1: Final validation + tag

**Files:** `CHANGELOG.md`, `pubspec.yaml`

- [ ] Run full test suite: `flutter test`; ensure ≥ 85% coverage via `flutter test --coverage`.
- [ ] Run `flutter pub publish --dry-run` to validate publishable state.
- [ ] Update `CHANGELOG.md` with v0.1.0 notes.
- [ ] Commit: `chore(auth-runtime): prepare v0.1.0 release`.
- [ ] Push branch; open PR; do not publish to pub.dev yet (leave for separate release PR with consumer-integration test).

---

## Self-review checklist

1. Spec §4 API is fully implemented (`ensureAuthenticated`, `fetch`, `upload`, `getClaims`, `getRoles`, `logout`, `authStateStream`, `securityEventStream`, `state`, `prefetchDiscovery`, `dispose`, `version`).
2. Wire protocol is byte-compatible with `@stawi/auth-runtime` (same discovery, same PKCE, same DPoP proof shape, same grant types, same reuse-detection contract, same 401-refresh retry).
3. No `dart:js`, `dart:js_util`, `package:js`, `dart:html` imports — those are deprecated. Web target deferred to v1.1 using `dart:js_interop` + `package:web`.
4. Widget tests render without real network.
5. Integration tests spin up an isolated mock IdP with each test.
6. Error taxonomy matches JS + mobile-specifics.
7. State machine transitions match spec §14.
8. Coverage ≥ 85%.
