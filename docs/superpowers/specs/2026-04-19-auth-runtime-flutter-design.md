# `antinvestor_auth_runtime` — Flutter auth runtime design

Status: draft
Date: 2026-04-19
Package: `antinvestor_auth_runtime` at `service-authentication/ui/runtime/`
Companion: `@stawi/auth-runtime` (JS, shipped) — shares the wire protocol specified in `stawi/widgets.js/docs/superpowers/specs/2026-04-19-auth-protocol-design.md`.

## 1. Purpose

Ship a Flutter package that gives Antinvestor services (service-chat, service-fintech, future services) a single drop-in dependency that handles OAuth2 + PKCE authentication, token lifecycle, DPoP (when IdP supports it), rotating refresh tokens with reuse detection, and a small widget toolkit (`AuthGate`, `SignInButton`, `SignOutButton`, `ProfileAvatar`) built on Riverpod 3.3.

The package implements the same **wire protocol** as `@stawi/auth-runtime`, so backend changes (e.g., DPoP rollout, reuse-detection) affect both JS and Flutter clients uniformly.

## 2. Non-goals (v1.0)

- **Web target.** Deferred to v1.1. When added, use `dart:js_interop` + `package:web` **only** — never `dart:js`, `dart:js_util`, `package:js`, or `dart:html` (all officially deprecated as of Dart 3.5).
- **Hardware-backed keys.** v1.0 uses `flutter_secure_storage` for refresh-token-at-rest and holds DPoP signing keys in Isolate RAM. v1.1 moves signing into Secure Enclave (iOS) / StrongBox (Android) via platform channels.
- **Biometric gating.** `local_auth` integration and per-refresh biometric prompt land in v1.1.
- **Passkeys / Sign in with Apple / Google Credential Manager.** v1.1+.
- **Attestation** (Play Integrity / App Attest). v1.2.

## 3. Supported platforms (v1.0)

| Platform | Minimum version | OAuth surface | Storage |
|---|---|---|---|
| iOS | 13.0 | ASWebAuthenticationSession via `flutter_appauth` | Keychain (`flutter_secure_storage`) |
| Android | 8.0 (API 26) | Chrome Custom Tabs via `flutter_appauth` | EncryptedSharedPreferences (`flutter_secure_storage`) |
| macOS | 11.0 | ASWebAuthenticationSession via `flutter_appauth` | Keychain |
| Windows | 10 | System browser + loopback | DPAPI |
| Linux | modern distros | System browser + loopback | libsecret |

Web: v1.1 via `dart:js_interop` wrapping the JS runtime.

## 4. Public API

```dart
/// Configuration for the auth runtime. Immutable.
class AuthConfig {
  final String clientId;
  final String idpBaseUrl;
  final String apiBaseUrl;
  final String redirectScheme;  // e.g. "com.antinvestor.chat"
  final List<String> scopes;    // default: openid profile email offline_access
  final String? installationId;
  final Duration discoveryTimeout;
  final Duration tokenTimeout;
  final Duration apiTimeout;
  final Duration uploadTimeout;
  const AuthConfig({...});
}

/// Runtime state.
enum AuthState { initializing, authenticated, unauthenticated, refreshing, error }

/// Flat error taxonomy — matches JS AuthErrorCode plus mobile-specifics.
enum AuthErrorCode {
  invalidConfig,
  discoveryFailed, networkTimeout, networkError, offline,
  oauthFailed, oauthUserCanceled, oauthBrowserUnavailable,
  tokenExchangeFailed, tokenRefreshFailed, tokenExpired,
  dpopNonceRequired, dpopInvalidProof,
  refreshReuseDetected,
  storageCorruption, storageUnavailable,
  cryptoUnsupported,
  loggedOutElsewhere, securityWipe,
  apiUnauthorized, apiForbidden, apiNotFound, apiValidation, apiServerError,
  deepLinkMismatch, biometricRequired, biometricUnavailable,
}

/// Non-retryable codes are `invalidConfig`, `refreshReuseDetected`,
/// `cryptoUnsupported`, `deepLinkMismatch`, `securityWipe`.
class AuthError extends Error {
  final AuthErrorCode code;
  final String message;
  final Object? cause;
  final String? traceId;
  bool get retryable;
}

/// Security signal callback.
sealed class SecurityEvent {
  final DateTime at;
  const factory SecurityEvent.refreshReuseDetected(DateTime at);
  const factory SecurityEvent.storageCorruption(DateTime at);
  const factory SecurityEvent.bindingInvalidated(DateTime at);
  const factory SecurityEvent.loggedOutElsewhere(DateTime at);
}

/// API response — opaque body (Uint8List) + status + headers.
class ApiResponse {
  final int status;
  final Map<String, String> headers;
  final Uint8List body;
}

abstract class AuthRuntime {
  /// Begins or resumes an authenticated session. On fresh install this
  /// opens the OAuth flow; on subsequent launches uses stored refresh token.
  Future<void> ensureAuthenticated();

  /// Perform an authenticated HTTP call. Tokens never cross back to the caller.
  Future<ApiResponse> fetch(
    String path, {
    String method = 'GET',
    Map<String, String>? headers,
    Object? body, // String | List<int> | Stream<List<int>>
    Duration? timeout,
  });

  /// Multipart upload of a file.
  Future<ApiResponse> upload(
    String path, {
    required String fieldName,
    required String filename,
    required String contentType,
    required Stream<List<int>> bytes,
    required int length,
    Duration? timeout,
  });

  /// Claims decoded from the current access token. Caller never gets the token itself.
  Future<Map<String, dynamic>> getClaims();

  /// Roles from claims (Hydra emits `realm_access.roles` or a top-level `roles` array).
  Future<List<String>> getRoles();

  /// Clears local state + best-effort server logout (end_session + revocation).
  Future<void> logout();

  /// Stream of auth state transitions. Never errors; uses [error] state for fatal init.
  Stream<AuthState> get authStateStream;

  /// Stream of security events (wipe, reuse detection). Caller should surface prominently.
  Stream<SecurityEvent> get securityEventStream;

  /// Synchronous state snapshot.
  AuthState get state;

  /// Warm the OIDC discovery cache. Call on app start for faster first sign-in.
  Future<void> prefetchDiscovery();

  /// Tear down isolates, streams, secure storage handles.
  Future<void> dispose();

  /// Injected at build time.
  String get version;
}

/// Factory. Never returns a singleton — one runtime per AuthConfig tuple.
AuthRuntime createAuthRuntime(AuthConfig config);
```

### 4.1 Widget surface

```dart
/// InheritedWidget that exposes the runtime to descendants.
class AuthRuntimeScope extends InheritedWidget {
  final AuthRuntime runtime;
  static AuthRuntime of(BuildContext context) => ...;
}

/// Rebuilds child when AuthState changes.
class AuthStateBuilder extends ConsumerWidget {
  final Widget Function(BuildContext, AuthState) builder;
}

/// Renders child only when authenticated. Otherwise renders sign-in affordance.
class AuthGate extends ConsumerWidget {
  final Widget child;
  final WidgetBuilder? unauthenticatedBuilder;
  final WidgetBuilder? loadingBuilder;
  final Widget Function(BuildContext, AuthError)? errorBuilder;
}

/// Material button that triggers ensureAuthenticated().
class SignInButton extends ConsumerStatefulWidget {
  final String? label;
  final ButtonStyle? style;
  final VoidCallback? onAuthenticated;
  final void Function(AuthError)? onError;
}

class SignOutButton extends ConsumerStatefulWidget {
  final String? label;
  final VoidCallback? onSignedOut;
}

/// Renders the user's avatar (profile picture if claim `picture` exists, else initials).
class ProfileAvatar extends ConsumerWidget {
  final double radius;
}

/// Listens for SecurityEvents and shows SnackBar/Dialog.
class AuthEventListener extends ConsumerWidget { ... }
```

### 4.2 Riverpod providers

```dart
final authRuntimeProvider = Provider<AuthRuntime>((ref) {
  throw StateError('Override authRuntimeProvider at app root');
});

final authStateProvider = StreamProvider<AuthState>((ref) =>
  ref.watch(authRuntimeProvider).authStateStream,
);

final isAuthenticatedProvider = Provider<bool>((ref) {
  final s = ref.watch(authStateProvider).value;
  return s == AuthState.authenticated;
});

final userClaimsProvider = FutureProvider<Map<String, dynamic>>((ref) async {
  if (ref.watch(authStateProvider).value != AuthState.authenticated) return {};
  return ref.watch(authRuntimeProvider).getClaims();
});

final rolesProvider = FutureProvider<List<String>>((ref) async {
  if (ref.watch(authStateProvider).value != AuthState.authenticated) return [];
  return ref.watch(authRuntimeProvider).getRoles();
});

final securityEventsProvider = StreamProvider<SecurityEvent>((ref) =>
  ref.watch(authRuntimeProvider).securityEventStream,
);
```

## 5. Architecture

```
┌──────────── Main Isolate (UI) ────────────┐
│                                            │
│  AuthRuntimeImpl (proxy)                   │
│    • _sendPort → TokenIsolate              │
│    • authStateController (Stream)          │
│    • securityEventController (Stream)      │
│    • Riverpod providers                    │
│    • Material/Cupertino widgets            │
│                                            │
│  OAuth flow (main isolate ONLY):           │
│    flutter_appauth.authorizeAndExchange    │
│    → returns code + verifier               │
│    → forward to TokenIsolate                │
└──────────────────┬─────────────────────────┘
                   │ SendPort / ReceivePort
                   │ (structured messages)
┌──────────────────▼─────────────────────────┐
│  TokenIsolate                              │
│    In RAM only:                            │
│      accessToken (String)                  │
│      refreshToken (String)                 │
│      dpopPrivateKey (SimpleKeyPair)        │
│      wrapKey (SecretKey — AES-GCM-256)     │
│      clockOffset                           │
│    Persisted via flutter_secure_storage:   │
│      wrapped_refresh_token (iv + ct + tag) │
│      dpop_key_bytes (encrypted via wrapKey)│
│      wrap_key_bytes (encrypted via platform│
│                      storage key)          │
│      last_id_token                          │
│    Performs:                                │
│      OAuth token exchange (+DPoP)           │
│      Refresh (rotating, reuse-detect wipe)  │
│      Authenticated fetch/upload             │
│      Logout (end_session + revocation)      │
│      Wipe on security event                 │
└────────────────────────────────────────────┘
```

**Why an Isolate instead of just the main thread?**

On Dart/Flutter, an Isolate has its own heap — no shared memory. Tokens held in the Token Isolate are unreachable from the UI Isolate except via explicit message passing. This is not hardware isolation (a rogue native library could still walk the process memory), but it does:

- Prevent accidental leakage via logging/telemetry code in the UI Isolate.
- Ensure `runtime.fetch(...)` returns only response bytes — the caller literally cannot receive the token.
- Give us a migration path: if the Isolate is later replaced with an FFI module using hardware-backed keys, the public API doesn't change.

Isolate overhead is ~10–50 ms spawn cost; we lazy-spawn on first `ensureAuthenticated()` / `fetch()`.

## 6. Protocol implementation

Identical wire contract to `@stawi/auth-runtime`:

1. **OIDC discovery** cached per `idpBaseUrl`; 10 s timeout; does not cache failures.
2. **DPoP** adaptive: feature-detect `dpop_signing_alg_values_supported` containing `ES256`; fall back to bearer otherwise.
3. **PKCE S256** from 64 random bytes base64url.
4. **Token exchange** with `DPoP` header when in DPoP mode; honors `DPoP-Nonce` challenge with single retry; corrects clock skew via `Date` response header.
5. **Refresh token rotation + reuse detection** — on `invalid_grant` with "reuse" in error_description, wipe everything + fire `SecurityEvent.refreshReuseDetected`.
6. **401-refresh-retry** — API responses with 401 trigger one forced refresh + one retry.
7. **Logout** — best-effort `end_session_endpoint` with `id_token_hint`, then `revocation_endpoint` for refresh token, then local wipe. `onLogout` stream event fires unconditionally.

## 7. Storage & crypto

### 7.1 TokenStore

```dart
abstract class TokenStore {
  Future<StoredSession?> load(String namespace);
  Future<void> save(String namespace, StoredSession session);
  Future<void> clear(String namespace);
}

class StoredSession {
  final WrappedBlob wrappedRefreshToken;  // {iv, ciphertext} — AES-GCM
  final Uint8List dpopKeyEncrypted;        // DPoP private key bytes encrypted with wrap key
  final Uint8List wrapKeyEncrypted;        // wrap key encrypted with platform-storage key
  final String? lastIdToken;
  final DateTime updatedAt;
}
```

Default impl: `SecureTokenStore` using `flutter_secure_storage` under a namespace-prefixed key. All Uint8List fields are base64-encoded for transport through `flutter_secure_storage` (which stores strings).

### 7.2 KeyManager

```dart
abstract class KeyManager {
  Future<SimpleKeyPair> generateDpopKey();     // ECDSA P-256
  Future<SecretKey> generateWrapKey();          // AES-GCM 256
  Future<Uint8List> signDpopProof(
    SimpleKeyPair key,
    Map<String, dynamic> header,
    Map<String, dynamic> payload,
  );
  Future<Uint8List> encrypt(SecretKey key, Uint8List plaintext);
  Future<Uint8List> decrypt(SecretKey key, Uint8List ciphertext);
}
```

Default impl: `DartCryptographyKeyManager` backed by `package:cryptography`. Keys held in Isolate RAM; private material encrypted on disk via the wrap key; wrap key itself encrypted by a platform-storage-derived key (initialized once per install).

v1.1 upgrade path: `SecureEnclaveKeyManager` for iOS, `AndroidKeystoreKeyManager` for Android, both via method channels. The `KeyManager` interface does not change.

## 8. State machine (pure)

```dart
enum _Input {
  initDone(hasTokens: bool),
  signInStart(),
  signInDone(),
  signInFail(error: AuthError),
  refreshStart(),
  refreshDone(),
  refreshFail(error: AuthError, wipe: bool),
  logout(),
  securityWipe(reason: SecurityEventType),
}

AuthState reduce(AuthState state, _Input input) { ... }
```

Identical transitions to JS spec §14. Unit-testable in pure Dart.

## 9. Dependencies

```yaml
dependencies:
  flutter: {sdk: flutter}
  flutter_riverpod: ^3.3.1        # matches existing packages
  flutter_secure_storage: ^9.2.2  # Keychain/Keystore/libsecret/DPAPI
  flutter_appauth: ^8.0.0+1        # OAuth via ASWebAuth / Chrome Custom Tabs
  cryptography: ^2.7.0             # ECDSA, AES-GCM, SHA-256
  http: ^1.2.2                      # HTTP client (also available via Isolate)
  crypto: ^3.0.6                    # base64url, PKCE
  async: ^2.11.0                    # Lock
  equatable: ^2.0.7                 # value equality for models
  uuid: ^4.5.1                      # idempotency keys
  meta: ^1.15.0
  collection: ^1.18.0

dev_dependencies:
  flutter_test: {sdk: flutter}
  flutter_lints: ^6.0.0
  mocktail: ^1.0.4
  shelf: ^1.4.1                     # in-process mock IdP
  shelf_router: ^1.1.4
```

## 10. Testing

- **Unit:** each protocol module (discovery, pkce, dpop, jwt, state_machine, token_exchange, api_proxy, key_manager, token_store) has `test/` file with Dart-native tests. Isolate code runs in the test isolate directly (no Isolate spawn) via a `TokenIsolateHandle` that exposes both in-isolate and in-thread modes.
- **Widget:** every widget has a test that renders it with mocked runtime + providers.
- **Integration:** `test/integration/` spins up `shelf`-based mock IdP that implements OIDC discovery, `/token`, `/revocation`, `/end_session`. Tests cover: full sign-in, refresh, reuse-detection wipe, 401-refresh retry, logout, DPoP nonce challenge, clock skew.
- **Coverage target:** ≥ 85% lines, 100% of state machine.

Flutter-specific test guidance: follows `superpowers:testing-flutter` — no `Future.delayed`-based flake; use `FakeAsync` / `pumpEventQueue`; real `flutter_secure_storage` is mocked via `MockFlutterSecureStorage` (official pattern).

## 11. Release plan

- **v0.1.0** — first preview. Internal consumers (service-chat, service-fintech) integrate in a feature branch each.
- **v0.2.0** — feedback cycle; API refinements based on integrator pain points.
- **v1.0.0** — stable contract. Semantic versioning thereafter.
- **v1.1.0** — Web target via `dart:js_interop` + `package:web` (deferred).

Versioning: pub.dev publishable; pattern matches `antinvestor_ui_{audit,auth,tenancy}`.

## 12. Migration guide for consumers

Each consuming app wires:

1. Add dependency: `antinvestor_auth_runtime: ^0.1.0`.
2. Configure `AuthConfig` with clientId, redirectScheme, installationId.
3. Register deep-link scheme (iOS `Info.plist`, Android `AndroidManifest.xml`, linked to `flutter_appauth` requirements).
4. Wrap root with `AuthRuntimeScope(runtime: createAuthRuntime(config), child: MyApp(...))` or override `authRuntimeProvider`.
5. Replace ad-hoc token management with `runtime.fetch(...)` for API calls.
6. Optionally use `AuthGate`, `SignInButton`, `ProfileAvatar` widgets.

Step-by-step doc at `docs/auth-runtime-integration.md` (deliverable of plan Group F-K).

## 13. Open questions

- Should the package own `GoRouter` redirect logic for auth-gated routes, or leave that to consumers? **Decision (v1.0): leave to consumers**; provide example snippet in README.
- Should `getRoles()` accept a custom extractor for non-standard IdP claim shapes? **Decision (v1.0): no — hardcode `roles` + `realm_access.roles` as in JS**; extend if needed.
- Should the runtime emit OpenTelemetry spans? **Decision (v1.0): no**; expose `onMetric` callback for app-level RUM integration in v1.1.

## 14. Future work (documented, not implemented)

- **Hardware-backed keys** via iOS Secure Enclave + Android StrongBox / TEE.
- **Biometric gating** (`local_auth`) per-refresh or per-sensitive-action.
- **Passkeys** via `webauthn` Dart package.
- **Sign in with Apple** + **Google Credential Manager** as silent sign-in fast paths.
- **Attestation** via Play Integrity API / App Attest for device trust.
- **Cross-device continuation** (QR-code sign-in).
- **Web target** via `dart:js_interop` + `package:web` wrapping `@stawi/auth-runtime`.
