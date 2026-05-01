# antinvestor_auth_runtime

Auth runtime for Antinvestor Flutter apps. OAuth2 + PKCE, adaptive DPoP,
rotating refresh tokens with reuse detection, optional Isolate-isolated
tokens, hardware-backed secure storage, Riverpod providers, and a small
Material widget toolkit.

[![Flutter 3.24+](https://img.shields.io/badge/flutter-3.24%2B-blue.svg)](https://flutter.dev)
[![Dart 3.11+](https://img.shields.io/badge/dart-3.11%2B-blue.svg)](https://dart.dev)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

---

## Install

```shell
flutter pub add antinvestor_auth_runtime
```

## Platform setup

The runtime drives the system browser for OAuth (via `flutter_web_auth_2`)
and receives the callback on a custom scheme. Each platform needs a
one-time declaration of that scheme.

Supported platforms: **iOS, Android, macOS, Web, Windows, Linux**.

Assume your app's redirect scheme is `com.antinvestor.myapp`; the runtime
will derive `com.antinvestor.myapp://callback` as the full redirect URI.

### iOS — `ios/Runner/Info.plist`

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLName</key>
    <string>com.antinvestor.myapp.auth</string>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>com.antinvestor.myapp</string>
    </array>
  </dict>
</array>
```

### Android — `android/app/src/main/AndroidManifest.xml`

Inside `<application>`:

```xml
<activity
    android:name="com.linusu.flutter_web_auth_2.CallbackActivity"
    android:exported="true">
  <intent-filter android:label="flutter_web_auth_2">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="com.antinvestor.myapp" />
  </intent-filter>
</activity>
```

### macOS

Same as iOS — declare `CFBundleURLSchemes` in `macos/Runner/Info.plist`.

### Web

Set `redirectUri: 'https://yourapp.com/auth.html'` in `AuthConfig` and
host an `auth.html` page at that path. See the
[`flutter_web_auth_2` web setup](https://pub.dev/packages/flutter_web_auth_2#web)
for the page contents (it forwards the callback URL via `postMessage`).

The IdP login page handles federated identity (Google, Apple, etc.) and
may use the browser's FedCM API where supported — the runtime is
FedCM-transparent, no client-side wiring required.

### Windows / Linux

`flutter_web_auth_2` uses an embedded `desktop_webview_window` by
default. For the loopback variant, pass `redirectUri:
'http://localhost:{port}/auth'` in `AuthConfig`.

## Native sign-in (Apple + Google)

The runtime ships built-in support for Sign in with Apple and Google
Sign-In so iOS / macOS / Android users can skip the browser hop and get
signed in through the platform's native credential sheet. This is
entirely opt-in; callers that pass no providers to `createAuthRuntime`
get the v0.1 OAuth2-only behaviour.

### Why use it

- Fastest UX on platforms where the user is already signed into Apple
  or Google — no browser context switch, no password typing.
- Fewer sign-in abandonments on mobile where the redirect dance is most
  fragile.
- Graceful degradation: when native providers decline (no session, user
  cancels, platform unavailable) the runtime falls back to the existing
  OAuth2 + PKCE flow automatically.

### How the waterfall works

On every `ensureAuthenticated()`:

1. **Proactive silent** (on mount): each configured native provider is
   asked for an auto-select credential. No UI. If one succeeds the
   runtime exchanges the ID token via RFC 8693 token-exchange and
   transitions to `authenticated`.
2. **Interactive** (on sign-in click): for each provider in order, the
   runtime calls `attemptInteractive`. The first `Ok` outcome is
   exchanged via token-exchange.
3. **OAuth2 fallback**: if every native provider returns `Cancelled`,
   `NoSession`, `Unavailable`, or `ErrorOutcome`, the runtime opens
   the system browser via `flutter_web_auth_2` exactly as in v0.1.

### Consumer setup

```dart
import 'dart:io';
import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';

final providers = <NativeCredentialProvider>[
  if (Platform.isIOS || Platform.isMacOS) AppleCredentialProvider(),
  GoogleCredentialProvider(serverClientId: googleServerClientId),
];

final runtime = createAuthRuntime(cfg, nativeProviders: providers);
```

With Riverpod, also override `authNativeProvidersProvider` so widgets
can render platform-aware sign-in buttons:

```dart
ProviderScope(
  overrides: [
    authNativeProvidersProvider.overrideWithValue(providers),
    authRuntimeProvider.overrideWithValue(runtime),
  ],
  child: const MyApp(),
);
```

### Platform requirements

**iOS**

- Enable the "Sign In with Apple" capability for your target in Xcode
  (`Signing & Capabilities` → `+ Capability`).
- The Bundle ID must match the one registered at
  [developer.apple.com](https://developer.apple.com) under your
  services ID.
- Minimum deployment target iOS 13.

**Android**

- Create a Google OAuth client in Google Cloud Console of type
  "Android" and record the **server client ID** (type "Web
  application") — the latter is what you pass to
  `GoogleCredentialProvider(serverClientId: …)`.
- Register the app's SHA-256 fingerprint on the Android OAuth client.
- `android/app/build.gradle` must have `minSdkVersion >= 23`
  (Credential Manager requirement).
- No `google-services.json` is required: the Credential-Manager-backed
  `google_sign_in` v7 flow does not use Firebase.

**macOS**

- Same Apple developer configuration as iOS.
- Add the Sign in with Apple entitlement in both
  `macos/Runner/DebugProfile.entitlements` and
  `macos/Runner/Release.entitlements`:

  ```xml
  <key>com.apple.developer.applesignin</key>
  <array>
    <string>Default</string>
  </array>
  ```

### Failure-mode table

| `NativeCredentialOutcome`        | Effect                                                                    |
|----------------------------------|---------------------------------------------------------------------------|
| `Ok(result)`                     | ID token exchanged via RFC 8693; runtime transitions to `authenticated`.  |
| `Cancelled()`                    | User dismissed the native sheet. Runtime falls through to the next provider, then OAuth2. |
| `NoSession()`                    | Silent attempt found no credential. Waterfall moves on.                   |
| `Unavailable(reason)`            | Provider cannot run on this platform / OS version. Waterfall moves on.    |
| `ErrorOutcome(AuthError)`        | Recorded as a `CredentialOutcomeEvent`; waterfall moves on.               |

The `credentialEventStream` emits probe / silent / interactive / outcome
/ sign-out events for telemetry; subscribe in debug builds to observe
the waterfall in action.

### Backend requirements

The authentication service (Ory Hydra or equivalent) must accept the
RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange` grant and
treat Apple / Google as trusted subject issuers. See
[docs/auth-runtime-native-credentials.md](../../docs/auth-runtime-native-credentials.md)
for the operator-side configuration guide.

## Quick start (Riverpod — preferred)

```dart
import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

void main() {
  final runtime = createAuthRuntime(const AuthConfig(
    clientId: 'antinvestor-myapp-mobile',
    idpBaseUrl: 'https://auth.antinvestor.com',
    apiBaseUrl: 'https://api.antinvestor.com',
    redirectScheme: 'com.antinvestor.myapp',
  ));

  runApp(ProviderScope(
    overrides: [
      authRuntimeProvider.overrideWithValue(runtime),
    ],
    child: MaterialApp(
      home: AuthGate(child: HomePage()),
    ),
  ));
}
```

## Quick start (non-Riverpod)

```dart
import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter/material.dart';

void main() {
  final runtime = createAuthRuntime(const AuthConfig(
    clientId: 'antinvestor-myapp-mobile',
    idpBaseUrl: 'https://auth.antinvestor.com',
    apiBaseUrl: 'https://api.antinvestor.com',
    redirectScheme: 'com.antinvestor.myapp',
  ));

  runApp(AuthRuntimeScope(
    runtime: runtime,
    child: MaterialApp(home: HomePage()),
  ));
}
```

`AuthRuntimeScope` exposes the runtime via `AuthRuntimeScope.of(context)`
for widgets that need access without Riverpod.

## Making authenticated calls

The access token never leaves the runtime: callers receive only the
response bytes + status + headers.

```dart
final runtime = ref.read(authRuntimeProvider);

final response = await runtime.fetch('/v1/me');
if (response.status == 200) {
  final me = jsonDecode(utf8.decode(response.body));
}
```

Supported methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`.
`body` may be a `String`, `List<int>`, or `Uint8List`. For file uploads
use `runtime.upload(path, fieldName:, filename:, contentType:, bytes:,
length:)` — multipart form-data with automatic retry on 401.

### Multi-domain usage

`runtime.fetch(path)` concatenates `AuthConfig.apiBaseUrl + path` by default. Pass an absolute URL to bypass:

```dart
await runtime.fetch('https://files.example.com/v1/upload', method: 'POST', body: bytes);
```

Useful when an app talks to multiple service domains but shares a single OAuth client / token audience.

## Audiences (thesa pattern)

Apps that front several downstream services need their access tokens to
carry a specific `aud` claim per service. `AuthConfig.audiences`
forwards a comma-joined `audience` parameter to both the authorize
endpoint and the token-exchange grant; Ory Hydra mints a token whose
`aud` claim contains every requested value.

```dart
createAuthRuntime(const AuthConfig(
  clientId: 'antinvestor-thesa-web',
  idpBaseUrl: 'https://auth.antinvestor.com',
  apiBaseUrl: 'https://api.antinvestor.com',
  redirectScheme: 'com.antinvestor.thesa',
  audiences: [
    'service-notification',
    'service-profile',
    'service-partition',
    'service-payment',
    'service-ledger',
    'service-contact',
    'service-property',
    'service-device',
    'service-files',
  ],
));
```

Omit the field (the default) when your client talks to a single
service.

## Typed claim getters

`AuthRuntime.getUserClaims()` wraps the raw claims map in a `UserClaims`
with typed accessors — including the Antinvestor-wide non-standard
claims (`contact_id`, `tenant_id`, `partition_id`).

```dart
final claims = await runtime.getUserClaims();
debugPrint('contact=${claims.contactId} tenant=${claims.tenantId}');

// Reach into bespoke per-app claims via the escape hatch:
final extra = claims.customClaims;
```

`customClaims` returns every claim that is **not** part of the OIDC
core / JWT registered set, so apps can surface their own fields without
colliding with the typed getters.

## Background tasks (WorkManager)

Android WorkManager (and similar Isolate-spawning background frameworks)
can instantiate the runtime inside a short-lived isolate and bail out
early when the user is signed out. Use `AuthRuntime.isAuthenticated`
for the synchronous pre-check so you don't pay for async warmup on a
terminal device.

```dart
class BackgroundAuth {
  static Future<T?> withRuntime<T>(Future<T> Function(AuthRuntime) fn) async {
    final runtime = createAuthRuntime(kConfig);
    try {
      if (!runtime.isAuthenticated) return null;
      return await fn(runtime);
    } finally {
      await runtime.dispose();
    }
  }
}
```

> **Warning:** Do NOT share runtime instances across Isolates. Construct
> and `dispose()` a fresh runtime per task — the token worker's streams,
> storage handles, and DPoP key material are not safe to move across
> isolate boundaries.

## Widget reference

| Widget | Purpose |
|--------|---------|
| `AuthGate` | Wraps a subtree; shows a sign-in placeholder when unauthenticated, the child otherwise. |
| `AuthStateBuilder` | Imperative builder variant — supply builders per state. |
| `AuthEventListener` | Subscribes to `securityEventStream` and surfaces events via snackbars or a callback. |
| `SignInButton` | Material button calling `ensureAuthenticated`. |
| `SignOutButton` | Material button calling `logout`. |
| `ProfileAvatar` | Circle avatar rendered from the ID token's `picture` claim with a letter fallback. |

All widgets honour the Material `ThemeData` of the surrounding app.

## Provider reference

| Provider | Type | Behaviour |
|----------|------|-----------|
| `authRuntimeProvider` | `Provider<AuthRuntime>` | The runtime itself. Override in `ProviderScope`. |
| `authStateProvider` | `StreamProvider<AuthState>` | Reactive `AuthState` transitions. |
| `isAuthenticatedProvider` | `Provider<bool>` | `true` when `state == authenticated`. |
| `userClaimsProvider` | `FutureProvider<UserClaims>` | ID token claims, wrapped for convenient access. |
| `rolesProvider` | `FutureProvider<List<String>>` | Roles extracted from the access token. |
| `securityEventsProvider` | `StreamProvider<SecurityEvent>` | Security signals (`refreshReuseDetected`, `storageCorruption`, …). |
| `authNativeProvidersProvider` | `Provider<List<NativeCredentialProvider>>` | Configured native credential providers. Defaults to `[]`; override at app root alongside `authRuntimeProvider`. |

## Security posture

| Control | Implementation |
|---------|----------------|
| Isolate isolation | Opt-in via `createAuthRuntime(..., useIsolate: true)` for defense-in-depth token separation. The default in-thread runtime is fully featured. |
| Hardware-backed secure storage | `flutter_secure_storage` — iOS Keychain, Android Keystore / EncryptedSharedPreferences, macOS Keychain, Linux libsecret. |
| DPoP binding | Adaptive: enabled automatically when the IdP advertises `dpop_signing_alg_values_supported`. ES256 proofs with nonce + clock-skew retry. |
| Refresh rotation | Every refresh returns a new RT; the old one is discarded. |
| Reuse detection | A rejected `invalid_grant` response triggers a security wipe + `SecurityEvent.refreshReuseDetected`. |
| Root-key + wrap-key chain | Wrap key (AES-GCM 256) encrypts the DPoP private key and refresh token; the wrap key itself is encrypted under a keychain-resident root key. |
| Logout | Best-effort server-side revocation + `end_session`; local wipe always runs even on network failure. |
| Storage corruption handling | Unreadable on-disk state triggers a wipe + `SecurityEvent.storageCorruption` rather than a crash. |

## Troubleshooting

**OAuth completes in the browser but the app never receives the code.**
The `redirectScheme` in `AuthConfig` must match the platform-manifest
declaration exactly. The runtime derives `{scheme}://callback` — double
check that.

**Refresh fails on every run with `tokenRefreshFailed`.**
`offline_access` must be in the requested scopes (it is by default).
Without it the IdP will not issue a refresh token.

**`AuthGate` shows the sign-in placeholder after a cold start when the
user was previously signed in.**
This is expected during the first microtask while the runtime reloads
storage. The `StreamProvider` emits the restored state on the next tick.
If it stays on the placeholder, inspect `securityEventsProvider` for a
`StorageCorruption` event — the session may have been wiped.

**Clock-skew retry loops forever.**
Only one clock-skew retry is attempted per request. Persistent failure
indicates a system clock far enough off that the IdP's `Date` header is
itself wrong; fix device time.

## Compatibility matrix

| Platform | Minimum |
|----------|---------|
| Flutter | 3.24 |
| Dart SDK | 3.11 |
| iOS | 13 |
| Android | 8 (API 26) |
| macOS | 11 |
| Windows | 10 |
| Linux | glibc-based modern distros (Ubuntu 22.04+) |

## Versioning

This package follows [Semantic Versioning](https://semver.org). Breaking
changes bump the major version. Within a major, we preserve the public
API surface exported from `antinvestor_auth_runtime.dart`.

## License

Apache 2.0 — see [LICENSE](LICENSE).
