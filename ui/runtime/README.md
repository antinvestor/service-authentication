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

The runtime drives the system browser for OAuth (via `flutter_appauth`)
and then receives the callback on a custom scheme. Each platform needs a
one-time declaration of that scheme.

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
    android:name="net.openid.appauth.RedirectUriReceiverActivity"
    android:exported="true"
    tools:node="replace">
  <intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="com.antinvestor.myapp" />
  </intent-filter>
</activity>
```

### macOS / Windows / Linux

No per-platform manifest entries are required: `flutter_appauth` uses the
system browser directly and receives the callback over an embedded
listener. The scheme only has to match `AuthConfig.redirectScheme`.

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
