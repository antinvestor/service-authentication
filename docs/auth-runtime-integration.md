# Integrating `antinvestor_auth_runtime` into a consuming app

This guide walks through wiring `antinvestor_auth_runtime` into an
existing Flutter app — specifically `service-chat` and `service-fintech`,
but the procedure applies to any Antinvestor Flutter client.

Each step lists the files to create or edit and the exact snippet to
drop in. Substitute the client-specific placeholders where called out.

---

## Step 1 — Add the dependency

In the consuming app's `pubspec.yaml`:

```yaml
dependencies:
  antinvestor_auth_runtime: ^0.1.0
```

Then run `flutter pub get` (or `dart pub get`).

If you are developing against the runtime inside this monorepo, use a
path dependency instead:

```yaml
dependencies:
  antinvestor_auth_runtime:
    path: ../../service-authentication/ui/runtime
```

## Step 2 — Decide the OAuth client ID

Each consuming app is its own OAuth client registered with the
Antinvestor IdP (Hydra). Use a descriptive, stable client ID per app.

| App | Suggested client ID placeholder | Replace with |
|-----|---------------------------------|--------------|
| service-chat | `antinvestor-chat-mobile` | Real Hydra client ID once provisioned |
| service-fintech | `antinvestor-fintech-mobile` | Real Hydra client ID once provisioned |

These IDs must be registered in the IdP tenancy config with the
`authorization_code` grant, `refresh_token` grant, and the app's redirect
URI in the allow-list.

## Step 3 — Register the redirect scheme per platform

See the runtime's README "Platform setup" section for iOS + Android
manifest edits. For `service-chat` use `com.antinvestor.chat` as the
scheme; for `service-fintech` use `com.antinvestor.fintech`.

## Step 4 — Create `lib/auth/auth_config.dart`

A single file pinning the per-app configuration. Example for
`service-chat`:

```dart
import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';

const AuthConfig chatAuthConfig = AuthConfig(
  clientId: 'antinvestor-chat-mobile',
  idpBaseUrl: 'https://auth.antinvestor.com',
  apiBaseUrl: 'https://chat-api.antinvestor.com',
  redirectScheme: 'com.antinvestor.chat',
  scopes: <String>[
    'openid',
    'profile',
    'email',
    'offline_access',
    'chat:read',
    'chat:write',
  ],
);
```

Mirror this for `service-fintech` with the fintech-specific values.

## Step 5 — Wire `createAuthRuntime` at app start

In the consuming app's `main.dart` (or wherever `runApp` lives):

```dart
import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'auth/auth_config.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();

  final runtime = createAuthRuntime(chatAuthConfig);

  runApp(ProviderScope(
    overrides: [
      authRuntimeProvider.overrideWithValue(runtime),
    ],
    child: const ChatApp(),
  ));
}
```

If the app is not already a Riverpod app, use `AuthRuntimeScope` instead
(see the README).

Optional but recommended: kick off discovery during splash so the first
sign-in isn't the one paying the round-trip:

```dart
unawaited(runtime.prefetchDiscovery());
```

## Step 6 — Wrap the navigator with `AuthGate`

```dart
class ChatApp extends StatelessWidget {
  const ChatApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Antinvestor Chat',
      home: AuthGate(
        child: const HomeScreen(),
        // Optional: customise the unauthenticated placeholder.
        unauthenticatedBuilder: (context) => const SignInLandingPage(),
      ),
    );
  }
}
```

`AuthGate` listens on `authStateProvider` and re-builds whenever the
runtime transitions. Once authenticated, the subtree mounts.

## Step 7 — Replace ad-hoc HTTP calls with `runtime.fetch`

Before:

```dart
final dio = Dio();
final res = await dio.get('/v1/conversations',
    options: Options(headers: {'Authorization': 'Bearer $token'}));
```

After:

```dart
final runtime = ref.read(authRuntimeProvider);
final res = await runtime.fetch('/v1/conversations');
final data = jsonDecode(utf8.decode(res.body));
```

The `apiBaseUrl` from `AuthConfig` is prepended automatically, the
`Authorization` header (Bearer or DPoP) is added, DPoP proofs are minted
per-request, and 401 responses trigger a transparent refresh + retry.

For uploads:

```dart
final res = await runtime.upload(
  '/v1/attachments',
  fieldName: 'file',
  filename: 'pic.jpg',
  contentType: 'image/jpeg',
  bytes: file.openRead(),
  length: await file.length(),
);
```

## Step 8 — Migrate any existing token storage

During a rollout from a legacy auth stack:

1. On first launch against the new runtime, read the legacy token store.
2. If a legacy refresh token exists and is still valid, *do not* attempt
   to import it — request a fresh sign-in instead. Cross-stack token
   reuse is a correctness footgun; the refresh token format, the IdP
   session, and the DPoP binding all differ.
3. Call `legacyStore.clear()` once the new runtime reports
   `AuthState.authenticated` so old artefacts don't linger.
4. Always call `runtime.dispose()` on app shutdown — this flushes the
   stream controllers and lets `flutter_secure_storage` release its
   keychain handles cleanly.

## Step 9 — Validation test

Add a test in the consuming app that asserts the runtime ends up
authenticated when fed a fake OAuth flow. The runtime ships an
integration harness pattern you can borrow — the minimal shape:

```dart
// test/auth/auth_smoke_test.dart
import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('runtime authenticates against a stubbed IdP', () async {
    // Construct a real runtime with a FakeOAuthFlow pointing at a
    // MockIdp (see the runtime's test/integration/_helpers.dart for
    // the fixture). On CI the package's own integration tests cover
    // this path; a smoke test here just confirms wiring.
    //
    // The key assertion is that after `ensureAuthenticated` returns,
    // `runtime.state == AuthState.authenticated` and
    // `runtime.getClaims()` contains the expected subject.
  });
}
```

For rich end-to-end coverage refer to the runtime's own
`test/integration/` suite, which drives a shelf-backed MockIdp end-to-end.

---

## Reference: matrix of placeholders

| Placeholder | service-chat | service-fintech |
|-------------|--------------|-----------------|
| `clientId` | `antinvestor-chat-mobile` | `antinvestor-fintech-mobile` |
| `idpBaseUrl` | `https://auth.antinvestor.com` | `https://auth.antinvestor.com` |
| `apiBaseUrl` | `https://chat-api.antinvestor.com` | `https://fintech-api.antinvestor.com` |
| `redirectScheme` | `com.antinvestor.chat` | `com.antinvestor.fintech` |

Replace the placeholder client IDs with values obtained from the
Antinvestor IdP admin console before shipping a release build.
