# `service-chat/ui` — migration to `antinvestor_auth_runtime`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** retire `service-chat/ui`'s custom auth stack (`openid_client`-based `AuthService` + dual-cache `TokenManager` + `TokenRefreshCoordinator` + `SharedTokenService`) in favor of `antinvestor_auth_runtime`. ≥230 call sites migrate to the unified runtime API.

**Prereq:** `antinvestor_auth_runtime` v0.3 merged (`audiences` + typed `UserClaims` getters + background-task docs).

**Branch:** `feat/auth-runtime-migration` off `service-chat/main`.

**Scope:** `service-chat/ui/` only. Non-goals: changing the backend auth contract (Hydra unchanged).

## Pre-flight — confirmations

1. Hydra continues to emit `contact_id` and `realm_access.roles` claims — verified.
2. Runtime v0.3's `UserClaims.contactId` getter covers the `contact_id` use-case — verified by unit test before starting.
3. WorkManager tasks construct a fresh runtime per task; no cross-Isolate sharing — documented in runtime README.
4. Deep-link scheme `com.antinvestor.chat://sso/redirect` remains stable. Runtime's `redirectScheme: "com.antinvestor.chat"` with `redirectPath: "/sso/redirect"` (the latter is the path portion `flutter_appauth` uses).

## Task breakdown

### CHAT-1 — Add dependency + construct runtime at app root

**Files:**
- `service-chat/ui/pubspec.yaml` — add `antinvestor_auth_runtime: ^0.3.0` (path dep during feature branch).
- `service-chat/ui/lib/core/auth/runtime_provider.dart` — new; holds a factory + provider override.
- `service-chat/ui/lib/main.dart` — modify to construct runtime before `runApp`.

```dart
// core/auth/runtime_provider.dart
const kChatAuthConfig = AuthConfig(
  clientId: 'antinvestor-chat',
  idpBaseUrl: 'https://oauth2.antinvestor.com',
  apiBaseUrl: 'https://api.antinvestor.com',
  redirectScheme: 'com.antinvestor.chat',
  redirectPath: '/sso/redirect',
  scopes: ['openid', 'profile', 'offline_access'],
);

AuthRuntime buildChatRuntime() => createAuthRuntime(kChatAuthConfig);
```

```dart
// main.dart (delta)
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await initializeApp(); // existing init
  final runtime = buildChatRuntime();
  runApp(
    ProviderScope(
      overrides: [authRuntimeProvider.overrideWithValue(runtime)],
      child: StawiApp(),
    ),
  );
}
```

Commit: `feat(auth): construct antinvestor_auth_runtime at app root`

### CHAT-2 — Replace `AuthInterceptor` with runtime.fetch

**Files:**
- `service-chat/ui/lib/core/networking/interceptors.dart` — delete `AuthInterceptor`.
- `service-chat/ui/lib/core/networking/client.dart` — rewire Connect RPC transport to use `runtime.fetch` under the hood.

Connect RPC has a `Transport` abstraction; write a `RuntimeBackedTransport` that delegates all RPCs to `runtime.fetch(path, method: 'POST', body: jsonBody, headers: {...})`. For upload RPCs use `runtime.upload`.

Commit: `refactor(chat/auth): route Connect RPC transport through runtime.fetch`

### CHAT-3 — Delete legacy auth files

**Files to delete:**
- `service-chat/ui/lib/features/auth/data/auth_service.dart`
- `service-chat/ui/lib/features/auth/data/auth_repository.dart`
- `service-chat/ui/lib/core/auth/token_refresh_coordinator.dart`
- `service-chat/ui/lib/core/auth/auth_context.dart` (if absorbed by runtime — confirm by running tests)

**Files to update:**
- `service-chat/ui/lib/features/auth/data/auth_state_provider.dart` — rewire to `authStateProvider` from runtime; remove `AuthStateNotifier` (runtime owns state).

Commit: `refactor(chat/auth): delete legacy AuthService + TokenRefreshCoordinator`

### CHAT-4 — Rewire background token refresh (WorkManager)

**Files:**
- `service-chat/ui/lib/core/auth/shared_token_service.dart` — replace with new `BackgroundAuthHelper`:

```dart
class BackgroundAuthHelper {
  /// Call from WorkManager task entry. Constructs a runtime, performs
  /// the work, disposes. Do NOT share runtime across tasks.
  static Future<T> withRuntime<T>(Future<T> Function(AuthRuntime) fn) async {
    final runtime = buildChatRuntime();
    try {
      if (!runtime.isAuthenticated) return Future.value() as T;
      return await fn(runtime);
    } finally {
      await runtime.dispose();
    }
  }
}
```

All ~50 WorkManager call sites switch to `BackgroundAuthHelper.withRuntime((rt) async { ... rt.fetch(...) ... })`.

Commit: `refactor(chat/auth): BackgroundAuthHelper for WorkManager tasks`

### CHAT-5 — Migrate route guards + login screen + profile UI

**Files:**
- `service-chat/ui/lib/app/router.dart` — replace `AuthChangeNotifier` with `ref.watch(authStateProvider)` directly in the `redirect` callback.
- `service-chat/ui/lib/features/auth/ui/login_screen.dart` — replace custom OAuth trigger with `SignInButton` from runtime; keep existing branding.
- `service-chat/ui/lib/features/settings/ui/settings_screen.dart` — replace sign-out button with `SignOutButton`.

Commit: `refactor(chat/auth): route guards + login + settings use runtime widgets`

### CHAT-6 — Access `contact_id` via typed UserClaims

**Files:**
- Grep for `contact_id` usage sites.
- Replace `claims['contact_id']` casts with `userClaims.contactId` (typed).

Commit: `refactor(chat/auth): use UserClaims.contactId typed getter`

### CHAT-7 — One-time token storage migration

**Files:**
- `service-chat/ui/lib/core/auth/migration.dart` — new.

```dart
/// Clear v1 tokens so the runtime forces a fresh sign-in on first launch
/// after the migration. Runs once per install via SharedPreferences flag.
Future<void> migrateLegacyAuthIfNeeded() async {
  final prefs = await SharedPreferences.getInstance();
  if (prefs.getBool('auth_runtime_migrated') == true) return;
  const storage = FlutterSecureStorage();
  for (final key in ['access_token', 'refresh_token', 'id_token', 'token_expires_at']) {
    await storage.delete(key: key);
  }
  await prefs.setBool('auth_runtime_migrated', true);
}
```

Call from `main.dart` before `buildChatRuntime`.

Commit: `refactor(chat/auth): one-time migration clears legacy secure-storage keys`

### CHAT-8 — Update tests

**Files:**
- Replace `mockAuthService` fixtures with `MockAuthRuntime` (from `antinvestor_auth_runtime/test_support`).
- Delete tests that cover the deleted legacy auth code.
- Add integration smoke test: launch app → tap sign-in → (mocked) OAuth succeeds → home screen renders.

Commit: `test(chat/auth): migrate test harness to MockAuthRuntime`

### CHAT-9 — Platform manifest verification

**Files:**
- `service-chat/ui/android/app/src/main/AndroidManifest.xml` — verify the existing intent-filter matches the new `redirectScheme` / `redirectPath`. No change expected; document expected state in a comment.
- `service-chat/ui/ios/Runner/Info.plist` — verify `CFBundleURLTypes` has the scheme. Add if missing.

Commit: `chore(chat/auth): verify platform URL scheme manifests`

### CHAT-10 — End-to-end smoke on device

Manual QA checklist (not automatable):

- [ ] Fresh install → sign in → authenticated state.
- [ ] App backgrounded for 15 min → resume → access token auto-refreshed.
- [ ] Kill app → relaunch → no re-sign-in required (stored refresh token used).
- [ ] Sign out → re-open → login screen.
- [ ] Airplane mode while authenticated → API calls surface `networkError` not `tokenExpired`.
- [ ] WorkManager background sync → runs with authenticated runtime and returns data.
- [ ] Mobile deep link → OAuth callback reaches the app correctly.

Commit: none (QA only); attach checklist to the PR description.

## Rollback plan

All migration commits are on a feature branch. If production issues surface post-merge:

1. Revert the feature-branch merge commit (single revert).
2. Force-clear the `auth_runtime_migrated` SharedPreferences flag via a small patch so users don't lose their legacy-token state permanently.
3. Release a hotfix pointing back at `AuthService`.

Low risk given the one-time-migration design clears legacy keys — but the revert path exists.

## Estimated effort

- Implementation: 12–18 subagent hours (most of the time is in touching ~230 call sites).
- QA on real devices (iOS + Android + desktop): 1 day.

## Open questions

- Does chat have any WorkManager task that MUST run before runtime.init() completes? If yes, add a synchronous cached-state path.
- Is `contact_id` token claim always present or only post-verification? If conditional, `UserClaims.contactId` needs to tolerate null (already does per v0.3 design).
