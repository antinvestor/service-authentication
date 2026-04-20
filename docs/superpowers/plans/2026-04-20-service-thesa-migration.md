# `service-thesa/ui` — migration to `antinvestor_auth_runtime`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** retire `service-thesa/ui`'s custom `openid_client`-based auth (`AuthService` + `AuthRepository` + `ThesaAuthTokenBridge`) in favor of `antinvestor_auth_runtime`. ~58 call sites. Adds mobile support as a free by-product (thesa is desktop-only today; the runtime supports mobile out-of-the-box).

**Prereq:** `antinvestor_auth_runtime` v0.3 merged (specifically the `audiences` parameter, which thesa uses).

**Branch:** `feat/auth-runtime-migration` off `service-thesa/main`.

## Pre-flight — confirmations

1. Hydra accepts the 9 thesa audiences: `service_tenancy`, `service_device`, `service_profile`, `service_notification`, `service_payment`, `service_ledger`, `service_setting`, `service_thesa`, `service_file` — confirm with backend team. Verify that Hydra's `audience` parameter syntax matches what v0.3 emits (see v0.3 spec for comma vs space decision).
2. Desktop loopback on port 5173 continues to work via `flutter_appauth`'s desktop backend — verify.
3. `antinvestor_ui_core`'s `AuthTokenProvider` interface stays as a compatibility shim during the transition; new code targets the runtime directly.

## Task breakdown

### THESA-1 — Add dependency + construct runtime at app root

**Files:**
- `service-thesa/ui/pubspec.yaml` — add `antinvestor_auth_runtime: ^0.3.0`.
- `service-thesa/ui/lib/core/auth/runtime_provider.dart` — new.
- `service-thesa/ui/lib/main.dart` — construct runtime before `runApp`.

```dart
// core/auth/runtime_provider.dart
const kThesaAuthConfig = AuthConfig(
  clientId: 'antinvestor-thesa',
  idpBaseUrl: 'https://oauth2.antinvestor.com',
  apiBaseUrl: 'https://api.antinvestor.com',
  redirectScheme: 'com.antinvestor.thesa',  // mobile; ignored on desktop
  redirectPort: 5173,                        // desktop loopback
  scopes: ['openid', 'profile', 'offline_access'],
  audiences: [
    'service_tenancy', 'service_device', 'service_profile',
    'service_notification', 'service_payment', 'service_ledger',
    'service_setting', 'service_thesa', 'service_file',
  ],
);
```

Commit: `feat(thesa/auth): construct antinvestor_auth_runtime at app root`

### THESA-2 — Rewire Connect RPC transport through runtime.fetch

**Files:**
- `service-thesa/ui/lib/core/networking/` — identify the Transport factory.
- Point every RPC client at a `RuntimeBackedTransport` (copy the pattern from service-chat CHAT-2; add to `antinvestor_ui_core` if it should be shared across apps).

Commit: `refactor(thesa/auth): Connect RPC transport uses runtime.fetch`

### THESA-3 — Delete legacy auth files

**Files to delete:**
- `service-thesa/ui/lib/features/auth/data/auth_service.dart`
- `service-thesa/ui/lib/features/auth/data/auth_repository.dart`
- `service-thesa/ui/lib/core/services/auth_bridge.dart` (the `ThesaAuthTokenBridge` adapter — no longer needed since `antinvestor_ui_core` will consume the runtime's providers directly).

**Files to update:**
- `service-thesa/ui/lib/features/auth/data/auth_state_provider.dart` — re-export runtime's `authStateProvider`.
- `antinvestor_ui_core` — update `AuthTokenProvider` consumers to accept `AuthRuntime` directly (separate PR in `antinvestor_ui_core` if that package is shared across apps).

Commit: `refactor(thesa/auth): delete legacy AuthService + AuthBridge`

### THESA-4 — Migrate route guards + login screen

**Files:**
- `service-thesa/ui/lib/app/router.dart` — use `authStateProvider`.
- `service-thesa/ui/lib/features/auth/ui/login_page.dart` — replace custom button with `SignInButton` from runtime. Keep gradient / Material 3 styling via `ButtonStyle` prop.

Commit: `refactor(thesa/auth): route guards + login page use runtime widgets`

### THESA-5 — Add mobile support (free upgrade)

Thesa is desktop-only today. Once the runtime is wired, iOS/Android become viable:

- Confirm platform manifest entries exist for the `com.antinvestor.thesa` scheme:
  - Android: add intent-filter to `service-thesa/ui/android/app/src/main/AndroidManifest.xml`.
  - iOS: add `CFBundleURLTypes` entry to `service-thesa/ui/ios/Runner/Info.plist`.
- Smoke-test sign-in on iOS simulator + Android emulator.
- Gate mobile behind a feature flag initially if product wants to control rollout.

Commit: `feat(thesa/auth): add mobile platform manifests (iOS + Android)`

### THESA-6 — One-time token storage migration

Same pattern as CHAT-7: clear legacy secure-storage keys on first launch after migration so the runtime triggers a fresh sign-in. SharedPreferences flag prevents repeat.

Commit: `refactor(thesa/auth): one-time migration clears legacy secure-storage keys`

### THESA-7 — Update tests

**Files:**
- Replace `mockAuthService` with `MockAuthRuntime`.
- Delete tests for the deleted legacy auth code.
- Add `audiences` assertion: with `audiences` configured, the generated authorize URL includes the expected `audience` param.
- Integration smoke: mocked OAuth → authenticated → RPC via runtime succeeds with a token whose `aud` claim matches configured audiences.

Commit: `test(thesa/auth): migrate test harness to MockAuthRuntime + audiences assertion`

### THESA-8 — End-to-end smoke

- [ ] Desktop: fresh install → sign in via browser loopback → authenticated.
- [ ] Mobile iOS: sign in via ASWebAuthenticationSession → authenticated.
- [ ] Mobile Android: sign in via Chrome Custom Tabs → authenticated.
- [ ] Token carries expected `aud` claim for each audience (decode and log in dev mode).
- [ ] Sign out clears state across platforms.

## Rollback plan

Same as chat: revert the feature-branch merge. Low risk; the app is smaller and simpler than chat.

## Estimated effort

- Implementation: 5–7 subagent hours (58 call sites, no dual-cache, no background refresh).
- QA on desktop + mobile: 0.5 day.

## Open questions

- Does thesa's backend validate the `aud` claim per-service, or is it informational only? If validated, the audiences list must match exactly what's registered in Hydra. Verify with backend team.
- Is mobile thesa a product ask for this iteration or purely a "we get it for free, flag it off" situation? Decide before THESA-5.
