# `antinvestor_auth_runtime` — roadmap design (v0.3 additions, v1.1 Web, consumer migrations)

Status: draft
Date: 2026-04-20
Scope: three follow-on tracks after v0.2.0 ships.

---

## 1. Context

Three Antinvestor Flutter apps currently reimplement authentication from scratch with `openid_client` + `flutter_secure_storage`:

- `service-chat/ui` — production, ~230 auth call sites, mobile + desktop, background refresh in WorkManager, custom `contact_id` claim.
- `service-thesa/ui` — production, ~58 auth call sites, desktop-only, passes a 9-element `audiences` array at authorize-time.
- `service-fintech/ui` — no consolidated app; feature packages only.

Goal: retire those ad-hoc implementations in favor of `antinvestor_auth_runtime`. Scouting (recon report in conversation history) identified four gaps to close before migration:

1. **`audiences` parameter** not in `AuthConfig` — thesa requires it.
2. **Custom-claim surfacing** — chat needs `contact_id`; today consumers call `runtime.getClaims()` and cast, which works but is undiscoverable.
3. **Background-task friendly** — chat's WorkManager path needs an `AuthRuntime` that is safe to construct outside a Riverpod scope and safe to dispose aggressively.
4. **Web target** — service-thesa is desktop-only today but the brief is "replace the current auth with a standardized reusable implementation" — web support is strongly implied for admin UIs.

This doc covers three tracks:

- **Track A: v0.3 runtime additions** — audiences, custom-claim helper, background-safe construction.
- **Track B: v1.1 Web target** — pure-Dart implementation with `dart:js_interop` + `package:web`.
- **Track C: consumer migrations** — chat, thesa, fintech.

Each is self-contained and can ship independently. Sequencing preference: v0.3 → chat migration → thesa migration → v1.1 Web → fintech (pending consolidation).

---

## 2. Track A — v0.3 runtime additions

### A.1 `audiences` parameter

**Motivation:** thesa passes resource-based audience hints to Hydra so issued tokens carry the right `aud` claim for each downstream service.

**Spec:**

- `AuthConfig.audiences: List<String>?` — optional, default `null` (omitted from authorize URL).
- When non-null, the runtime appends `audience=<comma-separated list>` to the authorize URL per Hydra's convention (Hydra accepts space-separated via RFC 8707 or comma-separated per its docs — default to comma).
- `ResolvedConfig` mirrors with non-nullable default empty list.
- Token exchange grant body also carries `audience` when configured.

**Backward compatibility:** additive; existing v0.2 callers unaffected.

**Tests:** assert authorize URL + token body both include `audience` when configured; omit when null.

### A.2 Custom-claim surfacing — `UserClaims` typed getters + helper

**Motivation:** chat's `contact_id` claim is a repeat pattern (non-standard OIDC claim used by multiple Antinvestor services). Today consumers call `runtime.getClaims()` which returns a `Map<String, dynamic>` and they cast. This works but is error-prone and undiscoverable.

**Spec:**

- `UserClaims` class already wraps the claims map (v0.1). Extend with typed getters for Antinvestor-specific claims:
  - `String? get contactId => _map['contact_id'] as String?;`
  - `String? get tenantId => _map['tenant_id'] as String?;`
  - `String? get partitionId => _map['partition_id'] as String?;`
  - `Map<String, dynamic> get customClaims;` — escape hatch returning the raw map minus the standard OIDC claims, for apps that have their own bespoke claims.
- `AuthRuntime.getUserClaims(): Future<UserClaims>` — new method returning the typed wrapper. `getClaims()` stays, returns raw map.
- Riverpod: `userClaimsProvider` already exists; document the typed getters.

**Tests:** unit tests for each getter with standard Hydra token shapes.

### A.3 Background-task friendly construction

**Motivation:** chat's `SharedTokenService` uses a standalone `AuthService` inside WorkManager tasks (no Riverpod / UI Isolate context).

**Spec:**

- `createAuthRuntime(cfg)` already works without Riverpod (factory is standalone). Verify + document.
- Add `AuthRuntime.isAuthenticated` synchronous getter for background task pre-check (avoids unnecessary work if the user is signed out).
- Document the pattern:
  ```dart
  // In a WorkManager task:
  final runtime = createAuthRuntime(kBackgroundAuthConfig);
  if (!runtime.isAuthenticated) { runtime.dispose(); return; }
  final response = await runtime.fetch('/v1/sync', method: 'POST');
  await runtime.dispose();
  ```
- Add warning in the README about NOT sharing runtime instances across isolates — each isolate constructs + disposes its own.

**No new code beyond the `isAuthenticated` getter.** Mostly documentation.

### A.4 Release

`v0.3.0` stacked on v0.2 or post-merge of v0.2. Additive across the board.

---

## 3. Track B — v1.1 Web target (pure Dart)

### B.1 Decision: implementation approach

Two options considered:

- **(a) Wrap `@stawi/auth-runtime` (JS)** via `dart:js_interop` + `package:web`.
- **(b) Pure-Dart Web implementation** using `dart:js_interop` only for browser primitives (`crypto.subtle`, `IndexedDB`, `Worker`).

**Chosen: (b).**

Rationale:

- **Long-term durability.** Flutter Web via Wasm is a Google strategic investment; pure Dart code compiles to both JS and Wasm. Wrapping an npm package ties us to JS-only and adds cross-boundary serialization overhead.
- **Single source of truth.** Mobile + Desktop + Web all share the same `antinvestor_auth_runtime` Dart codebase. Bug fixes land once.
- **Smaller bundle.** No separate JS runtime loaded; tree-shaking eliminates unused paths.
- **Non-deprecated APIs.** Uses `dart:js_interop` (stable since Dart 3.2) + `package:web` (replaces deprecated `dart:html`) exclusively. Never uses `dart:js`, `dart:js_util`, `package:js`, `dart:html`, or `package:html`.
- **FFI-style narrow interop.** Only `crypto.subtle`, `IndexedDB`, `Worker`, `BroadcastChannel`, `navigator.locks`, `FederatedCredential` touch JS-interop. The rest is pure Dart — DPoP proof builder, state machine, discovery, token exchange, API proxy, Riverpod providers, widgets — reused verbatim.

### B.2 Platform abstraction seams

v0.1 already has `KeyManager`, `TokenStore`, `KeyValueStore` abstractions. For Web, add:

```dart
// Per-platform implementations chosen at createAuthRuntime() via Platform probe.
abstract class RuntimePlatform {
  KeyManager buildKeyManager();
  KeyValueStore buildKeyValueStore(String namespace);
  WorkerBackend? buildWorkerBackend(ResolvedConfig cfg);  // null on non-Web; uses dedicated Web Worker on Web
  FederatedCredentialProvider? buildFederatedProvider(ResolvedConfig cfg);  // FedCM wrapper, Web-only
}
```

- `MobileRuntimePlatform` — existing v0.1 path (flutter_secure_storage + PointyCastle + Isolate).
- `DesktopRuntimePlatform` — same as Mobile, minus Isolate backend by default.
- **`WebRuntimePlatform`** — new:
  - `KeyManager`: uses `crypto.subtle` via `dart:js_interop` for non-extractable ECDSA P-256 (matches JS runtime's design exactly).
  - `KeyValueStore`: wraps IndexedDB via `package:web`.
  - `WorkerBackend`: dedicated Web Worker loading the runtime's web-worker entry point, bundled at build time.
  - `FederatedCredentialProvider`: FedCM wrapper (analogous to JS runtime's FedCM path) — silent + interactive + nonce binding + `preventSilentAccess` + `disconnect` on logout.

### B.3 Web-specific Dart files

```
ui/runtime/lib/src/web/
├── web_platform.dart                # exports WebRuntimePlatform
├── web_crypto.dart                  # JS-interop to crypto.subtle; non-extractable CryptoKey
├── web_storage.dart                 # JS-interop to IndexedDB (via package:web)
├── web_worker_backend.dart          # main-thread side of the dedicated Worker
├── web_worker_entry.dart            # compiles to a separate JS bundle for the Worker
├── web_fedcm.dart                   # IdentityCredential / FedCMOutcome — mirrors JS runtime's adaptive-FedCM design
└── web_broadcast.dart               # BroadcastChannel + navigator.locks
```

Conditional import pattern:

```dart
// ui/runtime/lib/src/platform.dart
export 'mobile/mobile_platform.dart'
    if (dart.library.js_interop) 'web/web_platform.dart';
```

### B.4 Web-only capabilities

- **FedCM** adaptive: probes `/.well-known/web-identity`; if present, uses FedCM silent on mount (analogous to v0.2's native Apple/Google on mobile). `FedCMOutcome` shape mirrors JS runtime's.
- **Cross-tab coordination:** `BroadcastChannel` for logout propagation + `navigator.locks` for refresh serialization (available on Web; polyfilled on mobile for Isolate coordination).
- **Same-origin worker:** the worker's IndexedDB is same-origin with the embedder. Refresh token encrypted at rest by a non-extractable AES-GCM wrap key stored in IndexedDB (matches JS runtime).

### B.5 Non-extractable key enforcement

Critical: `crypto.subtle.generateKey(..., false, ...)` — the `false` is `extractable: false`. Web exposes this as `CryptoKey` objects that **cannot** be serialized to raw bytes. Verify at runtime via `assert(!key.extractable)` and throw `AuthError(cryptoUnsupported)` if the platform silently allows export.

### B.6 OAuth flow on Web

- On Web, `flutter_appauth` does not apply. Use `window.open(authUrl, ...)` synchronously from the user click to preserve gesture (same lesson as the JS runtime's popup fix).
- Callback page (static HTML hosted by the relying party) `postMessage`s the code back to the opener. Main thread forwards to the worker.
- Alternatively: same-page redirect flow (`window.location.href = authUrl`) with a dedicated callback route. Document both; default to popup for embedded widget scenarios.

### B.7 Tests

- Web-only tests require `flutter test --platform chrome`. Separate test file prefix (`web_*_test.dart`) gated by the `chrome` platform tag.
- Mock IdP for integration tests runs in a Dart VM test isolate; Web tests use `package:http` MockClient.

### B.8 Web target task breakdown (deferred plan)

Separate plan doc to be written after v0.3 ships. High-level:

1. Extract `RuntimePlatform` abstraction from v0.2.
2. Conditional-import wiring.
3. `web_crypto.dart` — non-extractable key gen + DPoP signing via `crypto.subtle.sign`.
4. `web_storage.dart` — IDB wrapper.
5. `web_fedcm.dart` — FedCM probe + silent/interactive attempts + nonce binding + disconnect.
6. `web_worker_*.dart` — dedicated Worker topology.
7. Integration tests.
8. Web sample app (embed in a Flutter Web demo).
9. README update.
10. v1.1.0 release.

Estimated scope: 10–15 commits.

---

## 4. Track C — Consumer migrations

### C.1 Migration pattern (reusable across apps)

1. **Add dependency** (path during feature branch, pub.dev version after release).
2. **Construct runtime** in `main.dart` before `runApp`:
   ```dart
   void main() async {
     WidgetsFlutterBinding.ensureInitialized();
     final runtime = createAuthRuntime(kAuthConfig);
     runApp(
       ProviderScope(
         overrides: [authRuntimeProvider.overrideWithValue(runtime)],
         child: MyApp(runtime: runtime),
       ),
     );
   }
   ```
3. **Delete legacy auth files**: `auth_service.dart`, `auth_repository.dart`, `token_refresh_coordinator.dart`, `shared_token_service.dart` (chat only).
4. **Replace interceptor**: point API clients at `runtime.fetch` instead of `AuthInterceptor` manually attaching headers.
5. **Migrate state provider**: `authStateProvider` now re-exports `authStateProvider` from the runtime package.
6. **Rewire login screen** to `SignInButton` (or keep custom UI and call `ensureAuthenticated`).
7. **Migrate route guards** to consume `authStateProvider`.
8. **Purge stored tokens on first run** (one-time migration): trigger sign-in afresh since the runtime uses a different secure-storage key layout.
9. **Update deep-link / URL scheme** in platform manifests to match `redirectScheme` in `AuthConfig`.
10. **Test suite** updated to mock `AuthRuntime` instead of `AuthService`.

### C.2 Per-app complexity and deltas

| App | Call sites | Complexity | Key deltas needed |
|---|---|---|---|
| service-chat | ~230 | HIGH | `contact_id` getter, WorkManager-safe construction, custom deep-link scheme preserved, dual-cache removed in favor of runtime-owned state |
| service-thesa | ~58 | MEDIUM | `audiences` in config, desktop-only loopback (already supported by `flutter_appauth`), mobile support added as free by-product |
| service-fintech | N/A | BLOCKED | Consolidate feature packages into a single Flutter app first (separate scoping exercise) |

### C.3 Separate plans

- `docs/superpowers/plans/2026-04-20-service-chat-migration.md`
- `docs/superpowers/plans/2026-04-20-service-thesa-migration.md`
- `docs/superpowers/plans/2026-04-20-service-fintech-consolidation.md` (sketch; actual migration gated on consolidation decision)

These live in the `service-authentication` repo because the auth contract owns the migration story; app-level repos pick them up.

---

## 5. Sequencing

```
v0.1 PR #640 → merge
    ↓
v0.2 PR #641 → rebase onto main → merge
    ↓
v0.3 PR (audiences + typed UserClaims + background-task doc) → merge
    ↓
service-chat migration PR → merge (validates v0.3 additions)
    ↓
service-thesa migration PR → merge (validates desktop path + audiences)
    ↓
v1.1 Web PR → merge
    ↓
service-thesa Web release (admin console)
    ↓
service-fintech consolidation → then migration
```

Each step validates the previous — no speculative work. Fintech is gated on a product decision outside this doc.

---

## 6. Open questions flagged for owners

1. **Hydra `audience` parameter syntax** — comma-separated vs repeated `audience=` per RFC 8707. Confirm before A.1 implementation. Owner: service-authentication Go team.
2. **Custom claim canonical names** — `contact_id`, `tenant_id`, `partition_id` — confirm the standardized set, since adding getters freezes the names. Owner: platform architecture.
3. **Fintech consolidation direction** — monorepo app with feature modules vs multi-app per feature. Owner: fintech product.
4. **Web callback-page hosting** — where is the static `auth-callback.html` served from in the Antinvestor stack? Reuse the one bundled in `@stawi/profile/dist/auth-callback.html`? Owner: platform.
5. **Rollout strategy per app** — big-bang replace vs run-alongside-then-switch. Owner: each app team.
