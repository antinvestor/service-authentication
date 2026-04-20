# `service-fintech/ui` — consolidation (prerequisite to auth migration)

Status: sketch / planning only — implementation gated on product decision.
Date: 2026-04-20

## Observation

`service-fintech/ui/` has no consolidated Flutter app. The directory contains feature-specific packages (`funding/`, `identity/`, `loans/`, `operations/`, `savings/`, `seed/`, `stawi/`, `default/`) with no unifying `pubspec.yaml` at the top level.

This means "migrate fintech to `antinvestor_auth_runtime`" is ambiguous — which app? There is no app to migrate.

## Decision required

Before any auth migration plan for fintech can be written, product + engineering leadership must pick one of:

### Option A — Consolidate into a single Flutter app
- One `pubspec.yaml` at `service-fintech/ui/`.
- Feature packages become internal modules (`lib/features/{funding,identity,loans,...}`).
- Single auth runtime, single OAuth client, single deep-link scheme.
- **Auth migration scope after consolidation:** similar to service-chat (medium-to-high depending on total call sites).
- **Implication:** a shipping app can embed any feature without spawning multiple browser sessions for auth.

### Option B — Keep feature packages; ship multiple apps
- Each feature has its own app bundle + binary.
- Each app independently integrates the auth runtime.
- Multiple OAuth clients (one per app) registered with Hydra.
- **Auth migration scope:** N small migrations, each ~same size as service-thesa.
- **Implication:** users who want loans + savings install two apps and sign in twice. Unlikely acceptable UX.

### Option C — Shared auth across feature apps via native OS credential sharing
- Each feature ships as a separate app but they share credentials via:
  - iOS: Keychain Sharing groups (com.antinvestor.*.sharedKeychain).
  - Android: `android:sharedUserId` (deprecated) or custom ContentProvider.
- Runtime gains an `AuthConfig.keychainAccessGroup` parameter (iOS) / `sharedAccountType` (Android).
- **Auth migration scope:** N small migrations + one enhancement to the runtime for cross-app credential sharing.
- **Implication:** technically feasible but operationally complex; not recommended unless product has a hard split.

## Recommendation

Option A, strongly. It matches the pattern service-chat and service-thesa follow, simplifies the auth story, and aligns with how Antinvestor apps present to end users.

## Gated actions

Once the decision lands:

- If A: write `docs/superpowers/plans/YYYY-MM-DD-service-fintech-consolidation-then-migration.md` covering both the app consolidation and the subsequent auth migration. Treat as a major effort (scoping: 2–4 weeks).
- If B: write N migration plans, one per feature app.
- If C: first extend `antinvestor_auth_runtime` with credential-sharing support (v0.4+), then write migration plans.

## Open questions

1. Who owns the consolidation decision? (Likely fintech product + platform engineering.)
2. Is there a business reason the features are currently split? (Different deployment cadences? Regulatory separation?)
3. Are there existing plans for fintech UI that this doc is missing?

Until answered, no implementation work should start on fintech migration.
