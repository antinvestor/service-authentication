# Mobile/Web One Tap and MFA Implementation Plan

## Goal

Make authentication feel immediate for end users while keeping Hydra as the
only issuer of Antinvestor access, refresh, and ID tokens.

The user-facing target is:

1. Returning mobile users open the app and are signed in automatically when a
   safe platform credential is available.
2. New mobile users see the platform-native Google or Apple sheet before any
   browser flow.
3. Flutter web users reach the current hosted login page, where first-party
   FedCM and Google One Tap/FedCM are attempted before contact-code login.
4. Users can enable account-level MFA from an account security screen.
5. MFA does not add friction on every login: a verified trusted device can
   skip repeated MFA until risk or expiry requires step-up.

## Assumptions

- "One Tap" is Google terminology. Android uses Google Sign-In through
  Credential Manager / `google_sign_in`; web uses Google Identity Services
  with FedCM. Apple uses Sign in with Apple through the native Apple sheet,
  which requires an explicit user action.
- Google and Apple ID tokens are identity proofs only. They are never accepted
  as Antinvestor API bearer tokens.
- The public OAuth issuer remains the same user-facing origin. Hydra remains
  the authoritative issuer, but the auth service may front `/oauth2/token` to
  handle native credential token exchange and proxy all other grants to Hydra.
- Account-managed MFA is separate from the existing contact-code login flow.
  The current contact OTP path can remain as login bootstrap/recovery, but the
  new primary MFA methods are passkeys/WebAuthn and TOTP.

## Current State

Already present:

- Flutter runtime native providers:
  - `ui/runtime/lib/src/credentials/google_credential_provider.dart`
  - `ui/runtime/lib/src/credentials/apple_credential_provider.dart`
- Runtime native credential exchange call:
  - `ui/runtime/lib/src/protocol/token_exchange.dart`
  - posts RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange`
- Login page Google FedCM completion:
  - `apps/default/service/handlers/login_step_2_google_fedcm.go`
- First-party FedCM IdP and one-shot token stash:
  - `apps/default/service/handlers/fedcm_assertion.go`
  - `apps/default/service/handlers/fedcm_token_exchange.go`
- Shared user token claims:
  - `apps/default/service/handlers/login_step_4_consent.go`
  - `BuildUserTokenClaims`

Missing:

- Backend handling for provider ID token to Hydra token exchange.
- Provider-scoped external identity linking (`google:<sub>`, `apple:<sub>`).
- Mobile-native device enrollment without relying on browser cookies.
- Account-level MFA factor enrollment, verification, recovery, and trusted
  device policy.
- Flutter/runtime account security UI and typed APIs for MFA settings.

## Hydra Compatibility Audit

The existing browser login paths already fit Hydra's login/consent contract:

- Google FedCM on `/s/login` completes through `completeProviderLogin`, then
  calls `AcceptLoginRequest`; consent and token issuance remain Hydra-owned.
- First-party FedCM already runs a server-side authorization-code flow with the
  `fedcm.HeadlessDriver` and exchanges the code at Hydra's `/oauth2/token`.
- Hydra client provisioning defaults partition-owned OAuth clients to
  `authorization_code` plus `refresh_token`, and current seeds include the
  internal FedCM callback redirect URI.

The mobile-native path is not yet Hydra-compatible as implemented:

- `TokenExchange.exchangeIdToken` posts the RFC 8693 grant to the discovered
  `token_endpoint`.
- `SetupRouterV1` does not currently register `/oauth2/token` in the auth
  service, so discovery/gateway routing would send the native exchange directly
  to Hydra.
- The auth service docs already mark native credential backend support as
  future enablement.

Required Hydra-safe decisions:

- Keep Hydra as the only token issuer, but put an auth-service facade in front
  of the public `/oauth2/token` endpoint.
- Publish discovery metadata whose `token_endpoint` points at that facade.
- The facade must proxy ordinary grants to Hydra unchanged and handle only the
  native provider-token exchange itself.
- The facade's internal Hydra URL must be a separate private/public Hydra
  service URL, not the external issuer URL, or proxying and headless exchanges
  can loop back into the facade.
- Do not require Hydra to support
  `urn:ietf:params:oauth:grant-type:token-exchange` for this rollout unless a
  specific deployed Hydra version is verified to accept it. Use the tenancy
  `native_auth_enabled` property as the auth-service policy gate.
- Enforce the internal FedCM callback redirect URI for every user-facing
  authorization-code client during client sync, not only in seed migrations.
- Keep `offline_access` and `refresh_token` enabled for mobile clients so the
  returned Hydra refresh token works with the existing runtime refresh path.
- Before production, harden `/fedcm/token-exchange` to bind the one-shot stash
  to the requesting origin/client and a verifier, matching the earlier FedCM
  design instead of relying only on `hash(id_token)`.
- Native exchange and first-party FedCM should create or reuse a durable
  `LoginEvent` and call `BuildUserTokenClaims` rather than hand-building token
  extras. This keeps refresh-token webhook enrichment and browser-issued token
  shape identical.
- MFA must complete before `AcceptLoginRequest` or the headless Hydra token
  issuance. A token already minted by Hydra cannot be made "MFA complete" after
  the fact.

## Architecture

### Interaction Plane

- Flutter runtime signs users in through this waterfall:
  1. Existing stored Antinvestor session.
  2. Native silent provider attempts.
  3. Native interactive provider attempts.
  4. OAuth browser fallback.
- Hosted web login page signs users in through this waterfall:
  1. Hydra skip/remembered login.
  2. First-party FedCM from `idp_session`.
  3. Google One Tap/FedCM.
  4. Sign in with Apple button.
  5. Contact-code fallback.
- Account security UI exposes:
  - MFA status.
  - Add passkey.
  - Add authenticator app.
  - View/regenerate recovery codes.
  - Remove factor after step-up.
  - Trusted devices.

### Control Plane

Provider and MFA policy is resolved per OAuth client:

- `native_auth_enabled`
- `mfa_policy`: `optional`, `required`, or `risk_based`
- `mfa_trusted_device_ttl_days`
- `mfa_required_for_roles`

Store the native-auth opt-in on tenancy client properties so rollout is per
application without hard-coding OAuth client IDs in the auth service. Google
audience verification uses the auth service's configured server Google client
ID by default, so a client only needs `native_auth_enabled=true` unless it
intentionally overrides provider audience policy.

### Execution Plane

- Add a token endpoint facade in the auth service:
  - `POST /oauth2/token`
  - For `authorization_code`, `refresh_token`, and `client_credentials`, proxy
    the request to Hydra unchanged.
  - For `urn:ietf:params:oauth:grant-type:token-exchange`, verify the external
    subject token, run the same profile/login-event/claim path as browser
    login, drive Hydra headlessly, and return Hydra's token response.
  - The public OIDC discovery document must advertise this facade as
    `token_endpoint`; the facade must call a separately configured internal
    Hydra public URL for proxying and headless authorization-code exchange.
- Add an MFA gate called before:
  - `AcceptLoginRequest` in web/provider/contact flows.
  - headless Hydra issuance in native token exchange.
  - first-party FedCM assertion issuance.

### Data Plane

New auth-service-owned tables:

- `external_identities`
  - `id`
  - `tenant_id`
  - `partition_id`
  - `profile_id`
  - `provider` (`google`, `apple`)
  - `provider_subject`
  - `email_at_link`
  - `email_verified`
  - `last_seen_at`
  - unique `(provider, provider_subject)`

- `mfa_factors`
  - `id`
  - `profile_id`
  - `kind` (`webauthn`, `totp`)
  - `display_name`
  - `status` (`pending`, `active`, `revoked`)
  - `secret_ciphertext` for TOTP only
  - `webauthn_credential_id`
  - `webauthn_public_key`
  - `webauthn_sign_count`
  - `webauthn_transports`
  - `backup_eligible`
  - `last_used_at`
  - `created_by_login_event_id`

- `mfa_recovery_codes`
  - `id`
  - `profile_id`
  - `code_hash`
  - `used_at`

- `mfa_challenges`
  - `id`
  - `profile_id`
  - `login_event_id`
  - `client_id`
  - `purpose` (`login`, `settings_step_up`, `factor_enrollment`)
  - `allowed_methods`
  - `expires_at`
  - `consumed_at`
  - `attempt_count`

- `trusted_devices`
  - `id`
  - `profile_id`
  - `client_id`
  - `device_id`
  - `mfa_factor_id`
  - `trusted_until`
  - `last_used_at`
  - unique `(profile_id, client_id, device_id)`

Existing `login_events.properties` records:

- `native_provider`
- `native_issuer`
- `native_subject_hash`
- `mfa_required`
- `mfa_verified`
- `mfa_method`
- `mfa_factor_id`
- `trusted_device_used`

## Performance and Capacity Model

The headless Hydra authorization-code flow is not CPU-heavy, but it is more
round-trip and database intensive than a direct token grant. It must only run
when a new Antinvestor session is created from a Google, Apple, or first-party
FedCM identity proof. It must not run for normal API calls, access-token
refresh, or app-start checks when a valid Antinvestor session already exists.

Expected backend work per successful native exchange:

1. Verify the provider ID token.
2. Resolve or link the external identity and profile.
3. Resolve device, tenancy access, and roles.
4. Create or update a `LoginEvent`.
5. Start Hydra `/oauth2/auth`.
6. Accept Hydra login through the admin API.
7. Accept Hydra consent through the admin API.
8. Exchange the authorization code at Hydra `/oauth2/token`.

Operational targets:

- Cached JWKS verification should be local CPU plus cache lookup; remote JWKS
  fetches happen only on cache miss or key rotation.
- Internal Hydra calls should use pooled HTTP clients, short timeouts, and the
  internal Hydra public URL.
- Target P50 server-side exchange latency: under 300 ms after the provider ID
  token is already available.
- Target P95 server-side exchange latency: under 1.5 s in staging under normal
  load.
- A failed Hydra leg should return a clear OAuth error and fall back to browser
  OAuth on mobile unless policy requires blocking, such as `mfa_required`.
- Refresh-token calls stay on the normal Hydra refresh path and should not
  re-run provider verification or headless login.

Concurrency controls:

- Use the existing cache-backed FedCM lock pattern for first-party FedCM:
  `fedcm:lock:<profile_id>:<client_id>`.
- Add an equivalent short-lived native-exchange lock:
  `native:exchange:<provider>:<provider_subject_hash>:<client_id>`.
- Lock TTL should be short, around 5-10 seconds, and lock contention should
  return a retryable error.
- Replay cache must reject reused provider tokens independently of locks.
- Rate limit per `client_id`, provider, and source IP before expensive JWKS,
  profile, and Hydra work.

Observability targets:

- Trace one parent span around the facade request.
- Add child spans for provider verification, profile linking, device/access
  resolution, MFA policy, Hydra authorize, accept login, accept consent, and
  Hydra token exchange.
- Emit counters for success, policy block, provider-token failure, Hydra
  failure, MFA-required, replay, and rate-limit outcomes.
- Dashboards should break down latency by provider, platform, and client ID.

## Implementation To-do Checklist

### Backend Foundation

- [ ] Add auth-service `POST /oauth2/token` facade route.
- [ ] Add discovery/gateway routing so public discovery advertises the facade
      as `token_endpoint`.
- [x] Configure a separate internal Hydra public URL for facade upstream calls.
- [x] Proxy `authorization_code`, `refresh_token`, and `client_credentials`
      grants to Hydra without changing the request body or authentication
      semantics.
- [ ] Add integration tests that prove normal OAuth grants still work through
      the facade.

### Native Provider Exchange

- [x] Add `nativecredentials` package with issuer registry, JWKS cache, ID
      token verifier, replay cache, profile linker, and exchange coordinator.
- [x] Add `external_identities` model, repository, and migration.
- [x] Add per-client `native_auth_enabled` policy; provider audiences come
      from server-side authentication provider configuration.
- [x] Verify Google `iss`, `aud`, `exp`, `iat`, signature, and replay state.
- [x] Verify Apple `iss`, `aud`, `exp`, `iat`, signature, and replay state.
- [x] Resolve or create profile only from verified provider identity.
- [x] Link external identity using provider-scoped subject keys.
- [x] Create or reuse a durable `LoginEvent` before Hydra issuance.
- [x] Resolve access and roles with the same helpers used by browser consent.
- [x] Call `BuildUserTokenClaims` for every native-issued token.
- [x] Drive Hydra through the existing headless authorization-code driver.
- [x] Return Hydra's token response unchanged.

### Hydra Client Provisioning

- [x] Ensure every user-facing authorization-code client includes the internal
      callback URI `<FEDCM_PUBLIC_ORIGIN>/_internal/fedcm-callback`.
- [ ] Ensure mobile clients have `authorization_code`, `refresh_token`, `code`,
      and `offline_access`.
- [ ] Add startup or sync-time validation for missing callback URI, missing
      refresh grant, missing scope, and missing native provider audience.
- [ ] Do not require Hydra client `grant_types` to include RFC 8693 in facade
      mode.

### Flutter Runtime and Mobile UX

- [x] Extend native ID-token exchange form with `installation_id`, `platform`,
      and `device_name`.
- [ ] Add a high-level `NativeCredentialConfig` helper for Google/Apple setup.
- [ ] Attempt stored Antinvestor session first.
- [ ] Attempt silent Google only when no valid Antinvestor session exists.
- [ ] Attempt interactive Google or Apple only after user sign-in intent.
- [ ] Treat cancel/unavailable/no-session as normal fallback, not visible
      errors.
- [ ] Add typed handling for `mfa_required`.
- [ ] Keep browser OAuth fallback available for all native provider failures
      except explicit policy blocks.

### Web One Tap and FedCM

- [ ] Keep `/s/login` as the Flutter web credential broker.
- [ ] Keep Google FedCM completion on the hosted login page.
- [ ] Add Apple web button when Apple provider config is present.
- [x] Harden `/fedcm/token-exchange` with origin/client/verifier binding.
- [ ] Rework first-party FedCM token extras to use `BuildUserTokenClaims`.
- [ ] Ensure first-party FedCM creates or reuses a durable `LoginEvent`.

### MFA

- [ ] Add MFA factor, challenge, recovery-code, and trusted-device models.
- [ ] Add repositories and migrations.
- [ ] Add RPCs for MFA status, enrollment, removal, recovery codes, and trusted
      device management.
- [ ] Add browser MFA challenge endpoints before Hydra login acceptance.
- [ ] Add native MFA challenge creation before headless Hydra issuance.
- [ ] Add runtime `completeMfaChallenge`.
- [ ] Set Hydra `acr` and `amr` only after MFA has actually completed.
- [ ] Add trusted-device policy with expiry, revocation, and audit events.

### Verification and Rollout

- [ ] Add unit tests for provider verification, replay, identity linking, MFA
      policy, and trusted-device expiry.
- [ ] Add Hydra integration tests for facade proxying, native exchange, MFA
      challenge/resume, refresh preservation, and normal login regressions.
- [ ] Add Flutter tests for native provider waterfall and MFA-required state.
- [ ] Add staging smoke tests on Android, iOS, Chrome desktop/mobile, and
      Safari fallback.
- [ ] Roll out behind `native_auth_enabled=false` by default.
- [ ] Enable one staging client, then one production client at a time.
- [ ] Turn on required MFA only after recovery and support flows are proven.

## Implementation Phases

### Phase 1: Native Credential Token Exchange Backend

Add:

- `apps/default/service/handlers/oauth_token_facade.go`
- `apps/default/service/nativecredentials/`
  - `exchange.go`
  - `issuer_registry.go`
  - `id_token_verifier.go`
  - `profile_linker.go`
  - `device_context.go`
- `apps/default/service/models/external_identity.go`
- `apps/default/service/repository/external_identity.go`
- migration for `external_identities`
- gateway/discovery change so public `/.well-known/openid-configuration`
  advertises the auth-service facade as `token_endpoint`
- config:
  - `OAUTH2_HYDRA_PUBLIC_INTERNAL_URL` for facade-to-Hydra proxying
  - `NATIVE_CREDENTIAL_EXCHANGE_ENABLED` as a default-on deployment kill switch
  - per-client `native_auth_enabled` policy property
  - `AUTH_PROVIDER_GOOGLE_CLIENT_ID` as the Google ID-token audience

Do not add the RFC 8693 grant to Hydra client `grant_types` as a hard
requirement in facade mode. The auth service authorizes the native grant before
Hydra sees it; Hydra receives only the headless `authorization_code` exchange.

Request accepted by the facade:

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
client_id=<antinvestor-client-id>
subject_token=<google-or-apple-id-token>
subject_token_type=urn:ietf:params:oauth:token-type:id_token
subject_issuer=https://accounts.google.com
audience=<optional downstream audience>
installation_id=<runtime installation id>
platform=android|ios|web
device_name=<optional human label>
```

Validation:

- `client_id` resolves to an active tenancy client row.
- Native auth is enabled for that client row.
- `subject_issuer` is supported and has a configured audience. Google uses
  `AUTH_PROVIDER_GOOGLE_CLIENT_ID` by default.
- ID token signature validates against issuer JWKS.
- `iss`, `aud`, `exp`, and `iat` are valid.
- Token freshness window is 5 minutes plus skew.
- Google accepts `https://accounts.google.com` and `accounts.google.com`.
- Apple accepts `https://appleid.apple.com`.
- Nonce was already checked in the runtime, but the server also rejects
  missing nonce when the provider should return one.
- Replay cache rejects duplicate `(issuer, subject, iat, jwt-id-or-hash)`.
- Per-client/per-IP rate limit is enforced.

Exchange:

1. Resolve provider identity by `(provider, sub)`.
2. If found, use linked `profile_id`.
3. If not found and verified email/contact exists, resolve or create profile.
4. Link `(provider, sub)` to the profile.
5. Enroll or update the mobile device using `installation_id` and user agent.
6. Create a `LoginEvent` with source `google` or `apple`.
7. Resolve tenancy access and roles using existing helpers.
8. Run MFA gate.
9. If MFA is satisfied, run the existing headless Hydra driver with
   `BuildUserTokenClaims`.
10. Return Hydra's token response unchanged.

Hydra client prerequisites:

- `authorization_code` and `refresh_token` grant types.
- `code` response type.
- `openid profile email offline_access` scopes, with additional application
  scopes as needed.
- Internal callback URI:
  `<FEDCM_PUBLIC_ORIGIN>/_internal/fedcm-callback`.
- Client secret retrievable by the auth service for confidential clients.

Acceptance criteria:

- Android Google native sign-in returns Antinvestor access/refresh/ID tokens.
- iOS Sign in with Apple returns Antinvestor access/refresh/ID tokens.
- Returned access token contains normal `tenant_id`, `partition_id`,
  `access_id`, `profile_id`, `device_id`, `session_id`, and `roles`.
- Refresh works through existing refresh grant.
- Logout/revocation works through existing runtime code.
- A forged, stale, wrong-audience, or replayed provider token is rejected.

### Phase 2: Flutter Runtime Mobile UX

Keep `createAuthRuntime` as the single app integration point, but make native
credential setup harder to misconfigure.

Changes:

- Add `NativeCredentialConfig`:
  - `googleServerClientId`
  - `enableApple`
  - `providerOrder`
  - `preferSilent`
- Add a helper:

```dart
final runtime = createAuthRuntime(
  cfg,
  nativeCredentialConfig: NativeCredentialConfig(
    googleServerClientId: googleServerClientId,
    enableApple: Platform.isIOS || Platform.isMacOS,
  ),
);
```

- Keep the existing lower-level `nativeProviders` override for tests and
  custom apps.
- Extend `TokenExchange.exchangeIdToken` to include:
  - `installation_id`
  - `platform`
  - `device_name`
- On Android:
  - silent Google attempt on app start.
  - interactive Google sheet on user sign-in tap.
- On iOS:
  - show Sign in with Apple as the first native option.
  - optionally show Google as second option if configured.
- On all mobile:
  - if provider returns `NoSession`, `Cancelled`, or `Unavailable`, fall back
    without showing technical errors.
  - if provider exchange fails server-side, continue to browser OAuth fallback
    unless the error is a policy block such as MFA required.

Acceptance criteria:

- App launch with a valid stored session shows authenticated state without UI.
- App launch with Google silent credential signs in without browser.
- User tap opens native sheet and returns authenticated state.
- User cancel falls back to the normal sign-in screen without losing state.
- Native exchange failure is observable in `credentialEventStream`.

### Phase 3: Web One Tap and Flutter Web UX

Use the hosted auth service login page as the web credential broker. This keeps
Flutter web simple and avoids putting provider-specific JavaScript inside every
consumer app.

Changes:

- Keep `/s/login` rendering:
  - `FedCMNonce`
  - `GoogleClientID`
  - existing `fedcm_google.js`
- Add Sign in with Apple on the login page when
  `AUTH_PROVIDER_APPLE_CLIENT_ID` is set.
- Order login options visually:
  1. Existing remembered/FedCM session auto path.
  2. Google prompt/button.
  3. Apple button.
  4. Email/phone field.
- Do not block first paint waiting on FedCM/Google. Render the contact field
  immediately and let One Tap overlay when available.
- For Flutter web, keep `flutter_web_auth_2` redirect to `/s/login`; the login
  page handles One Tap and returns the normal authorization code.

Acceptance criteria:

- Chrome/FedCM users can sign in via Google prompt without typing contact.
- Non-FedCM browsers still show the hosted login page and contact fallback.
- Apple web button completes via existing provider callback.
- If One Tap is dismissed, the contact input remains usable immediately.

### Phase 4: Account-Managed MFA Backend

Add:

- `apps/default/service/models/mfa_factor.go`
- `apps/default/service/models/mfa_challenge.go`
- `apps/default/service/models/mfa_recovery_code.go`
- `apps/default/service/models/trusted_device.go`
- repositories for each model
- migrations for each table
- `apps/default/service/mfa/`
  - `policy.go`
  - `webauthn.go`
  - `totp.go`
  - `challenge.go`
  - `trusted_device.go`
  - `recovery.go`

Add AuthenticationService RPCs:

- `GetMFAStatus`
- `BeginWebAuthnEnrollment`
- `CompleteWebAuthnEnrollment`
- `BeginTOTPEnrollment`
- `CompleteTOTPEnrollment`
- `ListMFAFactors`
- `RemoveMFAFactor`
- `RegenerateRecoveryCodes`
- `ListTrustedDevices`
- `RevokeTrustedDevice`

Add login-step endpoints for browser flows:

- `GET /s/mfa/{challengeId}`
- `POST /s/mfa/{challengeId}/totp`
- `POST /s/mfa/{challengeId}/recovery`
- `POST /s/mfa/{challengeId}/webauthn/options`
- `POST /s/mfa/{challengeId}/webauthn/verify`

Add native token-exchange MFA response:

```json
{
  "error": "mfa_required",
  "mfa_challenge_id": "...",
  "available_methods": ["webauthn", "totp", "recovery"]
}
```

Then add a runtime method:

```dart
Future<void> completeMfaChallenge({
  required String challengeId,
  required MfaAssertion assertion,
});
```

MFA policy:

- Optional by default.
- Required when user enabled at least one active factor.
- Required for policy-marked clients/roles.
- Bypass if:
  - trusted device is valid,
  - device risk is low,
  - login method has recent high assurance,
  - no sensitive step-up is requested.

Claims added after MFA:

- `acr`: `urn:antinvestor:acr:mfa` or stronger
- `amr`: include identity method plus `otp` or `webauthn`
- token extras:
  - `mfa_verified: true`
  - `mfa_method`
  - `mfa_verified_at`

Acceptance criteria:

- A user can enroll a passkey and TOTP from account settings.
- A user receives recovery codes only after successful enrollment.
- Removing the last factor requires explicit confirmation and step-up.
- Login prompts for MFA when required and no trusted device exists.
- Successful MFA creates a trusted device if the user chooses that option.
- Trusted-device expiry triggers MFA again.

### Phase 5: Account Security UI

Update `ui/auth` to include an account security route:

- `SecurityOverviewScreen`
- `MFAStatusCard`
- `PasskeyFactorList`
- `TOTPEnrollmentSheet`
- `RecoveryCodesSheet`
- `TrustedDevicesList`

UX rules:

- Default recommendation is passkey because it is the fastest and most
  phishing-resistant.
- TOTP is offered as "Authenticator app" fallback.
- Recovery codes are shown once, with a clear "saved" confirmation.
- Never show raw TOTP secret again after enrollment.
- Avoid forcing MFA setup during first sign-in unless a client policy requires
  it. Instead, show a dismissible account-security prompt post-login.

Acceptance criteria:

- Users can understand current security state at a glance.
- Enrollment takes no more than:
  - passkey: one platform prompt after tapping "Add passkey"
  - TOTP: scan QR, enter one code, save recovery codes
- Login challenge screens are short and do not expose provider/security
  internals.

### Phase 6: Observability and Audit

Metrics:

- `auth.native_exchange.started`
- `auth.native_exchange.completed`
- `auth.native_exchange.failed`
- `auth.native_exchange.duration`
- `auth.mfa.challenge.created`
- `auth.mfa.challenge.completed`
- `auth.mfa.challenge.failed`
- `auth.mfa.factor.enrolled`
- `auth.mfa.factor.removed`
- `auth.mfa.trusted_device.used`

Required labels:

- `client_id`
- `provider`
- `platform`
- `reason`
- `mfa_method`
- `grant_type`

Audit/login event properties:

- provider used
- MFA challenge result
- trusted device decision
- failure reason category, never raw tokens or secrets

### Phase 7: Testing

Go unit tests:

- provider issuer registry
- Google token verifier with test JWKS
- Apple token verifier with test JWKS
- replay cache
- external identity linker
- MFA policy decisions
- TOTP verify window
- recovery code one-time use
- trusted device expiry

Go integration tests:

- discovery advertises the facade token endpoint
- facade proxies `authorization_code`, `refresh_token`, and
  `client_credentials` grants to Hydra
- facade uses the internal Hydra URL and cannot recursively call itself
- native Google exchange happy path
- native Apple exchange happy path
- wrong `aud`
- wrong `iss`
- stale token
- replayed token
- MFA required returns `mfa_required`
- MFA complete then exchange returns Hydra tokens
- token refresh preserves claims
- every mobile/FedCM token uses `BuildUserTokenClaims` claim shape
- client sync enforces the internal FedCM callback redirect URI
- `/fedcm/token-exchange` rejects wrong-origin, wrong-client, expired, and
  verifier-mismatched requests
- web Google FedCM regression
- contact-code regression
- service account regression

Flutter tests:

- native provider waterfall ordering
- silent Google success
- Apple interactive success
- cancel/fallback behavior
- native exchange form includes installation/platform metadata
- MFA-required response transitions into challenge state
- recovery from failed MFA

Manual staging tests:

- Android physical device with Google account.
- iOS physical device with Apple Account and Face ID/Touch ID.
- Chrome desktop with FedCM.
- Mobile Chrome with Google One Tap.
- Safari fallback with Apple button/contact-code path.

## Rollout

1. Deploy backend facade and native exchange behind client-property flag
   `native_auth_enabled=false`.
2. Enable for one staging mobile client.
3. Validate Android Google and iOS Apple physical-device flows.
4. Enable web login-page ordering changes in staging.
5. Enable optional MFA enrollment in staging.
6. Enable one production client at a time.
7. Turn on MFA-required policy only after recovery-code and support workflows
   are validated.

## Production Risks

1. Provider token audience misconfiguration.
   - Mitigation: per-client issuer registry, startup config validation, staging
     smoke test per client.

2. MFA lockout.
   - Mitigation: recovery codes, trusted-device display, support recovery path,
     and no forced setup until recovery path is live.

3. Token endpoint facade breaks normal OAuth grants.
   - Mitigation: facade proxies non-native grants byte-for-byte, integration
     tests cover auth code, refresh, and client credentials, and rollout starts
     on staging gateway only.

## Definition of Done

- Native Google and Apple login produce Hydra access/refresh/ID tokens through
  the Flutter runtime.
- Flutter web login reaches One Tap/FedCM before contact-code login.
- All issued tokens use the same claim shape as existing consent-issued tokens.
- Users can enroll, use, and recover from account-level MFA.
- Trusted-device behavior keeps daily login seamless without bypassing MFA
  policy.
- Observability distinguishes native provider failures, Hydra failures, and MFA
  failures.

## References

- Google Identity Services: One Tap returns a Google-signed JWT credential that
  must be verified server-side.
  https://developers.google.com/identity/gsi/web/guides/display-google-one-tap
- Google Android backend auth: mobile apps should send the ID token to the
  backend, which verifies signature, issuer, audience, and expiry before
  creating a session.
  https://developers.google.com/identity/sign-in/android/backend-auth
- Android Credential Manager Sign in with Google:
  https://developer.android.com/identity/sign-in/credential-manager-siwg-implementation
- Apple Sign in with Apple: native apps receive identity tokens and user info
  that the app server verifies.
  https://developer.apple.com/documentation/signinwithapple/authenticating-users-with-sign-in-with-apple
- Apple identity token guidance:
  https://developer.apple.com/documentation/signinwithapple/receiving-a-users-identity-token
- RFC 8693 OAuth 2.0 Token Exchange:
  https://www.rfc-editor.org/rfc/rfc8693
- Ory Hydra production guide: public port serves discovery, auth, token,
  revocation, logout, and userinfo; admin port must remain private.
  https://www.ory.com/docs/hydra/self-hosted/production
- Ory Hydra custom login and consent flow:
  https://www.ory.com/docs/hydra/guides/custom-ui-oauth2
- OWASP Multifactor Authentication Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- NIST SP 800-63B authentication guidance:
  https://pages.nist.gov/800-63-4/sp800-63b.html
