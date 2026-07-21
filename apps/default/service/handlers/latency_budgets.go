// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import "time"

// Per-branch latency budgets for interactive login and SA webhooks.
// See docs/superpowers/specs/2026-07-21-subsecond-login-valkey-design.md.
//
// SLO: platform-controlled interactive paths aim for p99 < 1s wall clock.
// Budgets below are hard ceilings for in-process work (not including RTT to
// the browser or third-party IdPs like Google). Soft steps never hard-fail
// the OAuth challenge — they degrade and continue.
//
// Do not wrap all of LoginEndpointShow in a single parent timeout — skip and
// remember-me need different ceilings than form render.
const (
	// --- Login form (GET /s/login, non-skip) ---
	loginFormBudget         = 500 * time.Millisecond
	loginHydraTimeout       = 120 * time.Millisecond
	loginSoftTenancyBudget  = 80 * time.Millisecond
	loginHydraAdminTimeout  = 50 * time.Millisecond
	loginTenancySoftTimeout = 40 * time.Millisecond
	// Valkey can spike under cross-AZ / concurrent SET; detached from parent.
	loginCacheTimeout = 150 * time.Millisecond

	// --- Session skip / remember-me ---
	rememberMeSoftBudget = 200 * time.Millisecond
	// Session skip (Hydra Skip=true): soft-fail into form on any error.
	skipLoginBudget       = 800 * time.Millisecond
	skipDeviceSoftTimeout = 150 * time.Millisecond
	skipLoginDBTimeout    = 250 * time.Millisecond

	// --- Contact submit (POST /s/login/{id}/post) ---
	// Profile GetByContact / CreateContact / CreateContactVerification.
	// OTP delivery may be async; keep the HTTP path under 1s p99.
	loginSubmitBudget         = 900 * time.Millisecond
	loginSubmitProfileTimeout = 400 * time.Millisecond
	loginSubmitVerifyTimeout  = 500 * time.Millisecond

	// --- Verification complete (OTP submit) ---
	// Profile CheckVerification + Hydra accept; must stay under 1s p99.
	verifyStrongBudget = 900 * time.Millisecond
	// --- Hydra admin / sign webhook ---
	// Transport-level ceiling for Hydra admin HTTP client (defence in depth).
	hydraAdminHTTPTimeout = 2 * time.Second
	// Process-local parsed private key cache. Survives short Hydra admin blips
	// without putting key material in Valkey. Hydra key rotation is rare.
	// Warm private_key_jwt path is pure CPU (≪ 150ms) after the key is cached.
	jwkSigningCacheTTL = 10 * time.Minute
	// Cold JWKS fetch (cache miss / post-deploy). Detached so a slow Hydra
	// admin does not inherit a spent parent request deadline.
	jwkFetchTimeout = 1500 * time.Millisecond

	// --- Token / discovery facade (public /oauth2/token proxy) ---
	// Fail fast under the edge kill so clients retry instead of hanging 15s.
	facadeUpstreamTimeout = 2 * time.Second

	// --- Consent (GET /s/consent) ---
	consentStrongBudget       = 900 * time.Millisecond
	consentHydraTimeout       = 120 * time.Millisecond
	consentOAuthClientTimeout = 350 * time.Millisecond
	consentDeviceTimeout      = 200 * time.Millisecond
	// Entire ensureLoginEventTenancyAccess call tree (not per-RPC).
	strongTenancyTotalTimeout = 500 * time.Millisecond

	// --- Logout (GET /s/logout) ---
	logoutBudget       = 800 * time.Millisecond
	logoutHydraTimeout = 200 * time.Millisecond

	// --- SA token webhook (Hydra hook) ---
	saWebhookColdBudget   = 200 * time.Millisecond
	saClaimsCacheTTL      = 10 * time.Minute
	saNegativeCacheTTL    = 2 * time.Second
	oauthClientTenancyTTL = 15 * time.Minute

	// --- FedCM id-assertion (headless Hydra flow) ---
	// Multi-hop server-side OAuth; keep under edge kill with room for Hydra.
	fedcmAssertionBudget     = 4 * time.Second
	fedcmHeadlessHTTPTimeout = 3 * time.Second
	fedcmTenancySoftTimeout  = 400 * time.Millisecond
	fedcmHydraClientTimeout  = 200 * time.Millisecond

	// --- Social / OIDC provider callback ---
	// External Google token exchange is not under our p99 SLO; internal work
	// after Google returns is capped so the total stays under the ~15s edge kill.
	socialCallbackBudget        = 5 * time.Second
	socialGoogleExchangeTimeout = 2500 * time.Millisecond
	socialProfileLookupTimeout  = 800 * time.Millisecond
	socialProfileCreateTimeout  = 800 * time.Millisecond
	socialStoreLoginTimeout     = 400 * time.Millisecond
	socialHydraAcceptTimeout    = 300 * time.Millisecond
	socialStrongTenancyTimeout  = 500 * time.Millisecond
)

// NATS JetStream KV-safe cache key prefixes (charset: [-/_=.a-zA-Z0-9], no colon).
// Same shapes work on memory, NATS, and Valkey so CACHE_URI rollback stays viable.
const (
	loginEventCachePrefix    = "auth_login_event_"
	rateLimitCachePrefix     = "auth_login_rl_"
	fedcmExchangePrefix      = "auth_fedcm_exchange_"
	saClaimsCachePrefix      = "auth_sa_claims_"
	saClaimsNegCachePrefix   = "auth_sa_claims_neg_"
	oauthClientTenancyPrefix = "auth_oauth_client_tenancy_"
)
