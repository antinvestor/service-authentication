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

// Outbound HTTP client timeouts — applied once when clients are constructed
// (NewAuthServer / provider setup). Handlers must not wrap every call in
// context.WithTimeout; they pass req.Context() and let the client deadline
// fire naturally (Frame default retry still applies).
//
// Soft-fail policy lives in handler control flow (optional steps log +
// continue), not in micro-budgets.
const (
	// Hydra admin API (login/consent accept, clients, JWKS).
	hydraAdminHTTPTimeout = 2 * time.Second
	// Hydra public used by FedCM headless multi-hop auth.
	hydraPublicHTTPTimeout = 2 * time.Second
	// Token facade proxies /oauth2/token which runs Hydra + enrich webhooks.
	// That path is multi-hop by design; 2s was aborting healthy mints under load.
	hydraTokenHTTPTimeout = 10 * time.Second

	// Process-local JWKS private-key cache (not an I/O budget).
	jwkSigningCacheTTL = 10 * time.Minute

	// Shared cache TTLs for SA claims / OAuth client→tenancy map.
	saClaimsCacheTTL      = 10 * time.Minute
	saNegativeCacheTTL    = 2 * time.Second
	oauthClientTenancyTTL = 15 * time.Minute
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
