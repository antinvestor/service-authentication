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
// Do not wrap all of LoginEndpointShow in a single parent timeout — skip and
// remember-me need different ceilings than form render.
const (
	loginFormBudget         = 450 * time.Millisecond
	loginHydraTimeout       = 150 * time.Millisecond
	loginSoftTenancyBudget  = 80 * time.Millisecond
	loginHydraAdminTimeout  = 50 * time.Millisecond
	loginTenancySoftTimeout = 40 * time.Millisecond
	loginCacheTimeout       = 50 * time.Millisecond

	rememberMeSoftBudget = 200 * time.Millisecond
	skipLoginBudget      = 800 * time.Millisecond

	verifyStrongBudget = 2 * time.Second
	// Parent budget for consent. Sub-budgets must fit under this parent.
	consentStrongBudget       = 3 * time.Second
	consentHydraTimeout       = 150 * time.Millisecond
	consentOAuthClientTimeout = 800 * time.Millisecond
	consentDeviceTimeout      = 500 * time.Millisecond
	// Single budget for the entire ensureLoginEventTenancyAccess call tree
	// (getOAuthClient + getPartition + access list/create — NOT 1s per RPC).
	strongTenancyTotalTimeout = 1 * time.Second

	saWebhookColdBudget   = 200 * time.Millisecond
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
