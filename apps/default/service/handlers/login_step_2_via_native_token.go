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

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/handlers/providers"
	"github.com/pitabwire/util"
)

type nativeTokenRequest struct {
	Provider string `json:"provider"`
	IDToken  string `json:"id_token"`
}

type nativeTokenResponse struct {
	RedirectURL string `json:"redirect_url"`
}

// NativeTokenLoginEndpoint handles mobile native social login by verifying
// an externally-obtained token (ID token or access token from a mobile SDK)
// and completing the Hydra login flow. This is the primary login path for
// mobile apps that use native provider SDKs (Google Sign-In, Sign in with
// Apple, Facebook Login SDK, MSAL).
//
// POST /s/social/native/{loginEventId}
// Body: { "provider": "google", "id_token": "<raw token from SDK>" }
// Response: { "redirect_url": "https://..." }
func (h *AuthServer) NativeTokenLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx)

	loginEventID := req.PathValue(pathValueLoginEventID)
	log = log.WithField("login_event_id", loginEventID)

	// Step 1: Decode and validate the JSON request body
	var tokenReq nativeTokenRequest
	if err := json.NewDecoder(req.Body).Decode(&tokenReq); err != nil {
		log.WithError(err).Warn("failed to decode native token request body")
		return fmt.Errorf("invalid request body: %w", err)
	}

	if tokenReq.Provider == "" {
		log.Warn("native token request missing provider")
		return fmt.Errorf("provider is required")
	}

	if tokenReq.IDToken == "" {
		log.Warn("native token request missing id_token")
		return fmt.Errorf("id_token is required")
	}

	log = log.WithField("provider", tokenReq.Provider)

	// Step 2: Rate limit check
	ipAddr := util.GetIP(req)
	rateLimitResult := h.CheckLoginRateLimit(ctx, ipAddr)
	if !rateLimitResult.Allowed {
		log.WithFields(map[string]any{
			"attempts_used":   rateLimitResult.AttemptsUsed,
			"retry_after_sec": rateLimitResult.RetryAfterSec,
		}).Warn("native token login rate limit exceeded")
		return fmt.Errorf("too many login attempts, please try again later")
	}

	// Step 3: Look up the provider and check it supports native token verification
	authProvider, ok := h.loginAuthProviders[tokenReq.Provider]
	if !ok {
		log.Warn("native token request for unknown provider")
		return fmt.Errorf("unknown login provider: %s", tokenReq.Provider)
	}

	verifier, ok := authProvider.(providers.NativeTokenVerifier)
	if !ok {
		log.Warn("provider does not support native token verification")
		return fmt.Errorf("provider %s does not support native token login", tokenReq.Provider)
	}

	// Step 4: Verify the token with the provider
	log.Debug("verifying native token with provider")

	user, err := verifier.VerifyNativeToken(ctx, tokenReq.IDToken)
	if err != nil {
		log.WithError(err).Error("native token verification failed")
		return fmt.Errorf("token verification failed: %w", err)
	}

	log.WithField("has_contact", user.Contact != "").
		Debug("native token verification successful")

	// Step 5: Retrieve login event from cache
	loginEvt, err := h.getLoginEventFromCache(ctx, loginEventID)
	if err != nil {
		log.WithError(err).Error("login event not found in cache for native token login")
		return fmt.Errorf("login session not found: %w", err)
	}

	// Step 6: Enrich login event with partition/tenant info if not already set
	if loginEvt.TenantID == "" || loginEvt.PartitionID == "" {
		h.updateTenancyForLoginEvent(ctx, loginEventID)

		loginEvt, err = h.getLoginEventFromCache(ctx, loginEventID)
		if err != nil {
			log.WithError(err).Error("failed to reload login event after tenancy enrichment")
			return fmt.Errorf("login session not found: %w", err)
		}

		if loginEvt.TenantID == "" || loginEvt.PartitionID == "" {
			log.WithField("client_id", loginEvt.ClientID).
				Error("login event still missing tenancy info after enrichment")
			return fmt.Errorf("unable to resolve tenancy for login session")
		}
	}

	ctx = util.SetTenancy(ctx, loginEvt)

	// Step 7: Complete the provider login flow (profile, login attempt, Hydra accept)
	redirectURL, err := h.completeProviderLogin(ctx, loginEvt, user, tokenReq.Provider)
	if err != nil {
		return err
	}

	// Step 8: Return JSON response with redirect URL
	rw.Header().Set("Content-Type", "application/json")

	log.WithFields(map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
	}).Info("native token login completed successfully")

	return json.NewEncoder(rw).Encode(&nativeTokenResponse{
		RedirectURL: redirectURL,
	})
}
