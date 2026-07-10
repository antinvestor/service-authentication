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
	"strings"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers/providers"
	"github.com/pitabwire/util"
)

const (
	loginSessionProviderAuth = "l_provider_sess"
)

// setupLoginOptions configures which login methods are enabled for the login page template.
func (h *AuthServer) setupLoginOptions(cfg *config.AuthenticationConfig) {

	h.loginOptions = map[string]any{"enableContactLogin": !cfg.AuthProviderContactLoginDisabled}

	if cfg.GoogleLoginConfigured() {
		h.loginOptions["enableGoogleLogin"] = true
	}

	if cfg.AuthProviderMetaClientID != "" {
		h.loginOptions["enableFacebookLogin"] = true
	}

	if cfg.AuthProviderAppleClientID != "" {
		h.loginOptions["enableAppleLogin"] = true
	}

	if cfg.AuthProviderMicrosoftClientID != "" {
		h.loginOptions["enableMicrosoftLogin"] = true
	}
}

func (h *AuthServer) ProviderLoginEndpointV2(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx)

	loginEventID := req.PathValue(pathValueLoginEventID)
	providerName := req.URL.Query().Get("provider")

	log = log.WithFields(map[string]any{
		"login_event_id": loginEventID,
		"provider":       providerName,
	})

	if providerName == "" {
		log.Warn("provider login attempt with empty provider name")
		return fmt.Errorf("provider name is required")
	}

	provider, ok := h.loginAuthProviders[providerName]
	if !ok {
		log.WithField("available_providers", loginAuthProviderNames(h.loginAuthProviders)).
			Warn("provider login attempt with unknown provider")
		return fmt.Errorf("unknown login provider: %s", providerName)
	}

	pkce, err := providers.NewPKCE()
	if err != nil {
		log.WithError(err).Error("failed to generate PKCE challenge")
		return fmt.Errorf("failed to generate PKCE: %w", err)
	}

	authState := &providers.AuthState{
		Provider:     providerName,
		State:        util.RandomAlphaNumericString(32),
		PKCEVerifier: pkce.Verifier,
		Nonce:        util.RandomAlphaNumericString(32),
		LoginEventID: loginEventID,
		ExpiresAt:    time.Now().Add(5 * time.Minute),
	}

	encoded, err := h.cookiesCodec.Encode(loginSessionProviderAuth, authState)
	if err != nil {
		log.WithError(err).Error("failed to encode auth state cookie")
		return fmt.Errorf("failed to encode auth state: %w", err)
	}

	providers.SetAuthStateCookie(rw, encoded)

	authURL := provider.AuthCodeURL(authState.State, pkce.Challenge, authState.Nonce)

	log.WithFields(map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
	}).Debug("redirecting to external provider")

	// Browser fetch() cannot read Location when it points at a third-party
	// IdP (opaque redirect). Login JS therefore requests JSON and navigates
	// with window.location.assign so Google always receives response_type=code.
	if prefersJSON(req) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Cache-Control", "no-store")
		return json.NewEncoder(rw).Encode(map[string]string{
			"redirect_url": authURL,
		})
	}

	http.Redirect(rw, req, authURL, http.StatusSeeOther)
	return nil
}

// prefersJSON reports whether the client asked for an application/json body
// (used by the FedCM→OAuth fallback fetch) rather than a 303 redirect.
func prefersJSON(req *http.Request) bool {
	accept := req.Header.Get("Accept")
	if accept == "" {
		return false
	}
	// Prefer explicit JSON over broad */* so normal form POSTs still redirect.
	return strings.Contains(accept, "application/json")
}

// loginAuthProviderNames returns registered provider names for diagnostic logging.
func loginAuthProviderNames(providerMap map[string]providers.AuthProvider) []string {
	names := make([]string, 0, len(providerMap))
	for name := range providerMap {
		names = append(names, name)
	}
	return names
}
