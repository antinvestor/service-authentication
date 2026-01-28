package handlers

import (
	"fmt"
	"net/http"
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

	if cfg.AuthProviderGoogleClientID != "" {
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
		LoginEventID: loginEventID,
		ExpiresAt:    time.Now().Add(5 * time.Minute),
	}

	encoded, err := h.cookiesCodec.Encode(loginSessionProviderAuth, authState)
	if err != nil {
		log.WithError(err).Error("failed to encode auth state cookie")
		return fmt.Errorf("failed to encode auth state: %w", err)
	}

	providers.SetAuthStateCookie(rw, encoded)

	authURL := provider.AuthCodeURL(authState.State, pkce.Challenge)

	log.WithFields(map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
	}).Info("redirecting user to external provider for authentication")

	http.Redirect(rw, req, authURL, http.StatusSeeOther)
	return nil
}

// loginAuthProviderNames returns registered provider names for diagnostic logging.
func loginAuthProviderNames(providerMap map[string]providers.AuthProvider) []string {
	names := make([]string, 0, len(providerMap))
	for name := range providerMap {
		names = append(names, name)
	}
	return names
}
