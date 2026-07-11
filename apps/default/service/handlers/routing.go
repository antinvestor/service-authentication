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
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/pitabwire/util"
)

// findStaticDirectory searches for the static assets directory in common locations
func findStaticDirectory() string {
	searchPaths := []string{
		"static",
		"apps/default/static",
		"../static",
		"../../static",
	}

	for _, path := range searchPaths {
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			absPath, err := filepath.Abs(path)
			if err == nil {
				return absPath
			}
		}
	}

	return "static"
}

// SetupRouterV1 -
func (h *AuthServer) SetupRouterV1(ctx context.Context) *http.ServeMux {

	router := http.NewServeMux()

	// Configure CSRF middleware based on environment
	// In test environments, disable CSRF middleware to allow HTTP requests
	serviceName := h.Config().Name()
	isTestEnv := serviceName == "authentication_tests"

	var csrfMiddleware func(http.Handler) http.Handler
	if isTestEnv {
		// In test environment, use a no-op middleware that just passes through
		csrfMiddleware = func(h http.Handler) http.Handler {
			return h
		}
	} else {
		csrfMiddleware = http.NewCrossOriginProtection().Handler
	}

	// Static file serving (no auth, no CSRF) with cache headers
	staticDir := findStaticDirectory()
	fileServer := http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir)))

	// Wrap file server with cache headers
	staticHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Auth assets are served from stable URLs, so they must stay revalidatable.
		// Immutable caching is only safe for files whose URL changes when content changes.
		switch filepath.Ext(r.URL.Path) {
		case ".css", ".js":
			w.Header().Set("Cache-Control", "no-cache")
		default:
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}

		// Set proper content types
		switch filepath.Ext(r.URL.Path) {
		case ".css":
			w.Header().Set("Content-Type", "text/css")
		case ".js":
			w.Header().Set("Content-Type", "application/javascript")
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		}

		fileServer.ServeHTTP(w, r)
	})

	// Public routes (no auth, no CSRF)
	h.addHandler(router, h.ErrorEndpoint, "/error", "ErrorEndpoint")
	h.addHandler(router, h.SwaggerEndpoint, "/swagger.json", "SwaggerEndpoint")
	router.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		setOAuthPublicCORSHeaders(w, r)
		if err := h.OpenIDConfigurationFacadeEndpoint(w, r); err != nil {
			h.writeAPIError(r.Context(), w, err, "OpenIDConfigurationFacade")
		}
	})
	// Browser SPAs discover token_endpoint on the accounts host and preflight
	// with OPTIONS before exchanging authorization codes (PKCE).
	router.HandleFunc("OPTIONS /oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		setOAuthPublicCORSHeaders(w, r)
		w.Header().Set("Allow", "POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	})
	router.HandleFunc("POST /oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		setOAuthPublicCORSHeaders(w, r)
		if err := h.OAuthTokenFacadeEndpoint(w, r); err != nil {
			h.writeAPIError(r.Context(), w, err, "OAuthTokenFacade")
		}
	})

	// Custom root handler that handles both static files and index
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			http.Redirect(w, r, "/static/favicon.svg", http.StatusMovedPermanently)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/static/") {
			// Handle static files
			staticHandler.ServeHTTP(w, r)
			return
		}
		// Handle other paths as not found
		err := h.NotFoundEndpoint(w, r)
		if err != nil {
			h.redirectToErrorPage(w, r, err, "NotFoundEndpoint")
		}
	})

	// Secure routes with CSRF protection (HTML endpoints - redirect to error page on failure)
	unAuthenticatedHandler := func(f func(w http.ResponseWriter, r *http.Request) error, path string, name string, method string) {
		router.HandleFunc(fmt.Sprintf("%s %s", method, path), func(w http.ResponseWriter, r *http.Request) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerErr := f(w, r)
				if handlerErr != nil {
					h.redirectToErrorPage(w, r, handlerErr, name)
				}
			})

			// Apply CSRF middleware for secure routes
			csrfHandler := csrfMiddleware(handler)
			// Apply device ID middleware
			deviceHandler := h.deviceIDMiddleware(csrfHandler)
			deviceHandler.ServeHTTP(w, r)
		})
	}

	unAuthenticatedHandler(h.LoginEndpointShow, "/s/login", "LoginEndpointShow", "GET")
	unAuthenticatedHandler(h.LoginEndpointSubmit, "/s/login/{loginEventId}/post", "SubmitLoginEndpoint", "POST")
	unAuthenticatedHandler(h.ShowLogoutEndpoint, "/s/logout", "ShowLogoutEndpoint", "GET")
	unAuthenticatedHandler(h.ShowConsentEndpoint, "/s/consent", "ShowConsentEndpoint", "GET")
	unAuthenticatedHandler(h.AccessInstructionsEndpoint, accessInstructionsPath, "AccessInstructionsEndpoint", "GET")
	unAuthenticatedHandler(h.WorkspaceSelectorEndpoint, workspaceSelectorPath, "WorkspaceSelectorEndpoint", "GET")
	unAuthenticatedHandler(h.WorkspaceSelectorSubmitEndpoint, workspaceSelectorPath, "WorkspaceSelectorSubmitEndpoint", "POST")
	unAuthenticatedHandler(h.VerificationEndpointShow, "/s/verify/contact/{loginEventId}", "VerificationEndpointShow", "GET")
	unAuthenticatedHandler(h.VerificationEndpointSubmit, "/s/verify/contact/{loginEventId}/post", "VerificationEndpointSubmit", "POST")
	unAuthenticatedHandler(h.VerificationResendEndpoint, "/s/verify/contact/{loginEventId}/resend", "VerificationResendEndpoint", "POST")
	unAuthenticatedHandler(h.ProviderLoginEndpointV2, "/s/social/login/{loginEventId}", "SocialLoginEndpoint", "POST")

	// Social login callback - provider is determined from signed auth state cookie, not URL
	unAuthenticatedHandler(h.ProviderCallbackEndpointV2, "/s/social/callback", "SocialLoginCallbackEndpoint", "GET")
	unAuthenticatedHandler(h.ProviderCallbackEndpointV2, "/s/social/callback", "SocialLoginCallbackEndpoint", "POST")

	// FedCM — IdP discovery (public, no auth)
	router.HandleFunc("GET /.well-known/web-identity", func(w http.ResponseWriter, r *http.Request) {
		if err := h.fedcmWellKnown.WellKnownWebIdentity(w, r); err != nil {
			h.redirectToErrorPage(w, r, err, "FedCMWellKnown")
		}
	})
	router.HandleFunc("GET /fedcm/config.json", func(w http.ResponseWriter, r *http.Request) {
		if err := h.fedcmWellKnown.FedCMConfig(w, r); err != nil {
			h.redirectToErrorPage(w, r, err, "FedCMConfig")
		}
	})

	// FedCM — session-backed JSON endpoints. No CSRF (Sec-Fetch-Dest + cookie
	// validation gate them). Errors are returned as JSON by the handler; this
	// wrapper only handles unexpected Go errors.
	fedcmHandler := func(f func(w http.ResponseWriter, r *http.Request) error, method, path, name string) {
		router.HandleFunc(fmt.Sprintf("%s %s", method, path), func(w http.ResponseWriter, r *http.Request) {
			if err := f(w, r); err != nil {
				h.writeAPIError(r.Context(), w, err, name)
			}
		})
	}
	fedcmHandler(h.FedCMAccountsEndpoint, "GET", "/fedcm/accounts", "FedCMAccounts")
	fedcmHandler(h.FedCMClientMetadataEndpoint, "GET", "/fedcm/client_metadata", "FedCMClientMetadata")
	fedcmHandler(h.FedCMIdAssertionEndpoint, "POST", "/fedcm/id-assertion", "FedCMIdAssertion")
	fedcmHandler(h.FedCMDisconnectEndpoint, "POST", "/fedcm/disconnect", "FedCMDisconnect")
	fedcmHandler(h.FedCMTokenExchangeEndpoint, "POST", "/fedcm/token-exchange", "FedCMTokenExchange")

	// FedCM cold-start login (HTML; CSRF-protected)
	unAuthenticatedHandler(h.FedCMLoginShow, "/s/fedcm/login", "FedCMLoginShow", "GET")
	unAuthenticatedHandler(h.FedCMLoginSubmit, "/s/fedcm/login", "FedCMLoginSubmit", "POST")
	unAuthenticatedHandler(h.FedCMVerifyShow, "/s/fedcm/verify/{loginEventId}", "FedCMVerifyShow", "GET")
	unAuthenticatedHandler(h.FedCMVerifySubmit, "/s/fedcm/verify/{loginEventId}", "FedCMVerifySubmit", "POST")

	// FedCM probe completion on /s/login (JSON fetch from the login page)
	router.HandleFunc("POST /s/login/{loginEventId}/fedcm-complete", func(w http.ResponseWriter, r *http.Request) {
		if err := h.FedCMCompleteLogin(w, r); err != nil {
			h.writeAPIError(r.Context(), w, err, "FedCMCompleteLogin")
		}
	})

	// Google FedCM completion. Same-origin JSON fetch from the /s/login page;
	// the handler enforces Sec-Fetch-Site, server-bound nonce, and Hydra's
	// single-use login_challenge so we don't need the HTML CSRF middleware.
	router.HandleFunc("POST /s/social/google/fedcm-complete", func(w http.ResponseWriter, r *http.Request) {
		if err := h.FedCMGoogleCompleteEndpoint(w, r); err != nil {
			h.writeAPIError(r.Context(), w, err, "FedCMGoogleComplete")
		}
	})

	// Webhook routes has internal PSK for its authentication with hydra.
	// When HYDRA_WEBHOOK_API_PSK is empty (default), no auth check is performed
	// and the endpoint relies on network isolation. When set, the Bearer token
	// in the Authorization header must match exactly.
	webhookAuthenticatedHandler := func(f func(w http.ResponseWriter, r *http.Request) error, path, name, method string) {
		router.HandleFunc(fmt.Sprintf("%s %s", method, path), func(w http.ResponseWriter, r *http.Request) {
			log := util.Log(r.Context())

			expectedToken := strings.TrimSpace(h.Config().HydraWebhookAPIToken)
			if expectedToken == "" && !isTestEnv {
				log.Error("webhook request rejected: HYDRA_WEBHOOK_API_PSK is not configured")
				http.Error(w, "webhook authentication is not configured", http.StatusServiceUnavailable)
				return
			}

			if expectedToken != "" {
				const bearerPrefix = "Bearer "
				auth := r.Header.Get("Authorization")

				if !strings.HasPrefix(auth, bearerPrefix) {
					log.Warn("webhook request rejected: missing or malformed Authorization header")
					http.Error(w, "unauthorised", http.StatusUnauthorized)
					return
				}

				providedToken := strings.TrimSpace(strings.TrimPrefix(auth, bearerPrefix))
				if subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) != 1 {
					log.Warn("webhook request rejected: invalid bearer token")
					http.Error(w, "unauthorised", http.StatusUnauthorized)
					return
				}
			}

			if err := f(w, r); err != nil {
				h.writeAPIError(r.Context(), w, err, name)
			}
		})
	}

	// Webhook routes (PSK auth when HYDRA_WEBHOOK_API_PSK is configured)
	webhookAuthenticatedHandler(h.TokenEnrichmentEndpoint, "/webhook/enrich/{tokenType}", "WebhookTokenEnrichmentEndpoint", "POST")
	webhookAuthenticatedHandler(h.SignPrivateKeyJWTEndpoint, "/webhook/sign/private-key-jwt", "WebhookSignPrivateKeyJWT", "POST")

	return router
}
