package handlers

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	httpInterceptor "github.com/pitabwire/frame/security/interceptors/httptor"
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
		// Set cache headers for static assets (Cache-Control is preferred over Expires)
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable") // 1 year, immutable for versioned assets

		// Set proper content types
		if filepath.Ext(r.URL.Path) == ".css" {
			w.Header().Set("Content-Type", "text/css")
		} else if filepath.Ext(r.URL.Path) == ".js" {
			w.Header().Set("Content-Type", "application/javascript")
		}

		fileServer.ServeHTTP(w, r)
	})

	// Public routes (no auth, no CSRF)
	h.addHandler(router, h.ErrorEndpoint, "/error", "ErrorEndpoint", "GET")
	h.addHandler(router, h.SwaggerEndpoint, "/swagger.json", "SwaggerEndpoint", "GET")

	// Custom root handler that handles both static files and index
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

	unAuthenticatedHandler(h.ShowLoginEndpoint, "/s/login", "ShowLoginEndpoint", "GET")
	unAuthenticatedHandler(h.SubmitLoginEndpoint, "/s/login/post", "SubmitLoginEndpoint", "POST")
	unAuthenticatedHandler(h.ShowLogoutEndpoint, "/s/logout", "ShowLogoutEndpoint", "GET")
	unAuthenticatedHandler(h.ShowConsentEndpoint, "/s/consent", "ShowConsentEndpoint", "GET")
	unAuthenticatedHandler(h.ShowVerificationEndpoint, "/s/verify/contact/{loginEventId}", "ShowVerificationEndpoint", "GET")
	unAuthenticatedHandler(h.SubmitVerificationEndpoint, "/s/verify/contact/{loginEventId}/post", "SubmitVerificationEndpoint", "POST")
	unAuthenticatedHandler(h.ProviderLoginEndpoint, "/s/social/login/{loginEventId}/{provider}", "SocialLoginEndpoint", "POST")
	unAuthenticatedHandler(h.ProviderCallbackEndpoint, "/social/callback/{provider}", "SocialLoginCallbackEndpoint", "GET")
	unAuthenticatedHandler(h.ProviderCallbackEndpoint, "/social/callback/{provider}", "SocialLoginCallbackEndpoint", "POST")

	// Webhook routes has internal PSK for its authentication with hydra.
	// When HYDRA_WEBHOOK_API_PSK is empty (default), no auth check is performed
	// and the endpoint relies on network isolation. When set, the Bearer token
	// in the Authorization header must match exactly.
	webhookAuthenticatedHandler := func(f func(w http.ResponseWriter, r *http.Request) error, path, name, method string) {
		router.HandleFunc(fmt.Sprintf("%s %s", method, path), func(w http.ResponseWriter, r *http.Request) {
			log := util.Log(r.Context())

			expectedToken := strings.TrimSpace(h.Config().HydraWebhookAPIToken)
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
				h.writeAPIError(r.Context(), w, err, http.StatusInternalServerError, name)
			}
		})
	}

	// Webhook routes (PSK auth when HYDRA_WEBHOOK_API_PSK is configured)
	webhookAuthenticatedHandler(h.TokenEnrichmentEndpoint, "/webhook/enrich/{tokenType}", "WebhookTokenEnrichmentEndpoint", "POST")

	// API routes with authentication (JSON endpoints - return JSON errors)
	apiAuthenticatedHandlers := func(f func(w http.ResponseWriter, r *http.Request) error, path string, name string, method string) {
		router.HandleFunc(fmt.Sprintf("%s %s", method, path), func(w http.ResponseWriter, r *http.Request) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerErr := f(w, r)
				if handlerErr != nil {
					h.writeAPIError(r.Context(), w, handlerErr, http.StatusInternalServerError, name)
				}
			})

			// Apply authentication middleware
			authMiddleware := httpInterceptor.AuthenticationMiddleware(handler, h.securityAuth)
			authMiddleware.ServeHTTP(w, r)
		})
	}

	apiAuthenticatedHandlers(h.CreateAPIKeyEndpoint, "/api/key", "CreateAPIKeyEndpoint", "PUT")
	apiAuthenticatedHandlers(h.ListAPIKeyEndpoint, "/api/key", "ListApiKeyEndpoint", "GET")
	apiAuthenticatedHandlers(h.DeleteAPIKeyEndpoint, "/api/key/{ApiKeyId}", "DeleteApiKeyEndpoint", "DELETE")
	apiAuthenticatedHandlers(h.GetAPIKeyEndpoint, "/api/key/{ApiKeyId}", "GetApiKeyEndpoint", "GET")

	return router
}
