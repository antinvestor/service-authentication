package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/config"
	handlers2 "github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/gorilla/csrf"
	"github.com/gorilla/securecookie"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/util"
)

type holder struct {
	sc           *securecookie.SecureCookie
	service      *frame.Service
	config       *config.AuthenticationConfig
	profileCli   *profilev1.ProfileClient
	partitionCli *partitionv1.PartitionClient
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (h *holder) writeError(ctx context.Context, w http.ResponseWriter, err error, code int, msg string) {

	w.Header().Set("Content-Type", "application/json")

	log := h.service.Log(ctx).
		WithField("code", code).
		WithField("message", msg).WithError(err)
	log.Error("internal service error")
	w.WriteHeader(code)

	err = json.NewEncoder(w).Encode(&ErrorResponse{
		Code:    code,
		Message: fmt.Sprintf(" internal processing err message: %s %s", msg, err),
	})
	if err != nil {
		log.WithError(err).Error("could not write error to response")
	}
}

// deviceIDMiddleware to ensure secure cookie
func (h *holder) deviceIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to get the existing cookie
		cookie, err := r.Cookie("DevSessionID")
		if err == nil {
			// Decode and verify the cookie
			var decodedValue string
			if decodeErr := h.sc.Decode("DevSessionID", cookie.Value, &decodedValue); decodeErr == nil {
				r = r.WithContext(utils.DeviceIDToContext(r.Context(), decodedValue))
				next.ServeHTTP(w, r)
				return
			}
		}

		newDeviceID := util.IDString()

		// Encode and sign the cookie
		encoded, encodeErr := h.sc.Encode("DevSessionID", newDeviceID)
		if encodeErr != nil {
			http.Error(w, "Failed to encode cookie", http.StatusInternalServerError)
			return
		}

		// Set the secure, signed cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "DevSessionID",
			Value:    encoded,
			Path:     "/",
			MaxAge:   473040000, // 15 years
			Secure:   true,      // HTTPS-only
			HttpOnly: true,      // No JavaScript access
			SameSite: http.SameSiteStrictMode,
			Expires:  time.Now().Add(473040000 * time.Second),
		})
		r = r.WithContext(utils.DeviceIDToContext(r.Context(), newDeviceID))
		// Continue to the next handler
		next.ServeHTTP(w, r)
	})
}

func (h *holder) addHandler(router *http.ServeMux,
	f func(w http.ResponseWriter, r *http.Request) error, path string, name string, method string) {

	router.HandleFunc(fmt.Sprintf("%s %s", method, path), func(w http.ResponseWriter, r *http.Request) {
		// Set up request context with required services
		r = r.WithContext(frame.SvcToContext(r.Context(), h.service))
		r = r.WithContext(profilev1.ToContext(r.Context(), h.profileCli))
		r = r.WithContext(partitionv1.ToContext(r.Context(), h.partitionCli))

		log := h.service.Log(r.Context())

		err := f(w, r)
		if err != nil {
			log.WithError(err).WithField("path", path).WithField("name", name).Error("handler error")
			h.writeError(r.Context(), w, err, http.StatusInternalServerError, "internal processing error")
		}
	})
}

// NewAuthRouterV1 NewRouterV1 -
func NewAuthRouterV1(ctx context.Context, service *frame.Service,
	authConfig *config.AuthenticationConfig,
	profileCli *profilev1.ProfileClient,
	partitionCli *partitionv1.PartitionClient) *http.ServeMux {

	log := service.Log(ctx)
	router := http.NewServeMux()

	csrfSecret, err := hex.DecodeString(authConfig.CsrfSecret)
	if err != nil {
		log.Fatal("Failed to decode csrf secret :", err)
	}

	csrfMiddleware := csrf.Protect(csrfSecret, csrf.Secure(true))

	hashKey, err := hex.DecodeString(authConfig.SecureCookieHashKey)
	if err != nil {
		log.Fatal("Failed to decode hash key:", err)
	}

	blockKey, err := hex.DecodeString(authConfig.SecureCookieBlockKey)
	if err != nil {
		log.Fatal("Failed to decode block key:", err)
	}

	h := &holder{
		service:      service,
		config:       authConfig,
		profileCli:   profileCli,
		partitionCli: partitionCli,
		sc:           securecookie.New(hashKey, blockKey),
	}

	// Basic routes
	h.addHandler(router, handlers2.IndexEndpoint, "/", "IndexEndpoint", "GET")
	h.addHandler(router, handlers2.ErrorEndpoint, "/error", "ErrorEndpoint", "GET")

	// Secure routes (with CSRF protection and device ID middleware)
	secureHandler := func(f func(w http.ResponseWriter, r *http.Request) error, path string, name string, method string) {
		router.HandleFunc(fmt.Sprintf("%s %s", method, path), func(w http.ResponseWriter, r *http.Request) {
			// Set up request context with required services
			r = r.WithContext(frame.SvcToContext(r.Context(), h.service))
			r = r.WithContext(profilev1.ToContext(r.Context(), h.profileCli))
			r = r.WithContext(partitionv1.ToContext(r.Context(), h.partitionCli))

			// Apply middleware chain: deviceID -> CSRF -> auth handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := f(w, r)
				if err != nil {
					log := h.service.Log(r.Context())
					log.WithError(err).WithField("path", path).WithField("name", name).Error("handler error")
					h.writeError(r.Context(), w, err, http.StatusInternalServerError, "internal processing error")
				}
			})

			// Apply CSRF middleware for secure routes
			csrfHandler := csrfMiddleware(handler)
			// Apply device ID middleware
			deviceHandler := h.deviceIDMiddleware(csrfHandler)
			deviceHandler.ServeHTTP(w, r)
		})
	}

	// Auth routes (with authentication middleware)
	authHandler := func(f func(w http.ResponseWriter, r *http.Request) error, path string, name string, method string) {
		router.HandleFunc(fmt.Sprintf("%s %s", method, path), func(w http.ResponseWriter, r *http.Request) {
			// Set up request context with required services
			r = r.WithContext(frame.SvcToContext(r.Context(), h.service))
			r = r.WithContext(profilev1.ToContext(r.Context(), h.profileCli))
			r = r.WithContext(partitionv1.ToContext(r.Context(), h.partitionCli))

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := f(w, r)
				if err != nil {
					log := h.service.Log(r.Context())
					log.WithError(err).WithField("path", path).WithField("name", name).Error("handler error")
					h.writeError(r.Context(), w, err, http.StatusInternalServerError, "internal processing error")
				}
			})

			// Apply authentication middleware
			authMiddleware := service.AuthenticationMiddleware(handler, authConfig.Oauth2JwtVerifyAudience, authConfig.Oauth2JwtVerifyIssuer)
			authMiddleware.ServeHTTP(w, r)
		})
	}

	// Secure routes with CSRF protection
	secureHandler(handlers2.ShowLoginEndpoint, "/s/login", "ShowLoginEndpoint", "GET")
	secureHandler(handlers2.SubmitLoginEndpoint, "/s/login/post", "SubmitLoginEndpoint", "POST")
	secureHandler(handlers2.ShowLogoutEndpoint, "/s/logout", "ShowLogoutEndpoint", "GET")
	secureHandler(handlers2.ShowConsentEndpoint, "/s/consent", "ShowConsentEndpoint", "GET")
	secureHandler(handlers2.ShowRegisterEndpoint, "/s/register", "ShowRegisterEndpoint", "GET")
	secureHandler(handlers2.SubmitRegisterEndpoint, "/s/register/post", "SubmitRegisterEndpoint", "POST")
	secureHandler(handlers2.SetPasswordEndpoint, "/s/password", "SetPasswordEndpoint", "GET")
	secureHandler(handlers2.ForgotEndpoint, "/s/forgot", "ForgotEndpoint", "GET")

	// Webhook routes (no auth required)
	h.addHandler(router, handlers2.TokenEnrichmentEndpoint, "/webhook/enrich/{tokenType}", "WebhookTokenEnrichmentEndpoint", "POST")

	// API routes with authentication
	authHandler(handlers2.CreateAPIKeyEndpoint, "/api/key", "CreateAPIKeyEndpoint", "PUT")
	authHandler(handlers2.ListAPIKeyEndpoint, "/api/key", "ListApiKeyEndpoint", "GET")
	authHandler(handlers2.DeleteAPIKeyEndpoint, "/api/key/{ApiKeyId}", "DeleteApiKeyEndpoint", "DELETE")
	authHandler(handlers2.GetAPIKeyEndpoint, "/api/key/{ApiKeyId}", "GetApiKeyEndpoint", "GET")

	return router
}
