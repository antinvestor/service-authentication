package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/service/handlers"
	"github.com/antinvestor/service-authentication/utils"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/pitabwire/frame"
	"net/http"
	"time"
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

	log := h.service.L(ctx).
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
		cookie, err := r.Cookie("DevLnkID")
		if err == nil {
			// Decode and verify the cookie
			var decodedValue string
			if decodeErr := h.sc.Decode("DevLnkID", cookie.Value, &decodedValue); decodeErr == nil {
				r = r.WithContext(utils.DeviceIDToContext(r.Context(), decodedValue))
				next.ServeHTTP(w, r)
				return
			}
		}

		newDeviceID := frame.GenerateID(r.Context())

		// Encode and sign the cookie
		encoded, encodeErr := h.sc.Encode("DevLnkID", newDeviceID)
		if encodeErr != nil {
			http.Error(w, "Failed to encode cookie", http.StatusInternalServerError)
			return
		}

		// Set the secure, signed cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "DevLnkID",
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

func (h *holder) addHandler(router *mux.Router,
	f func(w http.ResponseWriter, r *http.Request) error, path string, name string, method string) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(frame.ToContext(r.Context(), h.service))
		r = r.WithContext(profilev1.ToContext(r.Context(), h.profileCli))
		r = r.WithContext(partitionv1.ToContext(r.Context(), h.partitionCli))

		err := f(w, r)
		if err != nil {
			h.writeError(r.Context(), w, err, 500, "could not process request")
		}
	})

	router.Path(path).
		Name(name).
		Handler(handler).
		Methods(method)
}

// NewAuthRouterV1 NewRouterV1 -
func NewAuthRouterV1(ctx context.Context, service *frame.Service,
	authConfig *config.AuthenticationConfig,
	profileCli *profilev1.ProfileClient,
	partitionCli *partitionv1.PartitionClient) *mux.Router {

	log := service.L(ctx)
	router := mux.NewRouter().StrictSlash(true)

	csrfSecret, err := hex.DecodeString(authConfig.CsrfSecret)
	if err != nil {
		log.Fatal("Failed to decode csrf secret :", err)
	}

	csrfMiddleware := csrf.Protect(csrfSecret, csrf.Secure(true))

	sRouter := router.PathPrefix("/s").Subrouter()
	sRouter.Use(csrfMiddleware)

	authRouter := router.PathPrefix("/api").Subrouter()

	webhookRouter := router.PathPrefix("/webhook").Subrouter()

	authRouter.Use(func(handler http.Handler) http.Handler {
		return service.AuthenticationMiddleware(handler, authConfig.Oauth2JwtVerifyAudience, authConfig.Oauth2JwtVerifyIssuer)
	})

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

	sRouter.Use(h.deviceIDMiddleware)

	h.addHandler(router, handlers.IndexEndpoint, "/", "IndexEndpoint", "GET")
	h.addHandler(router, handlers.ErrorEndpoint, "/error", "ErrorEndpoint", "GET")

	h.addHandler(sRouter, handlers.ShowLoginEndpoint, "/login", "ShowLoginEndpoint", "GET")
	h.addHandler(sRouter, handlers.SubmitLoginEndpoint, "/login/post", "SubmitLoginEndpoint", "POST")
	h.addHandler(sRouter, handlers.ShowLogoutEndpoint, "/logout", "ShowLogoutEndpoint", "GET")
	h.addHandler(sRouter, handlers.ShowConsentEndpoint, "/consent", "ShowConsentEndpoint", "GET")
	h.addHandler(sRouter, handlers.ShowRegisterEndpoint, "/register", "ShowRegisterEndpoint", "GET")
	h.addHandler(sRouter, handlers.SubmitRegisterEndpoint, "/register/post", "SubmitRegisterEndpoint", "POST")
	h.addHandler(sRouter, handlers.SetPasswordEndpoint, "/password", "SetPasswordEndpoint", "GET")
	h.addHandler(sRouter, handlers.ForgotEndpoint, "/forgot", "ForgotEndpoint", "GET")

	h.addHandler(webhookRouter, handlers.TokenEnrichmentEndpoint, "/enrich/{tokenType}", "WebhookTokenEnrichmentEndpoint", "POST")

	h.addHandler(authRouter, handlers.CreateAPIKeyEndpoint, "/key", "CreateAPIKeyEndpoint", "PUT")
	h.addHandler(authRouter, handlers.ListAPIKeyEndpoint, "/key", "ListApiKeyEndpoint", "GET")
	h.addHandler(authRouter, handlers.DeleteAPIKeyEndpoint, "/key/{ApiKeyId}", "DeleteApiKeyEndpoint", "DELETE")
	h.addHandler(authRouter, handlers.GetAPIKeyEndpoint, "/key/{ApiKeyId}", "GetApiKeyEndpoint", "GET")

	return router
}
