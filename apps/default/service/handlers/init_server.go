package handlers

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
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/gorilla/securecookie"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/util"
)

const DeviceSessionIDKey = "ses_id"

type AuthServer struct {
	sc           *securecookie.SecureCookie
	service      *frame.Service
	config       *config.AuthenticationConfig
	profileCli   *profilev1.ProfileClient
	partitionCli *partitionv1.PartitionClient

	// Repository dependencies
	loginRepo      repository.LoginRepository
	apiKeyRepo     repository.APIKeyRepository
	loginEventRepo repository.LoginEventRepository
	sessionRepo    repository.SessionRepository
}

func NewAuthServer(ctx context.Context, service *frame.Service,
	authConfig *config.AuthenticationConfig,
	profileCli *profilev1.ProfileClient,
	partitionCli *partitionv1.PartitionClient) *AuthServer {

	log := util.Log(ctx)

	hashKey, err := hex.DecodeString(authConfig.SecureCookieHashKey)
	if err != nil {
		log.Fatal("Failed to decode hash key:", err)
	}

	blockKey, err := hex.DecodeString(authConfig.SecureCookieBlockKey)
	if err != nil {
		log.Fatal("Failed to decode block key:", err)
	}

	h := &AuthServer{
		service:      service,
		config:       authConfig,
		profileCli:   profileCli,
		partitionCli: partitionCli,
		sc:           securecookie.New(hashKey, blockKey),

		// Initialise repositories
		loginRepo:      repository.NewLoginRepository(service),
		apiKeyRepo:     repository.NewAPIKeyRepository(service),
		loginEventRepo: repository.NewLoginEventRepository(service),
		sessionRepo:    repository.NewSessionRepository(service),
	}

	return h
}

// Service methods for accessing dependencies
func (h *AuthServer) Service() *frame.Service {
	return h.service
}

func (h *AuthServer) Config() *config.AuthenticationConfig {
	return h.config
}

func (h *AuthServer) ProfileCli() *profilev1.ProfileClient {
	return h.profileCli
}

func (h *AuthServer) PartitionCli() *partitionv1.PartitionClient {
	return h.partitionCli
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (h *AuthServer) writeError(ctx context.Context, w http.ResponseWriter, err error, code int, msg string) {

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

// NotFoundEndpoint handles 404 Not Found responses
func (h *AuthServer) NotFoundEndpoint(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	
	return json.NewEncoder(w).Encode(&ErrorResponse{
		Code:    http.StatusNotFound,
		Message: "The requested resource was not found",
	})
}

// deviceIDMiddleware to ensure secure cookie
func (h *AuthServer) deviceIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to get the existing cookie
		cookie, err := r.Cookie(DeviceSessionIDKey)
		if err == nil {
			// Decode and verify the cookie
			var decodedValue string
			if decodeErr := h.sc.Decode(DeviceSessionIDKey, cookie.Value, &decodedValue); decodeErr == nil {
				r = r.WithContext(utils.DeviceIDToContext(r.Context(), decodedValue))
				next.ServeHTTP(w, r)
				return
			}
		}

		newDeviceID := util.IDString()

		// Encode and sign the cookie
		encoded, encodeErr := h.sc.Encode(DeviceSessionIDKey, newDeviceID)
		if encodeErr != nil {
			http.Error(w, "Failed to encode cookie", http.StatusInternalServerError)
			return
		}

		// Set the secure, signed cookie
		http.SetCookie(w, &http.Cookie{
			Name:     DeviceSessionIDKey,
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

func (h *AuthServer) addHandler(router *http.ServeMux,
	f func(w http.ResponseWriter, r *http.Request) error, path string, name string, method string) {

	router.HandleFunc(fmt.Sprintf("%s %s", method, path), func(w http.ResponseWriter, r *http.Request) {
		log := h.service.Log(r.Context())

		err := f(w, r)
		if err != nil {
			log.WithError(err).WithField("path", path).WithField("name", name).Error("handler error")
			h.writeError(r.Context(), w, err, http.StatusInternalServerError, "internal processing error")
		}
	})
}
