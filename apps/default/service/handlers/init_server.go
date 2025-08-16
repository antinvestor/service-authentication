package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	devicev1 "github.com/antinvestor/apis/go/device/v1"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/gorilla/securecookie"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/util"
)

const DeviceSessionIDKey = "dev_ses_id"

type AuthServer struct {
	cookieCodec  []securecookie.Codec
	service      *frame.Service
	config       *config.AuthenticationConfig
	profileCli   *profilev1.ProfileClient
	deviceCli    *devicev1.DeviceClient
	partitionCli *partitionv1.PartitionClient

	// Repository dependencies
	loginRepo      repository.LoginRepository
	apiKeyRepo     repository.APIKeyRepository
	loginEventRepo repository.LoginEventRepository
	sessionRepo    repository.SessionRepository

	// Login options enabled
	loginOptions map[string]bool
}

func NewAuthServer(ctx context.Context, service *frame.Service, authConfig *config.AuthenticationConfig, profileCli *profilev1.ProfileClient, deviceCli *devicev1.DeviceClient, partitionCli *partitionv1.PartitionClient) *AuthServer {

	log := util.Log(ctx)

	h := &AuthServer{
		service:      service,
		config:       authConfig,
		profileCli:   profileCli,
		deviceCli:    deviceCli,
		partitionCli: partitionCli,

		// Initialise repositories
		loginRepo:      repository.NewLoginRepository(service),
		apiKeyRepo:     repository.NewAPIKeyRepository(service),
		loginEventRepo: repository.NewLoginEventRepository(service),
		sessionRepo:    repository.NewSessionRepository(service),
	}

	err := h.setupCookieSessions(ctx, authConfig)
	if err != nil {
		log.WithError(err).Fatal("Failed to setup cookie sessions")
	}

	h.setupAuthProviders(ctx, authConfig)

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

func (h *AuthServer) DeviceCli() *devicev1.DeviceClient {
	return h.deviceCli
}

func (h *AuthServer) PartitionCli() *partitionv1.PartitionClient {
	return h.partitionCli
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func initTemplatePayload(ctx context.Context) map[string]any {
	payload := make(map[string]any)

	deviceId := utils.DeviceIDFromContext(ctx)
	payload["DeviceID"] = deviceId

	return payload
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

func (h *AuthServer) NotFoundEndpoint(rw http.ResponseWriter, req *http.Request) error {
	return notFoundTmpl.Execute(rw, initTemplatePayload(req.Context()))
}

// deviceIDMiddleware to ensure secure cookie
func (h *AuthServer) deviceIDMiddleware(next http.Handler) http.Handler {

	performDeviceLog := func(ctx context.Context, r *http.Request, deviceSessID string) {
		ipAddr := util.GetIP(r)
		userAgent := r.UserAgent()

		req := devicev1.LogRequest{

			LinkId:    deviceSessID,
			Ip:        ipAddr,
			UserAgent: userAgent,
			LastSeen:  time.Now().String(),
			Extras:    map[string]string{"refer": r.Referer()},
		}
		_, err := h.DeviceCli().Svc().Log(ctx, &req)
		if err != nil {
			util.Log(ctx).WithField("device_session_id", deviceSessID).WithError(err).Info("device session log error")
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Try to get the existing cookie
		cookie, err := r.Cookie(DeviceSessionIDKey)
		if err == nil {
			// Decode and verify the cookie
			var decodedValue string
			for _, cookieCodec := range h.cookieCodec {

				decodeErr := cookieCodec.Decode(DeviceSessionIDKey, cookie.Value, &decodedValue)
				if decodeErr == nil {
					ctx = utils.DeviceIDToContext(ctx, decodedValue)
					r = r.WithContext(ctx)

					go performDeviceLog(ctx, r, decodedValue)
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		newDeviceSessID := util.IDString()

		// Encode and sign the cookie
		encoded, encodeErr := h.cookieCodec[0].Encode(DeviceSessionIDKey, newDeviceSessID)
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
		r = r.WithContext(utils.DeviceIDToContext(r.Context(), newDeviceSessID))

		defer performDeviceLog(ctx, r, newDeviceSessID)
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
