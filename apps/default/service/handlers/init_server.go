package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	devicev1 "github.com/antinvestor/apis/go/device/v1"
	notificationv1 "github.com/antinvestor/apis/go/notification/v1"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/gorilla/securecookie"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/util"
)

const (
	SessionKeyDeviceStorageName  = "device_storage"
	SessionKeySessionStorageName = "session_storage"
	SessionKeyDeviceIDKey        = "link_id"
	SessionKeyDeviceSessionIDKey = "sess_id"
)

type AuthServer struct {
	loginCookieCodec []securecookie.Codec
	service          *frame.Service
	config           *config.AuthenticationConfig
	profileCli       *profilev1.ProfileClient
	deviceCli        *devicev1.DeviceClient
	partitionCli     *partitionv1.PartitionClient
	notificationCli  *notificationv1.NotificationClient

	// Repository dependencies
	loginRepo      repository.LoginRepository
	apiKeyRepo     repository.APIKeyRepository
	loginEventRepo repository.LoginEventRepository

	// Login options enabled
	loginOptions map[string]any
}

func NewAuthServer(ctx context.Context, service *frame.Service, authConfig *config.AuthenticationConfig, profileCli *profilev1.ProfileClient, deviceCli *devicev1.DeviceClient, partitionCli *partitionv1.PartitionClient, notificationCli *notificationv1.NotificationClient) *AuthServer {

	log := util.Log(ctx)

	h := &AuthServer{
		service:         service,
		config:          authConfig,
		profileCli:      profileCli,
		deviceCli:       deviceCli,
		partitionCli:    partitionCli,
		notificationCli: notificationCli,

		// Initialise repositories
		loginRepo:      repository.NewLoginRepository(service),
		apiKeyRepo:     repository.NewAPIKeyRepository(service),
		loginEventRepo: repository.NewLoginEventRepository(service),
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
func (h *AuthServer) NotificationCli() *notificationv1.NotificationClient {
	return h.notificationCli
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

// nolint: unparam //code has to remain as it is
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
	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusNotFound)
	return notFoundTmpl.Execute(rw, initTemplatePayload(req.Context()))
}

// deviceIDMiddleware to ensure secure cookie and session handling
func (h *AuthServer) deviceIDMiddleware(next http.Handler) http.Handler {

	performDeviceLog := func(ctx context.Context, r *http.Request, deviceID, sessionID string) {
		ipAddr := util.GetIP(r)
		userAgent := r.UserAgent()

		req := devicev1.LogRequest{
			SessionId: sessionID,
			Ip:        ipAddr,
			UserAgent: userAgent,
			LastSeen:  time.Now().String(),
			Extras:    map[string]string{"refer": r.Referer()},
		}

		if deviceID != "" {
			req.DeviceId = deviceID
		}

		_, err := h.DeviceCli().Svc().Log(ctx, &req)
		if err != nil {
			util.Log(ctx).WithField("device_id", deviceID).WithField("session_id", sessionID).WithError(err).Info("device session log error")
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		var deviceID string
		var sessionID string
		var sessionIDExists bool

		// Try to get the existing device ID cookie
		deviceCookie, err := r.Cookie(SessionKeyDeviceStorageName)
		if err == nil {
			// Decode and verify the device ID cookie
			for _, cookieCodec := range h.loginCookieCodec {
				decodeErr := cookieCodec.Decode(SessionKeyDeviceIDKey, deviceCookie.Value, &deviceID)
				if decodeErr == nil {
					break
				}
			}
		}

		// Try to get the existing session ID cookie
		sessionCookie, err := r.Cookie(SessionKeySessionStorageName)
		if err == nil {
			// Decode and verify the session ID cookie
			for _, cookieCodec := range h.loginCookieCodec {
				decodeErr := cookieCodec.Decode(SessionKeyDeviceSessionIDKey, sessionCookie.Value, &sessionID)
				if decodeErr == nil {
					sessionIDExists = true
					break
				}
			}
		}

		// If session ID doesn't exist, create a new one
		if !sessionIDExists {
			sessionID = util.IDString()

			// Encode and sign the session ID cookie
			encoded, encodeErr := h.loginCookieCodec[0].Encode(SessionKeyDeviceSessionIDKey, sessionID)
			if encodeErr != nil {
				http.Error(w, "failed to encode session cookie", http.StatusInternalServerError)
				return
			}

			// Set the secure, signed session ID cookie (short-term for login session)
			http.SetCookie(w, &http.Cookie{
				Name:     SessionKeySessionStorageName,
				Value:    encoded,
				Path:     "/",
				MaxAge:   1800, // 1 hour for login session
				Secure:   true, // HTTPS-only
				HttpOnly: true, // No JavaScript access
				SameSite: http.SameSiteStrictMode,
				Expires:  time.Now().Add(30 * time.Minute),
			})
		}

		if deviceID != "" {
			// Add both device ID and session ID to context
			ctx = utils.DeviceIDToContext(ctx, deviceID)
		}
		ctx = utils.SessionIDToContext(ctx, sessionID)
		r = r.WithContext(ctx)

		performDeviceLog(ctx, r, deviceID, sessionID)

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
