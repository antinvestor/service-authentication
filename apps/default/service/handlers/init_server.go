package handlers

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"buf.build/gen/go/antinvestor/device/connectrpc/go/device/v1/devicev1connect"
	devicev1 "buf.build/gen/go/antinvestor/device/protocolbuffers/go/device/v1"
	"buf.build/gen/go/antinvestor/notification/connectrpc/go/notification/v1/notificationv1connect"
	"buf.build/gen/go/antinvestor/partition/connectrpc/go/partition/v1/partitionv1connect"
	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	"connectrpc.com/connect"
	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers/providers"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/pitabwire/frame/cache"
	"github.com/pitabwire/frame/client"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	SessionKeyDeviceStorageName  = "device_storage"
	SessionKeySessionStorageName = "session_storage"
	SessionKeyDeviceIDKey        = "link_id"
	SessionKeyDeviceSessionIDKey = "sess_id"

	SessionKeyRememberMeStorageName     = "remember_me_storage"
	SessionKeyRememberMeLoginEventIDKey = "remember_login_event_id"
)

type AuthServer struct {
	cookiesCodec *providers.StateCodec
	config       *aconfig.AuthenticationConfig

	securityAuth security.Authenticator

	cacheMan cache.Manager

	profileCli      profilev1connect.ProfileServiceClient
	deviceCli       devicev1connect.DeviceServiceClient
	partitionCli    partitionv1connect.PartitionServiceClient
	notificationCli notificationv1connect.NotificationServiceClient

	iCache cache.Cache[string, models.LoginEvent]

	// Repository dependencies
	loginRepo      repository.LoginRepository
	apiKeyRepo     repository.APIKeyRepository
	loginEventRepo repository.LoginEventRepository

	// Login options enabled
	loginOptions map[string]any

	loginAuthProviders map[string]providers.AuthProvider

	defaultHydraCli hydra.Hydra
}

func NewAuthServer(ctx context.Context,
	securityAuth security.Authenticator, authConfig *aconfig.AuthenticationConfig,
	cacheMan cache.Manager,
	loginRepository repository.LoginRepository, loginEventRepository repository.LoginEventRepository,
	apiKeyRepository repository.APIKeyRepository,
	profileCli profilev1connect.ProfileServiceClient, deviceCli devicev1connect.DeviceServiceClient,
	partitionCli partitionv1connect.PartitionServiceClient, notificationCli notificationv1connect.NotificationServiceClient) *AuthServer {

	log := util.Log(ctx)

	var httpOpts []client.HTTPOption
	if authConfig.TraceReq() {
		httpOpts = append(httpOpts, client.WithHTTPTraceRequests(), client.WithHTTPTraceRequestHeaders())
	}

	httpCli := client.NewHTTPClient(ctx, httpOpts...)
	hydraCli := hydra.NewDefaultHydra(httpCli, authConfig.GetOauth2ServiceAdminURI())

	h := &AuthServer{

		cacheMan:     cacheMan,
		securityAuth: securityAuth,

		config:          authConfig,
		profileCli:      profileCli,
		deviceCli:       deviceCli,
		partitionCli:    partitionCli,
		notificationCli: notificationCli,

		// Initialise repositories
		loginRepo:      loginRepository,
		apiKeyRepo:     apiKeyRepository,
		loginEventRepo: loginEventRepository,

		defaultHydraCli: hydraCli,
	}

	err := h.setupSecureCookies(ctx, authConfig)
	if err != nil {
		log.WithError(err).Fatal("Failed to setup secure cookies")
	}

	h.setupLoginOptions(authConfig)

	authProviders, provErr := providers.SetupAuthProviders(ctx, authConfig)
	if provErr != nil {
		log.WithError(provErr).Error("failed to setup auth providers - provider login will be unavailable")
	} else {
		h.loginAuthProviders = authProviders
		for name := range authProviders {
			log.WithField("provider", name).Info("auth provider registered")
		}
	}

	return h
}

func (h *AuthServer) loginEventCache() cache.Cache[string, models.LoginEvent] {

	if h.iCache == nil {

		rCache, ok := h.cacheMan.GetRawCache(h.config.CacheName)
		if !ok {
			return nil
		}

		h.iCache = cache.NewGenericCache[string, models.LoginEvent](rCache, func(k string) string {
			return k
		})
	}
	return h.iCache
}

func (h *AuthServer) Config() *aconfig.AuthenticationConfig {
	return h.config
}

func (h *AuthServer) ProfileCli() profilev1connect.ProfileServiceClient {
	return h.profileCli
}

func (h *AuthServer) DeviceCli() devicev1connect.DeviceServiceClient {
	return h.deviceCli
}

func (h *AuthServer) PartitionCli() partitionv1connect.PartitionServiceClient {
	return h.partitionCli
}

func (h *AuthServer) NotificationCli() notificationv1connect.NotificationServiceClient {
	return h.notificationCli
}

func (h *AuthServer) LoginEventRepo() repository.LoginEventRepository {
	return h.loginEventRepo
}

// setupSecureCookies initialises the StateCodec used for encrypting cookie values.
// It uses the SecureCookieBlockKey from config as the AES-256-GCM encryption key.
func (h *AuthServer) setupSecureCookies(_ context.Context, cfg *aconfig.AuthenticationConfig) error {
	blockKey, err := hex.DecodeString(cfg.SecureCookieBlockKey)
	if err != nil {
		return fmt.Errorf("failed to decode secure cookie block key: %w", err)
	}

	// AES-256 requires exactly 32 bytes
	if len(blockKey) != 32 {
		return fmt.Errorf("secure cookie block key must be 32 bytes (64 hex chars), got %d bytes", len(blockKey))
	}

	codec, err := providers.NewStateCodec(blockKey)
	if err != nil {
		return fmt.Errorf("failed to create state codec: %w", err)
	}

	h.cookiesCodec = codec
	return nil
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const genericErrorMessage = "An unexpected error occurred. Please try again later."

// redirectToErrorPage redirects to the error page with appropriate error details.
// If ExposeErrors is false, only generic messages are shown to users.
func (h *AuthServer) redirectToErrorPage(w http.ResponseWriter, r *http.Request, err error, errorTitle string) {
	log := util.Log(r.Context())

	// Always log the full error details
	log.WithError(err).WithField("error_title", errorTitle).Error("redirecting to error page")

	// Determine what to show the user
	var displayTitle, displayDescription string
	if h.config.ExposeErrors {
		displayTitle = errorTitle
		displayDescription = err.Error()
	} else {
		displayTitle = "Error"
		displayDescription = genericErrorMessage
	}

	// Build redirect URL with error parameters
	errorURL := fmt.Sprintf("/error?error=%s&error_description=%s",
		url.QueryEscape(displayTitle),
		url.QueryEscape(displayDescription))

	http.Redirect(w, r, errorURL, http.StatusSeeOther)
}

func initTemplatePayload(ctx context.Context) map[string]any {
	payload := make(map[string]any)

	deviceId := utils.DeviceIDFromContext(ctx)
	payload["DeviceID"] = deviceId

	return payload
}

// writeAPIError writes a JSON error response for API endpoints.
// Always logs the full error but only exposes details if ExposeErrors is enabled.
func (h *AuthServer) writeAPIError(ctx context.Context, w http.ResponseWriter, err error, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")

	log := util.Log(ctx).
		WithField("code", code).
		WithField("message", msg).WithError(err)
	log.Error("API error")
	w.WriteHeader(code)

	// Determine what message to show
	var displayMessage string
	if h.config.ExposeErrors {
		displayMessage = fmt.Sprintf("%s: %s", msg, err.Error())
	} else {
		displayMessage = genericErrorMessage
	}

	encodeErr := json.NewEncoder(w).Encode(&ErrorResponse{
		Code:    code,
		Message: displayMessage,
	})
	if encodeErr != nil {
		log.WithError(encodeErr).Error("could not write error to response")
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

		extras, _ := structpb.NewStruct(map[string]any{"refer": r.Referer()})

		req := devicev1.LogRequest{
			SessionId: sessionID,
			Ip:        ipAddr,
			UserAgent: userAgent,
			LastSeen:  time.Now().String(),
			Extras:    extras,
		}

		if deviceID != "" {
			req.DeviceId = deviceID
		}

		_, err := h.DeviceCli().Log(ctx, connect.NewRequest(&req))
		if err != nil {
			util.Log(ctx).WithField("device_id", deviceID).WithField("session_id", sessionID).WithError(err).Debug("device session log error")
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
			if decodeErr := h.cookiesCodec.Decode(SessionKeyDeviceIDKey, deviceCookie.Value, &deviceID); decodeErr != nil {
				util.Log(ctx).WithError(decodeErr).Debug("failed to decode device ID cookie")
			}
		}

		// Try to get the existing session ID cookie
		sessionCookie, err := r.Cookie(SessionKeySessionStorageName)
		if err == nil {
			// Decode and verify the session ID cookie
			if decodeErr := h.cookiesCodec.Decode(SessionKeyDeviceSessionIDKey, sessionCookie.Value, &sessionID); decodeErr == nil {
				sessionIDExists = true
			}
		}

		// If session ID doesn't exist, create a new one
		if !sessionIDExists {
			sessionID = util.IDString()

			// Encode and sign the session ID cookie
			encoded, encodeErr := h.cookiesCodec.Encode(SessionKeyDeviceSessionIDKey, sessionID)
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
				SameSite: http.SameSiteLaxMode,
				Expires:  time.Now().Add(30 * time.Minute),
			})
		}

		if deviceID != "" {
			// Add both device ID and session ID to context
			ctx = utils.DeviceIDToContext(ctx, deviceID)
		}
		ctx = utils.SessionIDToContext(ctx, sessionID)
		r = r.WithContext(ctx)

		// Perform device logging asynchronously to avoid blocking the request
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			performDeviceLog(bgCtx, r, deviceID, sessionID)
		}()

		// Continue to the next handler
		next.ServeHTTP(w, r)
	})
}

func (h *AuthServer) addHandler(router *http.ServeMux,
	f func(w http.ResponseWriter, r *http.Request) error, path string, name string, method string) {

	router.HandleFunc(fmt.Sprintf("%s %s", method, path), func(w http.ResponseWriter, r *http.Request) {
		err := f(w, r)
		if err != nil {
			h.writeAPIError(r.Context(), w, err, http.StatusInternalServerError, name)
		}
	})
}

// SwaggerEndpoint serves the OpenAPI specification as JSON
func (h *AuthServer) SwaggerEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()

	// Try multiple locations for the OpenAPI JSON file
	possiblePaths := []string{
		"openapi.json",                     // Current directory
		"apps/default/openapi.json",        // Relative to project root
		"./openapi.json",                   // Explicit current directory
		"../openapi.json",                  // Parent directory
		"../../openapi.json",               // Two levels up
		"openapi-apikey.json",              // Alternative naming in current dir
		"apps/default/openapi-apikey.json", // Alternative naming in apps/default
	}

	var jsonData []byte
	var err error
	var foundPath string

	// Try each path until we find the file
	for _, path := range possiblePaths {
		jsonData, err = os.ReadFile(path)
		if err == nil {
			foundPath = path
			break
		}
	}

	// If no file found in any location, return error
	if foundPath == "" {
		util.Log(ctx).WithError(err).Error("could not find OpenAPI JSON file in any expected location")
		return fmt.Errorf("OpenAPI specification file not found")
	}

	// Set headers and serve the JSON content directly
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	rw.WriteHeader(http.StatusOK)

	// Write the JSON content directly without parsing/encoding
	_, err = rw.Write(jsonData)
	return err
}
