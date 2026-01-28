package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	client "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/util"
)

// Login flow error definitions for consistent error handling
var (
	ErrLoginChallengeNotFound = errors.New("login_challenge not found")
	ErrLoginEventNotFound     = errors.New("login_event not found")
	ErrClientIDMissing        = errors.New("client_id is required for login")
	ErrLoginEventCacheFailure = errors.New("failed to cache login event")
)

// Cache key prefix for login events to avoid collisions
// Note: NATS JetStream KV only allows alphanumeric, dash, underscore, slash, equals, and period in keys
const loginEventCachePrefix = "login_event_"

const SessionKeyLoginStorageName = "login-storage"
const SessionKeyLoginEventID = "login-event-id"

// updateTenancyForLoginEvent enriches the login event with partition/tenant info.
// This is designed to run asynchronously to avoid blocking the login response.
func (h *AuthServer) updateTenancyForLoginEvent(ctx context.Context, loginEventID string) {
	log := util.Log(ctx).WithField("login_event_id", loginEventID)
	start := time.Now()

	loginEvt, err := h.getLoginEventFromCache(ctx, loginEventID)
	if err != nil {
		log.WithError(err).WithField("duration_ms", time.Since(start).Milliseconds()).
			Error("cache lookup failed for login event")
		return
	}

	if loginEvt.ClientID == "" {
		log.Warn("login event missing client_id - cannot enrich with partition info")
		return
	}

	partitionResp, err := h.partitionCli.GetPartition(ctx, connect.NewRequest(&partitionv1.GetPartitionRequest{Id: loginEvt.ClientID}))
	if err != nil {
		log.WithError(err).WithField("client_id", loginEvt.ClientID).
			Error("partition lookup failed")
		return
	}

	partitionObj := partitionResp.Msg.GetData()
	if partitionObj == nil {
		log.WithField("client_id", loginEvt.ClientID).
			Warn("partition not found for client")
		return
	}

	loginEvt.PartitionID = partitionObj.GetId()
	loginEvt.TenantID = partitionObj.GetTenantId()

	if err = h.setLoginEventToCache(ctx, loginEvt); err != nil {
		log.WithError(err).Error("failed to update login event cache with partition info")
		return
	}

	log.WithFields(map[string]any{
		"partition_id": loginEvt.PartitionID,
		"tenant_id":    loginEvt.TenantID,
		"duration_ms":  time.Since(start).Milliseconds(),
	}).Debug("login event enriched with partition info")
}

// createLoginEvent creates a new login event and caches it for the OAuth2 flow.
// Returns the created event or an error if caching fails.
func (h *AuthServer) createLoginEvent(ctx context.Context, req *http.Request, loginReq *client.OAuth2LoginRequest, loginChallenge string) (*models.LoginEvent, error) {
	log := util.Log(ctx)
	start := time.Now()

	deviceSessionID := utils.SessionIDFromContext(ctx)

	cli, ok := loginReq.GetClientOk()
	if !ok || cli.GetClientId() == "" {
		log.WithField("oauth2_session_id", loginReq.GetSessionId()).
			Error("login request missing client_id")
		return nil, ErrClientIDMissing
	}

	clientID := cli.GetClientId()
	loginEvt := models.LoginEvent{
		ClientID:         clientID,
		LoginChallengeID: loginChallenge,
		SessionID:        deviceSessionID,
		Oauth2SessionID:  loginReq.GetSessionId(),
		IP:               util.GetIP(req),
	}
	loginEvt.ID = util.IDString()

	if err := h.setLoginEventToCache(ctx, &loginEvt); err != nil {
		log.WithError(err).WithFields(map[string]any{
			"login_event_id": loginEvt.GetID(),
			"client_id":      clientID,
		}).Error("failed to cache login event")
		return nil, fmt.Errorf("%w: %v", ErrLoginEventCacheFailure, err)
	}

	log.WithFields(map[string]any{
		"login_event_id": loginEvt.GetID(),
		"client_id":      clientID,
		"session_id":     deviceSessionID,
		"oauth2_session": loginReq.GetSessionId(),
		"duration_ms":    time.Since(start).Milliseconds(),
	}).Debug("login event created and cached")

	return &loginEvt, nil
}

// LoginEndpointShow displays the login page for OAuth2 authorization flow.
// It validates the login challenge, checks for session skip, and renders the login form.
func (h *AuthServer) LoginEndpointShow(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx)

	hydraCli := h.defaultHydraCli

	// Step 1: Extract and validate login challenge
	loginChallenge, err := hydra.GetLoginChallengeID(req)
	if err != nil {
		log.WithError(err).WithField("url", req.URL.String()).
			Warn("missing or invalid login_challenge parameter")
		return fmt.Errorf("%w: %v", ErrLoginChallengeNotFound, err)
	}

	// Use first 16 chars of challenge for logging (avoid logging full challenge)
	challengePrefix := loginChallenge
	if len(challengePrefix) > 16 {
		challengePrefix = challengePrefix[:16]
	}
	log = log.WithField("login_challenge_prefix", challengePrefix)

	// Step 2: Fetch login request from Hydra
	getLogReq, err := hydraCli.GetLoginRequest(ctx, loginChallenge)
	if err != nil {
		log.WithError(err).Error("hydra login request lookup failed")
		return fmt.Errorf("failed to get login request from hydra: %w", err)
	}

	// Step 3: Handle session skip (already authenticated)
	if getLogReq.Skip {
		subjectID := getLogReq.GetSubject()
		log.WithField("subject_id", subjectID).Debug("skipping login - session already exists")

		params := &hydra.AcceptLoginRequestParams{
			LoginChallenge: loginChallenge,
			SubjectID:      subjectID,

			ExtendSession:    true,
			Remember:         true,
			RememberDuration: h.config.SessionRememberDuration,
		}

		var loginCtx map[string]any
		redirectURL, acceptErr := hydraCli.AcceptLoginRequest(ctx, params, loginCtx, "session_refresh")
		if acceptErr != nil {
			log.WithError(acceptErr).Error("failed to accept login request for session skip")
			return fmt.Errorf("failed to accept login request: %w", acceptErr)
		}

		log.WithFields(map[string]any{
			"subject_id":  subjectID,
			"duration_ms": time.Since(start).Milliseconds(),
		}).Info("login skipped - redirecting to OAuth2 flow")

		http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
		return nil
	}

	// Step 3.5: Attempt remember-me auto-login
	rememberMeLoginEventID := h.getRememberMeLoginEventID(req)
	if rememberMeLoginEventID != "" {
		redirectURL, rememberErr := h.attemptRememberMeLogin(ctx, req, loginChallenge, getLogReq, rememberMeLoginEventID)
		if rememberErr == nil {
			log.WithField("old_login_event_id", rememberMeLoginEventID).
				Info("remember-me auto-login successful")
			http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
			return nil
		}
		log.WithError(rememberErr).Debug("remember-me auto-login failed - showing login form")
	}

	// Step 4: Create login event for new authentication
	loginEvent, err := h.createLoginEvent(ctx, req, getLogReq, loginChallenge)
	if err != nil {
		log.WithError(err).Error("failed to create login event")
		return err
	}

	// Step 5: Enrich login event with partition info asynchronously
	// This runs in background to avoid blocking the login page response
	go func() {

		bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		h.updateTenancyForLoginEvent(bgCtx, loginEvent.GetID())
	}()

	// Step 6: Prepare and render login template
	payload := initTemplatePayload(ctx)
	payload[pathValueLoginEventID] = loginEvent.GetID()
	payload["error"] = ""

	for k, val := range h.loginOptions {
		payload[k] = val
	}

	log.WithFields(map[string]any{
		"login_event_id": loginEvent.GetID(),
		"client_id":      loginEvent.ClientID,
		"duration_ms":    time.Since(start).Milliseconds(),
	}).Info("login page rendered")

	return loginTmpl.Execute(rw, payload)
}

// getRememberMeLoginEventID reads and decodes the remember-me cookie, returning
// the stored login event ID or an empty string on any failure.
func (h *AuthServer) getRememberMeLoginEventID(req *http.Request) string {
	cookie, err := req.Cookie(SessionKeyRememberMeStorageName)
	if err != nil {
		return ""
	}

	var loginEventID string
	if decodeErr := h.cookiesCodec.Decode(SessionKeyRememberMeLoginEventIDKey, cookie.Value, &loginEventID); decodeErr == nil {
		return loginEventID
	}
	return ""
}

// attemptRememberMeLogin tries to auto-login a returning user by looking up a
// previous login event (stored in the remember-me cookie) and creating a new
// login event that copies the profile/tenant context from the old one.
// Returns the redirect URL on success or an error on any failure.
func (h *AuthServer) attemptRememberMeLogin(ctx context.Context, req *http.Request,
	loginChallenge string, loginReq *client.OAuth2LoginRequest, oldLoginEventID string) (string, error) {

	oldLoginEvent, err := h.loginEventRepo.GetByID(ctx, oldLoginEventID)
	if err != nil || oldLoginEvent == nil {
		return "", fmt.Errorf("old login event not found: %w", err)
	}

	if oldLoginEvent.ProfileID == "" {
		return "", fmt.Errorf("old login event has no profile ID")
	}

	// Security: Verify the old login event was for the same OAuth2 client
	// This prevents session reuse across different OAuth2 clients
	cli, ok := loginReq.GetClientOk()
	if !ok || cli.GetClientId() == "" {
		return "", fmt.Errorf("current login request missing client_id")
	}
	if oldLoginEvent.ClientID != cli.GetClientId() {
		util.Log(ctx).WithFields(map[string]any{
			"old_client_id": oldLoginEvent.ClientID,
			"new_client_id": cli.GetClientId(),
		}).Warn("remember-me session rejected: client_id mismatch")
		return "", fmt.Errorf("session client mismatch")
	}

	deviceSessionID := utils.SessionIDFromContext(ctx)

	newLoginEvent := models.LoginEvent{
		ClientID:         oldLoginEvent.ClientID,
		LoginID:          oldLoginEvent.LoginID,
		LoginChallengeID: loginChallenge,
		ContactID:        oldLoginEvent.ContactID,
		ProfileID:        oldLoginEvent.ProfileID,
		SessionID:        deviceSessionID,
		Oauth2SessionID:  loginReq.GetSessionId(),
		DeviceID:         oldLoginEvent.DeviceID,
		IP:               util.GetIP(req),
		Client:           req.UserAgent(),
	}
	newLoginEvent.ID = util.IDString()
	newLoginEvent.TenantID = oldLoginEvent.TenantID
	newLoginEvent.PartitionID = oldLoginEvent.PartitionID
	newLoginEvent.AccessID = oldLoginEvent.AccessID

	if err = h.loginEventRepo.Create(ctx, &newLoginEvent); err != nil {
		return "", fmt.Errorf("failed to persist remember-me login event: %w", err)
	}

	if cacheErr := h.setLoginEventToCache(ctx, &newLoginEvent); cacheErr != nil {
		util.Log(ctx).WithError(cacheErr).Debug("failed to cache remember-me login event")
	}

	loginContext := map[string]any{
		"login_event_id": newLoginEvent.GetID(),
	}

	params := &hydra.AcceptLoginRequestParams{
		LoginChallenge:   loginChallenge,
		SubjectID:        oldLoginEvent.ProfileID,
		ExtendSession:    true,
		Remember:         true,
		RememberDuration: h.config.SessionRememberDuration,
	}

	redirectURL, err := h.defaultHydraCli.AcceptLoginRequest(ctx, params, loginContext, "remembered", oldLoginEvent.ContactID)
	if err != nil {
		return "", fmt.Errorf("failed to accept login request for remember-me: %w", err)
	}

	return redirectURL, nil
}

// getLoginEventFromCache retrieves a login event from cache with consistent error handling.
// Returns the login event, or an error if not found or cache failure.
func (h *AuthServer) getLoginEventFromCache(ctx context.Context, loginEventID string) (*models.LoginEvent, error) {
	if loginEventID == "" {
		return nil, ErrLoginEventNotFound
	}

	cacheKey := loginEventCachePrefix + loginEventID
	loginEvt, ok, err := h.loginEventCache().Get(ctx, cacheKey)
	if err != nil {
		util.Log(ctx).WithError(err).WithFields(map[string]any{
			"login_event_id": loginEventID,
			"cache_key":      cacheKey,
		}).Error("cache error retrieving login event")
		return nil, fmt.Errorf("cache error: %w", err)
	}
	if !ok {
		util.Log(ctx).WithField("login_event_id", loginEventID).
			Warn("login event not found in cache - may have expired")
		return nil, ErrLoginEventNotFound
	}

	return &loginEvt, nil
}

func (h *AuthServer) setLoginEventToCache(ctx context.Context, loginEvent *models.LoginEvent) error {
	cacheKey := loginEventCachePrefix + loginEvent.GetID()
	if err := h.loginEventCache().Set(ctx, cacheKey, *loginEvent, time.Hour); err != nil {
		util.Log(ctx).WithError(err).Error("failed to update login event cache with partition info")
		return err
	}
	return nil
}
