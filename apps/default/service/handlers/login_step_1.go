package handlers

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	client "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/frame/data"
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

	partitionObj, err := h.resolvePartitionByClientID(ctx, loginEvt.ClientID)
	if err != nil {
		log.WithError(err).WithField("client_id", loginEvt.ClientID).
			Warn("partition lookup failed for login event enrichment")
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
		Client:           req.UserAgent(),
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
		oauth2SessionID := getLogReq.GetSessionId()
		log.WithFields(map[string]any{
			"subject_id":        subjectID,
			"oauth2_session_id": oauth2SessionID,
		}).Debug("skipping login - session already exists")

		skipLoginEvent, skipErr := h.ensureLoginEventForSkippedLogin(ctx, req, getLogReq, loginChallenge, subjectID)
		if skipErr != nil {
			log.WithError(skipErr).Error("failed to resolve login event for skipped login")
			return fmt.Errorf("failed to resolve skipped-login event: %w", skipErr)
		}

		params := &hydra.AcceptLoginRequestParams{
			LoginChallenge: loginChallenge,
			SubjectID:      subjectID,
			SessionID:      skipLoginEvent.GetID(),

			ExtendSession:    true,
			Remember:         true,
			RememberDuration: h.config.SessionRememberDuration,
		}

		loginCtx := map[string]any{
			"login_event_id": skipLoginEvent.GetID(),
		}

		redirectURL, acceptErr := hydraCli.AcceptLoginRequest(ctx, params, loginCtx, "session_refresh")
		if acceptErr != nil {
			log.WithError(acceptErr).Error("failed to accept login request for session skip")
			return fmt.Errorf("failed to accept login request: %w", acceptErr)
		}

		log.WithFields(map[string]any{
			"subject_id":     subjectID,
			"login_event_id": skipLoginEvent.GetID(),
			"duration_ms":    time.Since(start).Milliseconds(),
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

	// Step 5: Enrich login event with partition info synchronously
	// This must complete before the user can submit their contact to ensure
	// proper tenancy context for verification creation
	h.updateTenancyForLoginEvent(ctx, loginEvent.GetID())

	// Step 6: Prepare and render login template
	payload := h.initTemplatePayloadWithI18n(ctx, req)
	payload[pathValueLoginEventID] = loginEvent.GetID()
	payload["error"] = ""

	maps.Copy(payload, h.loginOptions)

	log.WithFields(map[string]any{
		"login_event_id": loginEvent.GetID(),
		"client_id":      loginEvent.ClientID,
		"duration_ms":    time.Since(start).Milliseconds(),
	}).Info("login page rendered")

	return loginTmpl.Execute(rw, payload)
}

// ensureLoginEventForSkippedLogin guarantees that Hydra skip flows still carry a
// durable login_event record and tenancy access context.
func (h *AuthServer) ensureLoginEventForSkippedLogin(
	ctx context.Context,
	req *http.Request,
	loginReq *client.OAuth2LoginRequest,
	loginChallenge string,
	subjectID string,
) (*models.LoginEvent, error) {
	if loginReq == nil {
		return nil, fmt.Errorf("login request is required")
	}
	if subjectID == "" {
		return nil, fmt.Errorf("subject_id is required for skipped login")
	}

	cli, ok := loginReq.GetClientOk()
	if !ok || cli.GetClientId() == "" {
		return nil, fmt.Errorf("client_id is required for skipped login")
	}
	clientID := cli.GetClientId()
	oauth2SessionID := loginReq.GetSessionId()

	existingLoginEvent, err := h.resolveExistingSkippedLoginEvent(ctx, oauth2SessionID, clientID, subjectID)
	if err != nil {
		return nil, err
	}

	loginRecord, err := h.resolveSkippedLoginRecord(ctx, subjectID, clientID, existingLoginEvent)
	if err != nil {
		return nil, err
	}

	// Ensure device tracking for the skip flow. Non-browser clients (mobile apps, bots)
	// won't have device cookies, so we create/find a device using the session or User-Agent.
	userAgent := req.UserAgent()
	deviceID := h.resolveSkippedLoginDeviceID(ctx, subjectID, userAgent, existingLoginEvent)
	newLoginEvent := newSkippedLoginEvent(req, loginChallenge, clientID, subjectID, oauth2SessionID, userAgent, deviceID, loginRecord, existingLoginEvent)
	newLoginEvent.ID = util.IDString()

	if err = h.loginEventRepo.Create(ctx, newLoginEvent); err != nil {
		return nil, fmt.Errorf("failed to create login event for skipped login: %w", err)
	}

	newLoginEvent, err = h.ensureLoginEventTenancyAccess(ctx, newLoginEvent, clientID, subjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to apply tenancy context to skipped login event: %w", err)
	}

	if cacheErr := h.setLoginEventToCache(ctx, newLoginEvent); cacheErr != nil {
		util.Log(ctx).WithError(cacheErr).Debug("failed to cache skipped-login event")
	}

	return newLoginEvent, nil
}

func (h *AuthServer) resolveExistingSkippedLoginEvent(
	ctx context.Context,
	oauth2SessionID string,
	clientID string,
	subjectID string,
) (*models.LoginEvent, error) {
	if oauth2SessionID == "" {
		return nil, nil
	}

	existing, err := h.loginEventRepo.GetByOauth2SessionID(ctx, oauth2SessionID)
	if err != nil {
		if data.ErrorIsNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to resolve login event by oauth2_session_id: %w", err)
	}
	if existing == nil {
		return nil, nil
	}
	if existing.ClientID != "" && existing.ClientID != clientID {
		return nil, fmt.Errorf("existing login event client mismatch")
	}
	if existing.ProfileID != "" && existing.ProfileID != subjectID {
		return nil, fmt.Errorf("existing login event subject mismatch")
	}

	return existing, nil
}

func (h *AuthServer) resolveSkippedLoginRecord(
	ctx context.Context,
	subjectID string,
	clientID string,
	existingLoginEvent *models.LoginEvent,
) (*models.Login, error) {
	loginRecord, err := h.loginRepo.GetByProfileID(ctx, subjectID)
	if err != nil {
		if !data.ErrorIsNoRows(err) {
			return nil, fmt.Errorf("failed to resolve login record: %w", err)
		}
		loginRecord = &models.Login{
			ProfileID: subjectID,
			ClientID:  clientID,
			Source:    string(models.LoginSourceSessionRefresh),
		}
		loginRecord.GenID(ctx)
		if createErr := h.loginRepo.Create(ctx, loginRecord); createErr != nil {
			return nil, fmt.Errorf("failed to create login record for skipped login: %w", createErr)
		}
	}
	if existingLoginEvent != nil && existingLoginEvent.LoginID != "" {
		loginRecord.ID = existingLoginEvent.LoginID
	}

	return loginRecord, nil
}

func (h *AuthServer) resolveSkippedLoginDeviceID(
	ctx context.Context,
	subjectID string,
	userAgent string,
	existingLoginEvent *models.LoginEvent,
) string {
	deviceID := utils.DeviceIDFromContext(ctx)
	deviceObj, deviceErr := h.processDeviceSession(ctx, subjectID, userAgent)
	if deviceErr != nil {
		util.Log(ctx).WithError(deviceErr).Warn("device session processing failed during skip-login")
	}
	if deviceObj != nil && deviceObj.GetId() != "" {
		deviceID = deviceObj.GetId()
	}
	if deviceID == "" && existingLoginEvent != nil {
		deviceID = existingLoginEvent.DeviceID
	}
	return deviceID
}

func newSkippedLoginEvent(
	req *http.Request,
	loginChallenge string,
	clientID string,
	subjectID string,
	oauth2SessionID string,
	userAgent string,
	deviceID string,
	loginRecord *models.Login,
	existingLoginEvent *models.LoginEvent,
) *models.LoginEvent {
	newLoginEvent := &models.LoginEvent{
		ClientID:         clientID,
		LoginID:          loginRecord.GetID(),
		LoginChallengeID: loginChallenge,
		ProfileID:        subjectID,
		SessionID:        utils.SessionIDFromContext(req.Context()),
		Oauth2SessionID:  oauth2SessionID,
		DeviceID:         deviceID,
		IP:               util.GetIP(req),
		Client:           userAgent,
	}
	if existingLoginEvent != nil {
		newLoginEvent.ContactID = existingLoginEvent.ContactID
		newLoginEvent.AccessID = existingLoginEvent.AccessID
		newLoginEvent.TenantID = existingLoginEvent.TenantID
		newLoginEvent.PartitionID = existingLoginEvent.PartitionID
	}
	return newLoginEvent
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
		SessionID:        newLoginEvent.GetID(),
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

	eventCache := h.loginEventCache()
	if eventCache == nil {
		util.Log(ctx).Warn("login event cache unavailable - falling back to database lookup")
		return h.loginEventRepo.GetByID(ctx, loginEventID)
	}

	cacheKey := loginEventCachePrefix + loginEventID
	loginEvt, ok, err := eventCache.Get(ctx, cacheKey)
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
	eventCache := h.loginEventCache()
	if eventCache == nil {
		util.Log(ctx).Debug("login event cache unavailable - skipping cache update")
		return nil
	}

	cacheKey := loginEventCachePrefix + loginEvent.GetID()
	if err := eventCache.Set(ctx, cacheKey, *loginEvent, time.Hour); err != nil {
		util.Log(ctx).WithError(err).Error("failed to update login event cache with partition info")
		return err
	}
	return nil
}
