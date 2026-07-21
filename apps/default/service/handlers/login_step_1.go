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
	"errors"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	client "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/util"
)

// Login flow error definitions for consistent error handling
var (
	ErrLoginChallengeNotFound = errors.New("login_challenge not found")
	ErrLoginEventNotFound     = errors.New("login_event not found")
	ErrClientIDMissing        = errors.New("client_id is required for login")
	ErrLoginEventCacheFailure = errors.New("failed to cache login event")
)

// loginEventPropertyFedCMNonce holds the per-login nonce we pass into
// navigator.credentials.get({identity: …}) on /s/login. The id_token returned
// by FedCM (from either our own IdP or a federated provider like Google) MUST
// carry this exact value in its "nonce" claim, otherwise the completion
// endpoints reject it as a replay or substitution attempt. Persisting the
// nonce here — rather than re-deriving it from a cookie or signed token —
// gives us a single server-controlled binding that's destroyed alongside the
// LoginEvent when the login completes.
const loginEventPropertyFedCMNonce = "fedcm_nonce"

const SessionKeyLoginStorageName = "login-storage"
const SessionKeyLoginEventID = "login-event-id"

// updateTenancyForLoginEvent enriches a cached login event with partition/tenant
// info. Used by paths that already have a login_event_id (e.g. Google FedCM
// completion) and can tolerate soft failure. For the initial GET /s/login form
// render use softEnrichLoginEventTenancy with the Hydra login request instead —
// that path is budgeted and never blocks page render on tenancy RPC hangs.
//
// Resolution order (when not soft-enriching from the login request):
//  1. Tenancy service GetOAuthClient → partition
//  2. Hydra OAuth2 client metadata tenant_id/partition_id
func (h *AuthServer) updateTenancyForLoginEvent(ctx context.Context, loginEventID string) {
	log := util.Log(ctx).WithField("login_event_id", loginEventID)
	start := time.Now()

	// Soft budget so callers (FedCM) cannot hang for Frame's 30s default.
	budgetCtx, cancel := context.WithTimeout(ctx, loginSoftTenancyBudget)
	defer cancel()

	loginEvt, err := h.getLoginEventFromCache(budgetCtx, loginEventID)
	if err != nil {
		log.WithError(err).WithField("duration_ms", time.Since(start).Milliseconds()).
			Error("cache lookup failed for login event")
		return
	}

	if loginEvt.ClientID == "" {
		log.Warn("login event missing client_id - cannot enrich with partition info")
		return
	}

	// Prefer Hydra admin first (no self-token loop), then tenancy best-effort.
	source := tenancySourceHydraAdmin
	adminCtx, adminCancel := context.WithTimeout(budgetCtx, loginHydraAdminTimeout)
	tenantID, partitionID, metaErr := h.tenancyIDsFromHydraClient(adminCtx, loginEvt.ClientID)
	adminCancel()
	if metaErr == nil {
		loginEvt.TenantID = tenantID
		loginEvt.PartitionID = partitionID
	} else {
		tenCtx, tenCancel := context.WithTimeout(budgetCtx, loginTenancySoftTimeout)
		partitionObj, partErr := h.resolvePartitionByClientID(tenCtx, loginEvt.ClientID)
		tenCancel()
		if partErr != nil || partitionObj == nil {
			log.WithError(metaErr).WithField("client_id", loginEvt.ClientID).
				Warn("login event tenancy enrichment failed within soft budget")
			return
		}
		loginEvt.PartitionID = partitionObj.GetId()
		loginEvt.TenantID = partitionObj.GetTenantId()
		source = tenancySourceTenancy
	}

	if !ValidTenancyPair(loginEvt.TenantID, loginEvt.PartitionID) {
		log.WithFields(map[string]any{
			"client_id":    loginEvt.ClientID,
			"tenant_id":    loginEvt.TenantID,
			"partition_id": loginEvt.PartitionID,
		}).Warn("resolved incomplete tenancy pair for login event")
		return
	}

	if err = h.setLoginEventToCache(budgetCtx, loginEvt); err != nil {
		log.WithError(err).Error("failed to update login event cache with partition info")
		return
	}

	log.WithFields(map[string]any{
		"partition_id":   loginEvt.PartitionID,
		"tenant_id":      loginEvt.TenantID,
		"tenancy_source": source,
		"duration_ms":    time.Since(start).Milliseconds(),
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

	h.emitAnalyticsEvent(ctx, req, "", evtLoginEventCreated, map[string]any{
		"login_event_id": loginEvt.GetID(),
		"client_id":      clientID,
	})

	return &loginEvt, nil
}

// LoginEndpointShow displays the login page for OAuth2 authorization flow.
// It validates the login challenge, checks for session skip, and renders the login form.
//
// Latency: per-branch budgets (see latency_budgets.go). Form render soft-enriches
// tenancy and always paints the form within loginFormBudget when Hydra is healthy.
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

	// Step 2: Fetch login request from Hydra (hard budget)
	hydraCtx, hydraCancel := context.WithTimeout(ctx, loginHydraTimeout)
	getLogReq, err := hydraCli.GetLoginRequest(hydraCtx, loginChallenge)
	hydraCancel()
	if err != nil {
		log.WithError(err).Error("hydra login request lookup failed")
		return fmt.Errorf("failed to get login request from hydra: %w", err)
	}

	// Step 3: Handle session skip (already authenticated) — distinct budget
	if getLogReq.Skip {
		subjectID := getLogReq.GetSubject()
		oauth2SessionID := getLogReq.GetSessionId()
		log.WithFields(map[string]any{
			"subject_id":        subjectID,
			"oauth2_session_id": oauth2SessionID,
		}).Debug("skipping login - session already exists")

		skipCtx, skipCancel := context.WithTimeout(ctx, skipLoginBudget)
		defer skipCancel()

		skipLoginEvent, skipErr := h.ensureLoginEventForSkippedLogin(skipCtx, req, getLogReq, loginChallenge, subjectID)
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

		redirectURL, acceptErr := hydraCli.AcceptLoginRequest(skipCtx, params, loginCtx, "session_refresh")
		if acceptErr != nil {
			log.WithError(acceptErr).Error("failed to accept login request for session skip")
			return fmt.Errorf("failed to accept login request: %w", acceptErr)
		}

		log.WithFields(map[string]any{
			"subject_id":     subjectID,
			"login_event_id": skipLoginEvent.GetID(),
			"duration_ms":    time.Since(start).Milliseconds(),
		}).Info("login skipped - redirecting to OAuth2 flow")

		setLoginStatusLoggedIn(rw)
		http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
		return nil
	}

	// Step 3.5: Attempt remember-me auto-login (soft budget — fall through to form)
	rememberMeLoginEventID := h.getRememberMeLoginEventID(req)
	if rememberMeLoginEventID != "" {
		remCtx, remCancel := context.WithTimeout(ctx, rememberMeSoftBudget)
		redirectURL, rememberErr := h.attemptRememberMeLogin(remCtx, req, loginChallenge, getLogReq, rememberMeLoginEventID)
		remCancel()
		if rememberErr == nil {
			log.WithField("old_login_event_id", rememberMeLoginEventID).
				Info("remember-me auto-login successful")
			setLoginStatusLoggedIn(rw)
			http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
			return nil
		}
		log.WithError(rememberErr).Debug("remember-me auto-login failed - showing login form")
	}

	// Step 4–7: New authentication form path (form budget)
	formCtx, formCancel := context.WithTimeout(ctx, loginFormBudget)
	defer formCancel()

	loginEvent, err := h.createLoginEvent(formCtx, req, getLogReq, loginChallenge)
	if err != nil {
		log.WithError(err).Error("failed to create login event")
		return err
	}

	// Soft tenancy: never block form render on tenancy/token loops.
	// Strong tenancy is enforced at verification complete and consent.
	tenancySource := h.softEnrichLoginEventTenancy(formCtx, loginEvent, getLogReq)

	// FedCM nonce: same value is rendered into the page and stored on the LoginEvent.
	fedcmNonce := util.IDString()
	if loginEvent.Properties == nil {
		loginEvent.Properties = map[string]any{}
	}
	loginEvent.Properties[loginEventPropertyFedCMNonce] = fedcmNonce
	cacheCtx, cacheCancel := context.WithTimeout(formCtx, loginCacheTimeout)
	if cacheErr := h.setLoginEventToCache(cacheCtx, loginEvent); cacheErr != nil {
		log.WithError(cacheErr).Debug("failed to re-cache login event with FedCM nonce")
	}
	cacheCancel()

	payload := h.initTemplatePayloadWithI18n(ctx, req)
	payload[pathValueLoginEventID] = loginEvent.GetID()
	payload["ClientID"] = loginEvent.ClientID
	payload["FedCMNonce"] = fedcmNonce
	payload["GoogleClientID"] = h.config.AuthProviderGoogleClientID
	payload["PostHogAPIKey"] = h.config.PostHogAPIKey
	payload["PostHogHost"] = h.config.PostHogHost
	payload["error"] = ""

	maps.Copy(payload, h.loginOptions)

	log.WithFields(map[string]any{
		"login_event_id": loginEvent.GetID(),
		"client_id":      loginEvent.ClientID,
		"tenancy_source": tenancySource,
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
	var sessionSeed *models.LoginEvent

	if oauth2SessionID != "" {
		existing, err := h.loginEventRepo.GetByOauth2SessionID(ctx, oauth2SessionID)
		if err != nil {
			if !data.ErrorIsNoRows(err) {
				return nil, fmt.Errorf("failed to resolve login event by oauth2_session_id: %w", err)
			}
		} else if existing != nil {
			if existing.ProfileID != "" && existing.ProfileID != subjectID {
				return nil, fmt.Errorf("existing login event subject mismatch")
			}

			sessionSeed = existing
			if existing.ClientID == "" || existing.ClientID == clientID {
				return existing, nil
			}

			util.Log(ctx).WithFields(map[string]any{
				"oauth2_session_id":  oauth2SessionID,
				"existing_client_id": existing.ClientID,
				"current_client_id":  clientID,
				"profile_id":         subjectID,
			}).Info("skipped-login session reused across OAuth client boundary")
		}
	}

	recent, err := h.loginEventRepo.GetMostRecentByProfileID(ctx, subjectID)
	if err != nil {
		if !data.ErrorIsNoRows(err) {
			return nil, fmt.Errorf("failed to resolve login event by profile_id: %w", err)
		}
		return sessionSeed, nil
	}
	if recent == nil {
		return sessionSeed, nil
	}
	if recent.ProfileID != "" && recent.ProfileID != subjectID {
		return nil, fmt.Errorf("recent login event subject mismatch")
	}

	return recent, nil
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
		Properties: map[string]any{
			loginEventPropertyLoginSource: string(models.LoginSourceSessionRefresh),
		},
	}
	if existingLoginEvent != nil {
		newLoginEvent.ContactID = existingLoginEvent.ContactID
		if workspaceProps := copyWorkspaceProperties(existingLoginEvent.Properties); len(workspaceProps) > 0 {
			newLoginEvent.Properties = mergeLoginEventProperties(newLoginEvent.Properties, workspaceProps)
		}
		if existingLoginEvent.ClientID == "" || existingLoginEvent.ClientID == clientID {
			newLoginEvent.AccessID = existingLoginEvent.AccessID
			newLoginEvent.TenantID = existingLoginEvent.TenantID
			newLoginEvent.PartitionID = existingLoginEvent.PartitionID
		}
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
		Properties: map[string]any{
			loginEventPropertyLoginSource: string(models.LoginSourceSessionRefresh),
		},
	}
	newLoginEvent.ID = util.IDString()
	newLoginEvent.TenantID = oldLoginEvent.TenantID
	newLoginEvent.PartitionID = oldLoginEvent.PartitionID
	newLoginEvent.AccessID = oldLoginEvent.AccessID
	if workspaceProps := copyWorkspaceProperties(oldLoginEvent.Properties); len(workspaceProps) > 0 {
		newLoginEvent.Properties = mergeLoginEventProperties(newLoginEvent.Properties, workspaceProps)
	}

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

	// Detach from a nearly-spent parent budget (soft tenancy is 80ms total).
	// A spent parent was causing "context deadline exceeded" on Valkey SET
	// even when the value was already resolved in memory.
	cacheCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loginCacheTimeout)
	defer cancel()

	cacheKey := loginEventCachePrefix + loginEvent.GetID()
	if err := eventCache.Set(cacheCtx, cacheKey, *loginEvent, time.Hour); err != nil {
		util.Log(ctx).WithError(err).Error("failed to update login event cache with partition info")
		return err
	}
	return nil
}
