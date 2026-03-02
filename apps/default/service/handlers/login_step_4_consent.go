package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	devicev1 "buf.build/gen/go/antinvestor/device/protocolbuffers/go/device/v1"
	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	hydraclientgo "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

// ShowConsentEndpoint handles the OAuth2 consent flow.
// It retrieves consent challenge, processes device session, and grants consent.
func (h *AuthServer) ShowConsentEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx)

	hydraCli := h.defaultHydraCli

	// Step 1: Extract consent challenge
	consentChallenge, err := hydra.GetConsentChallengeID(req)
	if err != nil {
		log.WithError(err).Warn("missing or invalid consent_challenge parameter")
		return fmt.Errorf("consent challenge required: %w", err)
	}

	// Use first 16 chars for logging
	challengePrefix := consentChallenge
	if len(challengePrefix) > 16 {
		challengePrefix = challengePrefix[:16]
	}
	log = log.WithField("consent_challenge_prefix", challengePrefix)

	// Step 2: Get consent request from Hydra
	getConseReq, err := hydraCli.GetConsentRequest(ctx, consentChallenge)
	if err != nil {
		log.WithError(err).Error("hydra consent request lookup failed")
		return fmt.Errorf("failed to get consent request: %w", err)
	}

	client := getConseReq.GetClient()
	clientID := client.GetClientId()
	subjectID := getConseReq.GetSubject()
	log = log.WithField("subject_id", subjectID)

	// Step 3: Build token claims based on client type
	tokenMap, err := h.buildConsentTokenClaims(ctx, rw, req, getConseReq, clientID, subjectID)
	if err != nil {
		return err
	}

	// Step 4: Accept consent and get redirect URL
	params := &hydra.AcceptConsentRequestParams{
		ConsentChallenge:  consentChallenge,
		GrantScope:        getConseReq.GetRequestedScope(),
		GrantAudience:     client.GetAudience(),
		AccessTokenExtras: tokenMap,
		IdTokenExtras:     tokenMap,
		Remember:          true,
		RememberDuration:  7776000, // remember for ninety days (until logout)
	}

	redirectURL, err := hydraCli.AcceptConsentRequest(ctx, params)
	if err != nil {
		log.WithError(err).Error("hydra accept consent request failed")
		return fmt.Errorf("failed to accept consent: %w", err)
	}

	// Step 5: Clear session cookie and redirect
	h.clearDeviceSessionID(rw)
	h.logConsentSuccess(log, tokenMap, start)

	// For regular user flows from a browser, render an interstitial page
	if h.shouldRenderBrowserInterstitial(req, getConseReq.GetRequestedScope(), clientID) {
		payload := h.initTemplatePayloadWithI18n(ctx, req)
		payload["RedirectURL"] = redirectURL
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		return loginCompleteTmpl.Execute(rw, payload)
	}

	http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
	return nil
}

// buildConsentTokenClaims builds token claims based on the client type (internal system, API key, or user).
func (h *AuthServer) buildConsentTokenClaims(ctx context.Context, rw http.ResponseWriter, req *http.Request, consentReq *hydraclientgo.OAuth2ConsentRequest, clientID, subjectID string) (map[string]any, error) {
	if isInternalSystemScoped(consentReq.GetRequestedScope()) {

		requestedAudiences := consentReq.GetRequestedAccessTokenAudience()

		return h.buildInternalSystemTokenClaims(ctx, clientID, subjectID, requestedAudiences)
	}
	if isClientIDApiKey(clientID) {
		return h.buildAPIKeyTokenClaims(ctx, clientID)
	}
	return h.buildUserTokenClaims(ctx, rw, req, consentReq, clientID, subjectID)
}

// buildInternalSystemTokenClaims builds token claims for internal system clients.
func (h *AuthServer) buildInternalSystemTokenClaims(ctx context.Context, clientID, subjectID string, requesteAudiences []string) (map[string]any, error) {
	log := util.Log(ctx)

	partitionResp, err := h.partitionCli.GetPartition(ctx, connect.NewRequest(&partitionv1.GetPartitionRequest{Id: clientID}))
	if err != nil {
		log.WithError(err).WithField("client_id", clientID).Error("partition lookup failed")
		return nil, fmt.Errorf("failed to get partition: %w", err)
	}

	partitionObj := partitionResp.Msg.GetData()
	if partitionObj == nil {
		log.WithField("client_id", clientID).Error("partition not found")
		return nil, fmt.Errorf("partition not found for client: %s", clientID)
	}

	tenantID := partitionObj.GetTenantId()

	tenancyPath := fmt.Sprintf("%s/%s", tenantID, partitionObj.GetId())

	// Write the per-bot service access tuple in tenancy_access so Keto can
	// resolve the subject set chain: botID → tenancy_access:path#service →
	// ns:path#service → ns:path#permission.
	// Bridge tuples are written for the specific audiences the bot is granted
	// access to, scoping service bot access to only the services it needs.
	tuples := []security.RelationTuple{
		authz.BuildAccessTuple(tenancyPath, subjectID),
		authz.BuildServiceAccessTuple(tenancyPath, subjectID),
	}
	if len(requesteAudiences) > 0 {
		tuples = append(tuples, authz.BuildServiceInheritanceTuples(tenancyPath, requesteAudiences)...)
	}
	if writeErr := h.authorizer.WriteTuples(ctx, tuples); writeErr != nil {
		log.WithError(writeErr).
			WithField("tenant_id", tenantID).
			WithField("subject_id", subjectID).
			Warn("failed to write service tuples at consent time")
	}

	// Create a LoginEvent for auditability and webhook fallback.
	// Uses default tenant/partition IDs consistent with how the webhook
	// handles system_internal tokens, not from the partition lookup.
	cfg := h.Config()
	loginEvt := &models.LoginEvent{
		ClientID:  clientID,
		ProfileID: subjectID,
	}
	loginEvt.ID = util.IDString()
	loginEvt.TenantID = cfg.DefaultTenantID
	loginEvt.PartitionID = cfg.DefaultPartitionID

	if createErr := h.loginEventRepo.Create(ctx, loginEvt); createErr != nil {
		log.WithError(createErr).WithField("client_id", clientID).
			Warn("failed to create login event for system_internal consent (non-fatal)")
	}

	return map[string]any{
		"tenant_id":      tenantID,
		"partition_id":   partitionObj.GetId(),
		"roles":          []string{"system_internal"},
		"profile_id":     subjectID,
		"session_id":     loginEvt.GetID(),
		"login_event_id": loginEvt.GetID(),
	}, nil
}

// buildAPIKeyTokenClaims builds token claims for API key clients.
// TODO there should be a way to refine/limit the access this api key has
func (h *AuthServer) buildAPIKeyTokenClaims(ctx context.Context, clientID string) (map[string]any, error) {
	log := util.Log(ctx)

	apiKeyModel, err := h.apiKeyRepo.GetByKey(ctx, clientID)
	if err != nil {
		log.WithError(err).Error("could not find api key")
		return nil, err
	}

	roles := []string{"system_external"}
	if apiKeyModel.Scope != "" {
		var scopeList []string
		if json.Unmarshal([]byte(apiKeyModel.Scope), &scopeList) == nil {
			roles = append(roles, scopeList...)
		}
	}

	// Create a LoginEvent for auditability and webhook fallback.
	// This ensures non-interactive flows have a login event that the webhook
	// can look up if scope-based routing fails.
	loginEvt := &models.LoginEvent{
		ClientID:  clientID,
		ProfileID: apiKeyModel.ProfileID,
	}
	loginEvt.ID = util.IDString()
	loginEvt.TenantID = apiKeyModel.TenantID
	loginEvt.PartitionID = apiKeyModel.PartitionID
	loginEvt.AccessID = apiKeyModel.AccessID

	if createErr := h.loginEventRepo.Create(ctx, loginEvt); createErr != nil {
		log.WithError(createErr).WithField("client_id", clientID).
			Warn("failed to create login event for API key consent (non-fatal)")
	}

	return map[string]any{
		"tenant_id":      apiKeyModel.TenantID,
		"partition_id":   apiKeyModel.PartitionID,
		"access_id":      apiKeyModel.AccessID,
		"roles":          roles,
		"session_id":     loginEvt.GetID(),
		"login_event_id": loginEvt.GetID(),
	}, nil
}

// buildUserTokenClaims builds token claims for regular user logins.
func (h *AuthServer) buildUserTokenClaims(
	ctx context.Context,
	rw http.ResponseWriter,
	req *http.Request,
	consentReq *hydraclientgo.OAuth2ConsentRequest,
	clientID string,
	subjectID string,
) (map[string]any, error) {
	log := util.Log(ctx)
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required for user token claims")
	}
	if subjectID == "" {
		return nil, fmt.Errorf("subject_id is required for user token claims")
	}

	// Process device session with User-Agent for proper device labelling
	userAgent := req.UserAgent()
	deviceObj, deviceErr := h.processDeviceSession(ctx, subjectID, userAgent)
	if deviceErr != nil {
		if deviceObj == nil {
			log.WithError(deviceErr).Error("device session processing failed")
			return nil, fmt.Errorf("failed to process device session: %w", deviceErr)
		}
		log.WithError(deviceErr).Warn("device session processing had non-fatal error")
	}

	if err := h.storeDeviceID(ctx, rw, deviceObj); err != nil {
		log.WithError(err).Debug("failed to store device ID cookie")
	}

	// Extract login event ID from consent context.
	// This is required for a strict 1:1 mapping between user access tokens and login events.
	loginEventIDStr := extractLoginEventID(consentReq.GetContext())
	if loginEventIDStr == "" {
		return nil, fmt.Errorf("missing login_event_id in consent context")
	}

	loginEvent, err := h.loginEventRepo.GetByID(ctx, loginEventIDStr)
	if err != nil {
		log.WithError(err).WithField("login_event_id", loginEventIDStr).Error("login event lookup failed")
		return nil, fmt.Errorf("failed to get login event: %w", err)
	}
	if loginEvent == nil {
		return nil, fmt.Errorf("login event not found")
	}

	if loginEvent.ClientID != "" && loginEvent.ClientID != clientID {
		return nil, fmt.Errorf("login event client mismatch")
	}
	if loginEvent.ProfileID != "" && loginEvent.ProfileID != subjectID {
		return nil, fmt.Errorf("login event subject mismatch")
	}

	loginEventUpdated, err := h.ensureLoginEventTenancyAccess(ctx, loginEvent, clientID, subjectID)
	if err != nil {
		log.WithError(err).WithField("login_event_id", loginEvent.GetID()).Error("failed to ensure tenancy access for consent")
		return nil, err
	}
	loginEvent = loginEventUpdated

	if loginEvent.DeviceID != deviceObj.GetId() && deviceObj.GetId() != "" {
		loginEvent.DeviceID = deviceObj.GetId()
		if _, err = h.loginEventRepo.Update(ctx, loginEvent, "device_id"); err != nil {
			log.WithError(err).Debug("failed to update login event device_id")
		}
		if cacheErr := h.setLoginEventToCache(ctx, loginEvent); cacheErr != nil {
			log.WithError(cacheErr).Debug("failed to update login event cache after device update")
		}
	}

	// Set remember-me cookie
	if rmErr := h.setRememberMeCookie(rw, loginEvent.GetID()); rmErr != nil {
		log.WithError(rmErr).Debug("failed to set remember-me cookie")
	}

	return map[string]any{
		"tenant_id":         loginEvent.GetTenantID(),
		"partition_id":      loginEvent.GetPartitionID(),
		"access_id":         loginEvent.GetAccessID(),
		"contact_id":        loginEvent.GetContactID(),
		"session_id":        loginEvent.GetID(),
		"login_event_id":    loginEvent.GetID(),
		"oauth2_session_id": loginEvent.Oauth2SessionID,
		"roles":             []string{"user"},
		"device_id":         deviceObj.GetId(),
		"profile_id":        subjectID,
	}, nil
}

// extractLoginEventID extracts the login event ID from the consent context.
func extractLoginEventID(consentContext any) string {
	loginContext, ok := consentContext.(map[string]any)
	if !ok {
		return ""
	}
	loginEventID, ok := loginContext["login_event_id"]
	if !ok {
		return ""
	}
	loginEventIDStr, ok := loginEventID.(string)
	if !ok {
		return ""
	}
	return loginEventIDStr
}

// logConsentSuccess logs the successful consent with available token claims.
func (h *AuthServer) logConsentSuccess(log *util.LogEntry, tokenMap map[string]any, start time.Time) {
	logFields := map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
	}
	for _, key := range []string{"partition_id", "tenant_id", "session_id", "device_id"} {
		if v, ok := tokenMap[key]; ok {
			logFields[key] = v
		}
	}
	log.WithFields(logFields).Info("consent granted successfully")
}

// shouldRenderBrowserInterstitial determines if we should render an HTML interstitial page.
func (h *AuthServer) shouldRenderBrowserInterstitial(req *http.Request, requestedScope []string, clientID string) bool {
	isBrowser := strings.Contains(req.Header.Get("Accept"), "text/html")
	return isBrowser && !isInternalSystemScoped(requestedScope) && !isClientIDApiKey(clientID)
}

// inferDeviceName returns a human-readable device name based on the User-Agent string.
// This ensures non-browser clients (mobile apps, bots, CLI tools) get meaningful device labels.
func inferDeviceName(userAgent string) string {
	if userAgent == "" {
		return "Unknown Client"
	}

	ua := strings.ToLower(userAgent)

	switch {
	case strings.Contains(ua, "dart") || strings.Contains(ua, "flutter"):
		return "Mobile App (Flutter)"
	case strings.Contains(ua, "okhttp") || strings.Contains(ua, "android"):
		return "Mobile App (Android)"
	case strings.Contains(ua, "cfnetwork") || strings.Contains(ua, "darwin") || strings.Contains(ua, "ios"):
		return "Mobile App (iOS)"
	case strings.Contains(ua, "python") || strings.Contains(ua, "requests"):
		return "API Client (Python)"
	case strings.Contains(ua, "go-http-client") || strings.Contains(ua, "golang"):
		return "API Client (Go)"
	case strings.Contains(ua, "node") || strings.Contains(ua, "axios"):
		return "API Client (Node)"
	case strings.Contains(ua, "curl"):
		return "API Client (cURL)"
	case strings.Contains(ua, "postman"):
		return "API Client (Postman)"
	case strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") || strings.Contains(ua, "spider"):
		return "Bot"
	case strings.Contains(ua, "mozilla") || strings.Contains(ua, "chrome") || strings.Contains(ua, "safari") || strings.Contains(ua, "firefox"):
		return "Web Browser"
	default:
		return "API Client"
	}
}

func (h *AuthServer) processDeviceSession(ctx context.Context, profileId string, userAgent string) (*devicev1.DeviceObject, error) {

	deviceID := utils.DeviceIDFromContext(ctx)
	deviceSessionID := utils.SessionIDFromContext(ctx)

	deviceCli := h.DeviceCli()

	var deviceObj *devicev1.DeviceObject

	if deviceID != "" {
		resp, err := deviceCli.GetById(ctx, connect.NewRequest(&devicev1.GetByIdRequest{Id: []string{deviceID}}))
		if err == nil && len(resp.Msg.GetData()) > 0 {
			deviceObj = resp.Msg.GetData()[0]
		}
	}

	if deviceObj == nil && deviceSessionID != "" {

		session, err := deviceCli.GetBySessionId(ctx, connect.NewRequest(&devicev1.GetBySessionIdRequest{Id: deviceSessionID}))
		if err == nil {
			deviceObj = session.Msg.GetData()
		}

	}

	deviceName := inferDeviceName(userAgent)
	props, _ := structpb.NewStruct(map[string]any{
		"source":     "consent",
		"user_agent": userAgent,
	})
	if deviceObj == nil {

		resp, err0 := deviceCli.Create(ctx, connect.NewRequest(&devicev1.CreateRequest{
			Name:       deviceName,
			Properties: props,
		}))
		if err0 != nil {
			return nil, err0
		}
		deviceObj = resp.Msg.GetData()
	}

	if deviceObj.GetProfileId() == profileId {
		return deviceObj, nil
	}

	resp, err := deviceCli.Link(ctx, connect.NewRequest(&devicev1.LinkRequest{
		Id:         deviceObj.GetId(),
		ProfileId:  profileId,
		Properties: props,
	}))
	if err != nil {
		return deviceObj, err
	}

	deviceObj = resp.Msg.GetData()

	return deviceObj, nil

}

func (h *AuthServer) storeDeviceID(ctx context.Context, w http.ResponseWriter, deviceObj *devicev1.DeviceObject) error {

	deviceID := utils.DeviceIDFromContext(ctx)

	if deviceObj.GetId() == deviceID {
		return nil
	}

	// Encode and sign the device ID cookie
	encoded, encodeErr := h.cookiesCodec.Encode(SessionKeyDeviceIDKey, deviceObj.GetId())
	if encodeErr != nil {
		return encodeErr
	}

	// Set the secure, signed device ID cookie (long-term)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionKeyDeviceStorageName,
		Value:    encoded,
		Path:     "/",
		MaxAge:   473040000, // 15 years
		Secure:   true,      // HTTPS-only
		HttpOnly: true,      // No JavaScript access
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(473040000 * time.Second),
	})

	return nil
}

// setRememberMeCookie stores the login event ID in a long-lived encrypted cookie
// so that the user can be auto-logged-in when their Hydra session expires.
func (h *AuthServer) setRememberMeCookie(w http.ResponseWriter, loginEventID string) error {
	encoded, err := h.cookiesCodec.Encode(SessionKeyRememberMeLoginEventIDKey, loginEventID)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionKeyRememberMeStorageName,
		Value:    encoded,
		Path:     "/",
		MaxAge:   7776000, // 90 days
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(7776000 * time.Second),
	})

	return nil
}

// clearRememberMeCookie removes the remember-me cookie, forcing re-authentication on next visit.
func (h *AuthServer) clearRememberMeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionKeyRememberMeStorageName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(-1 * time.Hour),
	})
}

// clearDeviceSessionID clears the device session ID cookie, forcing creation of a new session
func (h *AuthServer) clearDeviceSessionID(w http.ResponseWriter) {
	// Set an expired session cookie to clear it
	http.SetCookie(w, &http.Cookie{
		Name:     SessionKeySessionStorageName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Negative MaxAge means delete the cookie
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(-1 * time.Hour), // Set to past time
	})
}
