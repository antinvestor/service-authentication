package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	devicev1 "buf.build/gen/go/antinvestor/device/protocolbuffers/go/device/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	hydraclientgo "github.com/ory/hydra-client-go/v25"
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

// buildConsentTokenClaims builds token claims based on the client type (service account or user).
func (h *AuthServer) buildConsentTokenClaims(ctx context.Context, rw http.ResponseWriter, req *http.Request, consentReq *hydraclientgo.OAuth2ConsentRequest, clientID, subjectID string) (map[string]any, error) {
	requestedScope := consentReq.GetRequestedScope()
	if isServiceAccountScoped(requestedScope) {
		requestedAudiences := consentReq.GetRequestedAccessTokenAudience()
		return h.buildServiceAccountConsentClaims(ctx, clientID, subjectID, requestedScope, requestedAudiences)
	}
	return h.buildUserTokenClaims(ctx, rw, req, consentReq, clientID, subjectID)
}

// buildServiceAccountConsentClaims builds token claims for service account clients
// (both system_internal and system_external).
// Service accounts are looked up via the tenancy service API by client_id.
func (h *AuthServer) buildServiceAccountConsentClaims(ctx context.Context, clientID, subjectID string, requestedScope, _ []string) (map[string]any, error) {
	log := util.Log(ctx)

	sa, err := h.lookupServiceAccountByClientID(ctx, clientID)
	if err != nil {
		log.WithError(err).WithField("client_id", clientID).Error("service account lookup failed")
		return nil, fmt.Errorf("service account not found for client: %s", clientID)
	}

	// Validate that the SA's profile matches the authenticating subject
	if sa.ProfileID != subjectID {
		log.WithField("client_id", clientID).
			WithField("subject_id", subjectID).
			WithField("sa_profile_id", sa.ProfileID).
			Error("service account subject mismatch")
		return nil, fmt.Errorf("service account subject mismatch for client %s", clientID)
	}

	// Validate scope matches SA type
	if err = validateScopeMatchesSAType(requestedScope, sa.Type); err != nil {
		log.WithError(err).WithField("client_id", clientID).Error("scope/type mismatch")
		return nil, err
	}

	// Get or create access for SA's profile in their partition
	accessObj, err := h.getOrCreateTenancyAccessByPartitionID(ctx, sa.PartitionID, subjectID)
	if err != nil {
		log.WithError(err).WithField("client_id", clientID).Error("failed to get/create access for SA")
		return nil, fmt.Errorf("failed to get/create access for service account: %w", err)
	}

	// Fetch roles from access record
	roles := h.fetchAccessRoleNames(ctx, accessObj.GetId())

	// Create a LoginEvent for auditability and webhook fallback.
	// This must succeed — without it, token refresh will fail to find the login event.
	loginEvt := &models.LoginEvent{
		ClientID:  clientID,
		ProfileID: subjectID,
		AccessID:  accessObj.GetId(),
	}
	loginEvt.ID = util.IDString()
	loginEvt.TenantID = sa.TenantID
	loginEvt.PartitionID = sa.PartitionID

	if createErr := h.loginEventRepo.Create(ctx, loginEvt); createErr != nil {
		log.WithError(createErr).WithField("client_id", clientID).
			Error("failed to create login event for service account consent")
		return nil, fmt.Errorf("failed to create login event: %w", createErr)
	}

	return map[string]any{
		"tenant_id":      sa.TenantID,
		"partition_id":   sa.PartitionID,
		"access_id":      accessObj.GetId(),
		"roles":          roles,
		"profile_id":     subjectID,
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
		"roles":             h.fetchAccessRoleNames(ctx, loginEvent.GetAccessID()),
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
func (h *AuthServer) shouldRenderBrowserInterstitial(req *http.Request, requestedScope []string, _ string) bool {
	isBrowser := strings.Contains(req.Header.Get("Accept"), "text/html")
	return isBrowser && !isServiceAccountScoped(requestedScope)
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
