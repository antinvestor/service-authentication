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
	tokenMap, err := h.buildConsentTokenClaims(ctx, rw, getConseReq, clientID, subjectID)
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
func (h *AuthServer) buildConsentTokenClaims(ctx context.Context, rw http.ResponseWriter, consentReq *hydraclientgo.OAuth2ConsentRequest, clientID, subjectID string) (map[string]any, error) {
	if isInternalSystemScoped(consentReq.GetRequestedScope()) {
		return h.buildInternalSystemTokenClaims(ctx, clientID, subjectID)
	}
	if isClientIDApiKey(clientID) {
		return h.buildAPIKeyTokenClaims(ctx, clientID)
	}
	return h.buildUserTokenClaims(ctx, rw, consentReq, subjectID)
}

// buildInternalSystemTokenClaims builds token claims for internal system clients.
func (h *AuthServer) buildInternalSystemTokenClaims(ctx context.Context, clientID, subjectID string) (map[string]any, error) {
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

	return map[string]any{
		"tenant_id":    partitionObj.GetTenantId(),
		"partition_id": partitionObj.GetId(),
		"roles":        []string{"system_internal"},
		"profile_id":   subjectID,
	}, nil
}

// buildAPIKeyTokenClaims builds token claims for API key clients.
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

	return map[string]any{
		"tenant_id":    apiKeyModel.TenantID,
		"partition_id": apiKeyModel.PartitionID,
		"roles":        roles,
	}, nil
}

// buildUserTokenClaims builds token claims for regular user logins.
func (h *AuthServer) buildUserTokenClaims(ctx context.Context, rw http.ResponseWriter, consentReq *hydraclientgo.OAuth2ConsentRequest, subjectID string) (map[string]any, error) {
	log := util.Log(ctx)

	// Process device session
	deviceObj, deviceErr := h.processDeviceSession(ctx, subjectID)
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

	// Extract login event ID from consent context
	loginEventIDStr := extractLoginEventID(consentReq.GetContext())

	var loginEvent *models.LoginEvent
	var err error

	if loginEventIDStr != "" {
		// Normal flow: login_event_id is in context
		loginEvent, err = h.loginEventRepo.GetByID(ctx, loginEventIDStr)
		if err != nil {
			log.WithError(err).WithField("login_event_id", loginEventIDStr).Error("login event lookup failed")
			return nil, fmt.Errorf("failed to get login event: %w", err)
		}
	} else {
		// Fallback: login was skipped (session exists), look up most recent login event for this profile
		log.Debug("login_event_id not found in context - looking up most recent login event")
		loginEvent, err = h.loginEventRepo.GetMostRecentByProfileID(ctx, subjectID)
		if err != nil {
			log.WithError(err).WithField("profile_id", subjectID).Warn("no login event found for profile - returning minimal claims")
			return map[string]any{
				"profile_id": subjectID,
				"device_id":  deviceObj.GetId(),
				"roles":      []string{"user"},
			}, nil
		}
		log.WithField("login_event_id", loginEvent.GetID()).Debug("retrieved login event via profile fallback")
	}

	// Set remember-me cookie
	if rmErr := h.setRememberMeCookie(rw, loginEvent.GetID()); rmErr != nil {
		log.WithError(rmErr).Debug("failed to set remember-me cookie")
	}

	return map[string]any{
		"tenant_id":    loginEvent.GetTenantID(),
		"partition_id": loginEvent.GetPartitionID(),
		"access_id":    loginEvent.GetAccessID(),
		"contact_id":   loginEvent.GetContactID(),
		"session_id":   loginEvent.GetID(),
		"roles":        []string{"user"},
		"device_id":    deviceObj.GetId(),
		"profile_id":   subjectID,
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

func (h *AuthServer) processDeviceSession(ctx context.Context, profileId string) (*devicev1.DeviceObject, error) {

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

	if deviceSessionID != "" {

		session, err := deviceCli.GetBySessionId(ctx, connect.NewRequest(&devicev1.GetBySessionIdRequest{Id: deviceSessionID}))
		if err == nil {
			deviceObj = session.Msg.GetData()
		}

	}

	props, _ := structpb.NewStruct(map[string]any{"source": "consent"})
	if deviceObj == nil {

		resp, err0 := deviceCli.Create(ctx, connect.NewRequest(&devicev1.CreateRequest{
			Name:       "Web Browser",
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
