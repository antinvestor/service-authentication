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
	"github.com/antinvestor/service-authentication/apps/default/utils"
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

	// Step 3: Get consent request from Hydra
	getConseReq, err := hydraCli.GetConsentRequest(ctx, consentChallenge)
	if err != nil {
		log.WithError(err).Error("hydra consent request lookup failed")
		return fmt.Errorf("failed to get consent request: %w", err)
	}

	var tokenMap map[string]any

	client := getConseReq.GetClient()
	clientID := client.GetClientId()
	subjectID := getConseReq.GetSubject()

	log = log.WithField("subject_id", subjectID)

	if isInternalSystemScoped(getConseReq.GetRequestedScope()) {

		partitionResp, partitionErr := h.partitionCli.GetPartition(ctx, connect.NewRequest(&partitionv1.GetPartitionRequest{Id: clientID}))
		if partitionErr != nil {
			log.WithError(partitionErr).WithField("client_id", clientID).Error("partition lookup failed")
			return fmt.Errorf("failed to get partition: %w", partitionErr)
		}

		partitionObj := partitionResp.Msg.GetData()
		if partitionObj == nil {
			log.WithField("client_id", clientID).Error("partition not found")
			return fmt.Errorf("partition not found for client: %s", clientID)
		}

		tokenMap = map[string]any{
			"tenant_id":    partitionObj.GetTenantId(),
			"partition_id": partitionObj.GetId(),
			"roles":        []string{"system_internal"},
			"profile_id":   subjectID,
		}

	} else if isClientIDApiKey(clientID) {

		// Check if this is an API key client
		apiKeyModel, err0 := h.apiKeyRepo.GetByKey(ctx, clientID)
		if err0 != nil {
			util.Log(ctx).WithError(err0).Error("could not find api key")
			return err0
		}

		// This is an API key client - handle as external service
		roles := []string{"system_external"}

		if apiKeyModel.Scope != "" {
			var scopeList []string
			err0 = json.Unmarshal([]byte(apiKeyModel.Scope), &scopeList)
			if err0 == nil {
				roles = append(roles, scopeList...)
			}
		}

		tokenMap = map[string]any{
			"tenant_id":    apiKeyModel.TenantID,
			"partition_id": apiKeyModel.PartitionID,
			"roles":        roles,
		}

	} else {

		// Step 4: Process device session
		deviceObj, deviceErr := h.processDeviceSession(ctx, subjectID)
		if deviceErr != nil {
			if deviceObj == nil {
				log.WithError(deviceErr).Error("device session processing failed")
				return fmt.Errorf("failed to process device session: %w", deviceErr)
			}
			log.WithError(deviceErr).Warn("device session processing had non-fatal error")
		}

		if deviceErr = h.storeDeviceID(ctx, rw, deviceObj); deviceErr != nil {
			log.WithError(deviceErr).Debug("failed to store device ID cookie")
			// Continue - device cookie is not critical for consent
		}

		// Step 5: Get login event for token claims (contains tenant/partition info from login phase)
		loginContext, ok := getConseReq.GetContext().(map[string]any)
		if ok {

			loginEventID, iOk := loginContext["login_event_id"]
			if iOk {

				loginEventIDStr, liOk := loginEventID.(string)

				if liOk {
					loginEvent, loginEvtErr := h.loginEventRepo.GetByID(ctx, loginEventIDStr)
					if loginEvtErr != nil {
						log.WithError(loginEvtErr).WithField("login_event_id", loginEventID).Error("login event lookup failed")
						return fmt.Errorf("failed to get login event: %w", loginEvtErr)
					}

					// Step 6: Build token claims from login event (already enriched with tenant/partition during login)
					tokenMap = map[string]any{
						"tenant_id":    loginEvent.GetTenantID(),
						"partition_id": loginEvent.GetPartitionID(),
						"access_id":    loginEvent.GetAccessID(),
						"contact_id":   loginEvent.GetContactID(),
						"session_id":   loginEvent.GetID(),
						"roles":        []string{"user"},
						"device_id":    deviceObj.GetId(),
						"profile_id":   subjectID,
					}

					// Set remember-me cookie so the user can be auto-logged-in
					// when their Hydra session expires.
					if rmErr := h.setRememberMeCookie(rw, loginEvent.GetID()); rmErr != nil {
						log.WithError(rmErr).Debug("failed to set remember-me cookie")
					}
				} else {
					log.Debug("login_event_id in context is not a string - possible token refresh")
				}
			}
		}
	}

	// Ensure tokenMap is initialized (defensive - should not normally be nil)
	if tokenMap == nil {
		log.Warn("tokenMap is nil - consent flow may be incomplete, using empty claims")
		tokenMap = map[string]any{}
	}

	// Step 6: Accept consent and get redirect URL
	// Remember=true ensures the consent session (including token extras) is persisted
	// for subsequent token refreshes
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

	// Step 7: Clear session cookie and redirect
	h.clearDeviceSessionID(rw)

	// Safe logging - tokenMap may have missing keys
	logFields := map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
	}
	if v, ok := tokenMap["partition_id"]; ok {
		logFields["partition_id"] = v
	}
	if v, ok := tokenMap["tenant_id"]; ok {
		logFields["tenant_id"] = v
	}
	if v, ok := tokenMap["session_id"]; ok {
		logFields["session_id"] = v
	}
	if v, ok := tokenMap["device_id"]; ok {
		logFields["device_id"] = v
	}
	log.WithFields(logFields).Info("consent granted successfully")

	// For regular user flows from a browser, render an interstitial page that
	// handles the redirect client-side. This allows mobile apps using deep links
	// or custom schemes to intercept the navigation while giving the browser tab
	// a proper "signed in" landing page instead of a blank or stale page.
	// Programmatic clients (no Accept: text/html) get a standard HTTP redirect.
	isBrowser := strings.Contains(req.Header.Get("Accept"), "text/html")
	if isBrowser && !isInternalSystemScoped(getConseReq.GetRequestedScope()) && !isClientIDApiKey(clientID) {
		payload := initTemplatePayload(ctx)
		payload["RedirectURL"] = redirectURL
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		return loginCompleteTmpl.Execute(rw, payload)
	}

	http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
	return nil
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
