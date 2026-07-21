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
	"fmt"
	"net/http"
	"strings"
	"time"

	devicev1 "buf.build/gen/go/antinvestor/device/protocolbuffers/go/device/v1"
	tenancyv2 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v2"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	hydraclientgo "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

// filterInternalScope removes the "internal" scope from a requested scope list.
// The "internal" capability is granted server-side based on roles, not requested
// by clients.
func filterInternalScope(scopes []string) []string {
	filtered := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if !strings.EqualFold(s, SATypeInternal) {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// isRootAdminOrOwner checks if the given tenant/partition match the root and
// the roles include "admin" or "owner".
func isRootAdminOrOwner(tenantID, partitionID string, roles []string) bool {
	if tenantID != authz.RootTenantID || partitionID != authz.RootPartitionID {
		return false
	}
	for _, r := range roles {
		if strings.EqualFold(r, "owner") || strings.EqualFold(r, "admin") {
			return true
		}
	}
	return false
}

// ShowConsentEndpoint handles the OAuth2 consent flow.
// It retrieves consent challenge, processes device session, and grants consent.
//
// Bounded by consentStrongBudget so M2M token contention cannot hang consent
// until the edge gateway kills the stream.
func (h *AuthServer) ShowConsentEndpoint(rw http.ResponseWriter, req *http.Request) error {
	parent := req.Context()
	ctx, cancel := context.WithTimeout(parent, consentStrongBudget)
	defer cancel()
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
	hydraCtx, hydraCancel := context.WithTimeout(ctx, consentHydraTimeout)
	getConseReq, err := hydraCli.GetConsentRequest(hydraCtx, consentChallenge)
	hydraCancel()
	if err != nil {
		log.WithError(err).Error("hydra consent request lookup failed")
		return fmt.Errorf("failed to get consent request: %w", err)
	}

	client := getConseReq.GetClient()
	clientID := client.GetClientId()

	// Prefer Hydra-embedded client / Valkey oauth-client tenancy map before
	// a cold tenancy GetOAuthClient (S2S token loop).
	oauthCtx, oauthCancel := context.WithTimeout(ctx, consentOAuthClientTimeout)
	clientObj, err := h.getOAuthClient(oauthCtx, clientID)
	oauthCancel()
	if err != nil {
		log.WithError(err).WithFields(map[string]any{
			"client_id":   clientID,
			"subject_id":  getConseReq.GetSubject(),
			"duration_ms": time.Since(start).Milliseconds(),
		}).Error("could not obtain consent OAuth client")
		return fmt.Errorf("resolve consent OAuth client %s: %w", clientID, err)
	}

	// Step 3: Build token claims based on client type
	tokenMap, err := h.buildConsentTokenClaims(ctx, rw, req, getConseReq, clientObj)
	if err != nil {
		return err
	}

	// Step 4: Accept consent and get redirect URL.
	// Filter out "internal" from granted scopes — it is a server-side capability
	// granted based on roles, not a client-requestable scope.
	grantedScopes := filterInternalScope(getConseReq.GetRequestedScope())

	params := &hydra.AcceptConsentRequestParams{
		ConsentChallenge:  consentChallenge,
		GrantScope:        grantedScopes,
		GrantAudience:     client.GetAudience(),
		AccessTokenExtras: tokenMap,
		IdTokenExtras:     tokenMap,
		Remember:          true,
		RememberDuration:  7776000, // remember for ninety days (until logout)
	}

	acceptCtx, acceptCancel := context.WithTimeout(ctx, consentHydraTimeout)
	redirectURL, err := hydraCli.AcceptConsentRequest(acceptCtx, params)
	acceptCancel()
	if err != nil {
		log.WithError(err).Error("hydra accept consent request failed")
		return fmt.Errorf("failed to accept consent: %w", err)
	}

	// Step 5: Clear session cookie and redirect
	h.clearDeviceSessionID(rw)
	h.logConsentSuccess(log, tokenMap, start)

	subjectAtConsent := ""
	if subj, ok := tokenMap["sub"].(string); ok {
		subjectAtConsent = subj
	}
	h.emitAnalyticsEvent(ctx, req, subjectAtConsent, evtConsentGranted, map[string]any{
		"client_id": clientID,
	})

	// Consent always runs after a successful login (either fresh or remembered),
	// so this is the universally-correct point to inform Chrome's FedCM Login
	// Status API that the IdP is logged-in. The login handlers also emit this
	// header at their own redirect points; emitting it here too is idempotent
	// and covers flows where the login path is bypassed (e.g. token refresh
	// after a long idle).
	setLoginStatusLoggedIn(rw)

	// For regular user flows from a browser, render an interstitial page
	if h.shouldRenderBrowserInterstitial(req, clientObj) {
		payload := h.initTemplatePayloadWithI18n(ctx, req)
		payload["RedirectURL"] = redirectURL
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		return loginCompleteTmpl.Execute(rw, payload)
	}

	http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
	return nil
}

// buildConsentTokenClaims builds token claims based on the client type (service account or user).
func (h *AuthServer) buildConsentTokenClaims(ctx context.Context, rw http.ResponseWriter, req *http.Request, consentReq *hydraclientgo.OAuth2ConsentRequest, clientObj *tenancyv2.OAuthClient) (map[string]any, error) {
	requestedScope := consentReq.GetRequestedScope()
	subjectID := consentReq.GetSubject()

	switch owner := clientObj.GetOwner().(type) {

	case *tenancyv2.OAuthClient_PartitionId:
		return h.buildUserTokenClaims(ctx, rw, req, consentReq, clientObj, subjectID)

	case *tenancyv2.OAuthClient_ServiceAccountId:
		serviceAccount, err := h.getServiceAccount(ctx, owner.ServiceAccountId)
		if err != nil {
			return nil, err
		}
		requestedAudiences := consentReq.GetRequestedAccessTokenAudience()
		return h.buildServiceAccountConsentClaims(ctx, consentReq, clientObj, serviceAccount, subjectID, requestedScope, requestedAudiences)

	default:
		return nil, fmt.Errorf("only partition or service account should own a client")

	}
}

// buildServiceAccountConsentClaims builds token claims for service account clients
// (both system_internal and system_external).
// Service accounts are looked up via the tenancy service API by client_id.
func (h *AuthServer) buildServiceAccountConsentClaims(ctx context.Context, consentReq *hydraclientgo.OAuth2ConsentRequest, clientObj *tenancyv2.OAuthClient, sa *tenancyv2.ServiceAccount, subjectID string, requestedScope, _ []string) (map[string]any, error) {
	log := util.Log(ctx).WithFields(map[string]any{
		"client_id":     clientObj.GetClientId(),
		"subject_id":    subjectID,
		"sa_profile_id": sa.GetProfileId(),
	})

	// Validate that the SA's profile matches the authenticating subject
	if sa.GetProfileId() != subjectID {
		log.Error("service account subject mismatch")
		return nil, fmt.Errorf("service account subject mismatch for client %s", clientObj.GetClientId())
	}

	// Validate scope matches SA type
	if err := validateScopeMatchesSAType(requestedScope, sa.GetType()); err != nil {
		log.WithError(err).Error("scope/type mismatch")
		return nil, err
	}

	// Service accounts are provisioned explicitly and are not gated by the
	// user-facing auto-access partition policy.
	accessObj, err := h.getTenancyAccessByPartitionID(ctx, sa.GetPartitionId(), subjectID)
	if err != nil {
		if !frame.ErrorIsNotFound(err) {
			log.WithError(err).Error("failed to resolve access for SA")
			return nil, fmt.Errorf("failed to resolve access for service account: %w", err)
		}

		accessObj, err = h.createTenancyAccessByPartitionID(ctx, sa.GetPartitionId(), subjectID)
		if err != nil {
			log.WithError(err).Error("failed to create access for SA")
			return nil, fmt.Errorf("failed to create access for service account: %w", err)
		}
	}

	// Fetch roles from access record, using partition default role
	partition, partitionErr := h.getPartition(ctx, sa.GetPartitionId())
	if partitionErr != nil {
		log.WithError(partitionErr).Warn("failed to resolve service account partition role defaults")
	}
	defaultRole := partitionDefaultRole(partition)
	roles := h.fetchAccessRoleNames(ctx, accessObj.GetId(), defaultRole)

	loginRecord, err := h.getOrCreateLoginRecord(ctx, subjectID, clientObj.GetClientId(), string(models.LoginSourceServiceAccount))
	if err != nil {
		log.WithError(err).Error("failed to resolve login record for service account consent")
		return nil, fmt.Errorf("failed to resolve login record: %w", err)
	}

	props := data.JSONMap{
		"auth_flow":            "service_account_consent",
		"grant_type":           "client_credentials",
		"service_account_type": sa.GetType(),
		"roles":                roles,
	}
	if consentReq != nil && consentReq.GetLoginSessionId() != "" {
		props["hydra_login_session_id"] = consentReq.GetLoginSessionId()
	}

	// Create a LoginEvent for auditability and webhook fallback.
	// This must succeed — without it, token refresh will fail to find the login event.
	loginEvt := &models.LoginEvent{
		ClientID:   clientObj.GetClientId(),
		LoginID:    loginRecord.GetID(),
		ProfileID:  subjectID,
		AccessID:   accessObj.GetId(),
		Properties: props,
		Client:     "hydra_consent",
		BaseModel: data.BaseModel{
			TenantID:    sa.GetTenantId(),
			PartitionID: sa.GetPartitionId(),
		},
	}
	loginEvt.ID = util.IDString()

	if createErr := h.loginEventRepo.Create(ctx, loginEvt); createErr != nil {
		log.WithError(createErr).Error("failed to create login event for service account consent")
		return nil, fmt.Errorf("failed to create login event: %w", createErr)
	}

	tenantID, partitionID := NormalizeTenancyPair(sa.GetTenantId(), sa.GetPartitionId())
	if !ValidTenancyPair(tenantID, partitionID) {
		return nil, ErrIncompleteTenancyPair
	}

	return map[string]any{
		"tenant_id":      tenantID,
		"partition_id":   partitionID,
		"access_id":      accessObj.GetId(),
		"roles":          roles,
		"profile_id":     subjectID,
		"session_id":     loginEvt.GetID(),
		"login_event_id": loginEvt.GetID(),
	}, nil
}

// resolveConsentDeviceObject processes device tracking within consentDeviceTimeout.
// Fail-open: returns an empty device on timeout/error so consent can complete.
func (h *AuthServer) resolveConsentDeviceObject(
	ctx context.Context,
	rw http.ResponseWriter,
	req *http.Request,
	subjectID string,
) *devicev1.DeviceObject {
	log := util.Log(ctx)
	devCtx, devCancel := context.WithTimeout(ctx, consentDeviceTimeout)
	deviceObj, deviceErr := h.processDeviceSession(devCtx, subjectID, req.UserAgent())
	devCancel()
	if deviceErr != nil {
		if deviceObj == nil {
			log.WithError(deviceErr).Warn("device session processing failed within budget; continuing with empty device_id")
			deviceObj = &devicev1.DeviceObject{}
		} else {
			log.WithError(deviceErr).Warn("device session processing had non-fatal error")
		}
	}
	if deviceObj == nil {
		deviceObj = &devicev1.DeviceObject{}
	}
	if err := h.storeDeviceID(ctx, rw, deviceObj); err != nil {
		log.WithError(err).Debug("failed to store device ID cookie")
	}
	return deviceObj
}

// buildUserTokenClaims builds token claims for regular user logins.
func (h *AuthServer) buildUserTokenClaims(
	ctx context.Context,
	rw http.ResponseWriter,
	req *http.Request,
	consentReq *hydraclientgo.OAuth2ConsentRequest,
	clientObj *tenancyv2.OAuthClient,
	subjectID string,
) (map[string]any, error) {
	log := util.Log(ctx)
	if clientObj == nil {
		return nil, fmt.Errorf("client_id is required for user token claims")
	}
	if subjectID == "" {
		return nil, fmt.Errorf("subject_id is required for user token claims")
	}

	deviceObj := h.resolveConsentDeviceObject(ctx, rw, req, subjectID)

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

	if loginEvent.ClientID != "" && loginEvent.ClientID != clientObj.GetClientId() {
		return nil, fmt.Errorf("login event client mismatch")
	}
	if loginEvent.ProfileID != "" && loginEvent.ProfileID != subjectID {
		return nil, fmt.Errorf("login event subject mismatch")
	}

	tenCtx, tenCancel := context.WithTimeout(ctx, strongTenancyTotalTimeout)
	loginEventUpdated, err := h.ensureLoginEventTenancyAccess(tenCtx, loginEvent, clientObj.GetClientId(), subjectID)
	tenCancel()
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

	defaultRole := partitionDefaultRole(h.resolvePartitionForLoginEventClaims(ctx, loginEvent, clientObj))
	roles := h.fetchAccessRoleNames(ctx, loginEvent.GetAccessID(), defaultRole)

	// Grant "internal" role to admin/owner users on the root tenant+partition.
	// This enables cross-tenant impersonation via EnrichTenancyClaims headers.
	if isRootAdminOrOwner(loginEvent.GetTenantID(), loginEvent.GetPartitionID(), roles) {
		hasInternal := false
		for _, r := range roles {
			if strings.EqualFold(r, SATypeInternal) {
				hasInternal = true
				break
			}
		}
		if !hasInternal {
			roles = append(roles, SATypeInternal)
		}
	}

	// Persist resolved roles in login event properties so the webhook fallback can use them
	// without calling the partition service (avoids circular dependency).
	if loginEvent.Properties == nil {
		loginEvent.Properties = data.JSONMap{}
	}
	loginEvent.Properties["roles"] = roles
	if _, err = h.loginEventRepo.Update(ctx, loginEvent, "properties"); err != nil {
		log.WithError(err).Debug("failed to persist roles in login event properties")
	}

	return BuildUserTokenClaims(loginEvent, subjectID, deviceObj.GetId(), roles)
}

// BuildUserTokenClaims returns the map of claims inserted into user-facing
// access and ID tokens at consent time. It is exported so the FedCM headless
// driver can reuse the exact same shape.
//
// tenant_id and partition_id are required as a pair — incomplete tenancy
// context fails closed rather than minting a partial token.
//
// The returned map must contain only string keys and JSON-serialisable values
// because Hydra places it verbatim into AccessTokenExtras / IdTokenExtras.
func BuildUserTokenClaims(loginEvent *models.LoginEvent, subjectID, deviceID string, roles []string) (map[string]any, error) {
	if loginEvent == nil {
		return nil, fmt.Errorf("login event is required")
	}
	tenantID, partitionID := NormalizeTenancyPair(loginEvent.GetTenantID(), loginEvent.GetPartitionID())
	if !ValidTenancyPair(tenantID, partitionID) {
		return nil, ErrIncompleteTenancyPair
	}

	return map[string]any{
		"tenant_id":         tenantID,
		"partition_id":      partitionID,
		"access_id":         loginEvent.GetAccessID(),
		"contact_id":        loginEvent.GetContactID(),
		"session_id":        loginEvent.GetID(),
		"login_event_id":    loginEvent.GetID(),
		"oauth2_session_id": loginEvent.Oauth2SessionID,
		"roles":             roles,
		"device_id":         deviceID,
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
func (h *AuthServer) shouldRenderBrowserInterstitial(req *http.Request, clientObj *tenancyv2.OAuthClient) bool {
	_, isPartition := clientObj.GetOwner().(*tenancyv2.OAuthClient_PartitionId)
	if !isPartition {
		return false
	}

	if req.Method != http.MethodGet {
		return false
	}

	if !acceptsHTML(req) || isProgrammaticRequest(req) {
		return false
	}

	return true
}

func acceptsHTML(req *http.Request) bool {
	accept := req.Header.Get("Accept")
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml+xml")
}

func isProgrammaticRequest(req *http.Request) bool {
	if req.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return true
	}

	contentType := req.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		return true
	}

	secFetchMode := req.Header.Get("Sec-Fetch-Mode")
	if secFetchMode == "cors" || secFetchMode == "same-origin" {
		return true
	}

	return false
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
	if deviceObj == nil || deviceObj.GetId() == "" {
		return nil
	}

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
