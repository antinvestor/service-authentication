package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/util"
)

// extractGrantedScopes extracts and normalises granted_scopes to []string
// from the first location found in the payload.
func extractGrantedScopes(tokenObject map[string]any) []string {
	var raw []any

	// 1. Top-level
	if v, ok := tokenObject["granted_scopes"]; ok {
		if raw, ok = v.([]any); !ok {
			return nil
		}
	} else if v, ok := tokenObject["request"]; ok {
		// 2. request.granted_scopes
		if req, ok := v.(map[string]any); ok {
			if v, ok = req["granted_scopes"]; ok {
				if raw, ok = v.([]any); !ok {
					return nil
				}
			}
		}
	} else if v, ok := tokenObject["requester"]; ok {
		// 3. requester.granted_scopes
		if req, ok := v.(map[string]any); ok {
			if v, ok = req["granted_scopes"]; ok {
				if raw, ok = v.([]any); !ok {
					return nil
				}
			}
		}
	}

	if raw == nil {
		return nil
	}

	// Exact pre-allocation; worst case all entries are strings
	out := make([]string, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		if s, ok := raw[i].(string); ok {
			out = append(out, s)
		}
	}

	return out
}

// extractLoginEventIDFromWebhook extracts the login event ID (session_id claim) from the webhook payload.
// This is the most direct way to look up the login event during token refresh.
func extractLoginEventIDFromWebhook(tokenObject map[string]any) string {
	session, ok := tokenObject["session"].(map[string]any)
	if !ok {
		return ""
	}

	// Check session.access_token.session_id (our custom claim from consent)
	if accessToken, ok := session["access_token"].(map[string]any); ok {
		if sessionID, ok := accessToken["session_id"].(string); ok && sessionID != "" {
			return sessionID
		}
	}

	// Check session.id_token structure (Hydra v2)
	if idToken, ok := session["id_token"].(map[string]any); ok {
		// Check id_token.id_token_claims.ext.session_id
		if idTokenClaims, ok := idToken["id_token_claims"].(map[string]any); ok {
			if ext, ok := idTokenClaims["ext"].(map[string]any); ok {
				if sessionID, ok := ext["session_id"].(string); ok && sessionID != "" {
					return sessionID
				}
				// Also try ext.id_token_claims.session_id (deep nesting)
				if deepClaims, ok := ext["id_token_claims"].(map[string]any); ok {
					if sessionID, ok := deepClaims["session_id"].(string); ok && sessionID != "" {
						return sessionID
					}
				}
			}
		}
	}

	// Check session.extra.session_id (Hydra v2 alternative)
	if extra, ok := session["extra"].(map[string]any); ok {
		if sessionID, ok := extra["session_id"].(string); ok && sessionID != "" {
			return sessionID
		}
	}

	return ""
}

// extractOAuth2SessionID extracts the Hydra OAuth2 session ID from the webhook payload.
// It checks multiple locations where the session ID might be stored:
// 1. Our custom oauth2_session_id claim set during consent (in session.access_token or nested locations)
// 2. session.id_token.id_token_claims.ext.oauth2_session_id
// 3. session.id (Hydra v2 internal)
// See: https://www.ory.com/docs/hydra/guides/claims-at-refresh
func extractOAuth2SessionID(tokenObject map[string]any) string {
	session, ok := tokenObject["session"].(map[string]any)
	if !ok {
		return ""
	}

	// Check session.access_token.oauth2_session_id (our custom claim from consent)
	if accessToken, ok := session["access_token"].(map[string]any); ok {
		if sessionID, ok := accessToken["oauth2_session_id"].(string); ok && sessionID != "" {
			return sessionID
		}
	}

	// Check session.id_token structure (Hydra v2)
	if idToken, ok := session["id_token"].(map[string]any); ok {
		// Check id_token.id_token_claims.ext.oauth2_session_id
		if idTokenClaims, ok := idToken["id_token_claims"].(map[string]any); ok {
			if ext, ok := idTokenClaims["ext"].(map[string]any); ok {
				if sessionID, ok := ext["oauth2_session_id"].(string); ok && sessionID != "" {
					return sessionID
				}
				// Also try ext.id_token_claims.oauth2_session_id (deep nesting in Hydra v2)
				if deepClaims, ok := ext["id_token_claims"].(map[string]any); ok {
					if sessionID, ok := deepClaims["oauth2_session_id"].(string); ok && sessionID != "" {
						return sessionID
					}
				}
			}
		}
		// Check id_token.oauth2_session_id directly
		if sessionID, ok := idToken["oauth2_session_id"].(string); ok && sessionID != "" {
			return sessionID
		}
	}

	// Check session.extra.oauth2_session_id (Hydra v2 alternative)
	if extra, ok := session["extra"].(map[string]any); ok {
		if sessionID, ok := extra["oauth2_session_id"].(string); ok && sessionID != "" {
			return sessionID
		}
	}

	// Try session.id (Hydra internal session ID)
	if sessionID, ok := session["id"].(string); ok && sessionID != "" {
		return sessionID
	}

	return ""
}

// extractClientID extracts client_id from multiple possible locations in the Hydra payload
func extractClientID(tokenObject map[string]any) string {
	// Try session.client_id first (some Hydra versions)
	if session, ok := tokenObject["session"].(map[string]any); ok {
		if clientID, ok := session["client_id"].(string); ok && clientID != "" {
			return clientID
		}
	}

	// Try request.client_id (standard location for token refresh)
	if request, ok := tokenObject["request"].(map[string]any); ok {
		if clientID, ok := request["client_id"].(string); ok && clientID != "" {
			return clientID
		}
	}

	// Try requester.client_id (alternative location)
	if requester, ok := tokenObject["requester"].(map[string]any); ok {
		if clientID, ok := requester["client_id"].(string); ok && clientID != "" {
			return clientID
		}
	}

	// Try top-level client_id
	if clientID, ok := tokenObject["client_id"].(string); ok && clientID != "" {
		return clientID
	}

	return ""
}

func extractGrantType(tokenObject map[string]any) string {
	parseGrantType := func(v any) string {
		switch typed := v.(type) {
		case string:
			return strings.TrimSpace(typed)
		case []string:
			for i := 0; i < len(typed); i++ {
				if gt := strings.TrimSpace(typed[i]); gt != "" {
					return gt
				}
			}
		case []any:
			for i := 0; i < len(typed); i++ {
				if gt, ok := typed[i].(string); ok {
					gt = strings.TrimSpace(gt)
					if gt != "" {
						return gt
					}
				}
			}
		}
		return ""
	}

	resolveFromContainer := func(container map[string]any) string {
		if container == nil {
			return ""
		}
		if gt := parseGrantType(container["grant_type"]); gt != "" {
			return gt
		}
		if gt := parseGrantType(container["grant_types"]); gt != "" {
			return gt
		}
		return ""
	}

	if request, ok := tokenObject["request"].(map[string]any); ok {
		if gt := resolveFromContainer(request); gt != "" {
			return gt
		}
	}
	if requester, ok := tokenObject["requester"].(map[string]any); ok {
		if gt := resolveFromContainer(requester); gt != "" {
			return gt
		}
	}

	return resolveFromContainer(tokenObject)
}

func inferGrantTypeFromTokenType(tokenType string) string {
	switch strings.ToLower(strings.TrimSpace(tokenType)) {
	case "refresh-token", "refresh_token":
		return "refresh_token"
	default:
		return ""
	}
}

// extractSubjectFromSession extracts the subject from id_token or nested claims.
func extractSubjectFromSession(idTokenWrapper, nestedIdTokenClaims map[string]any) string {
	if idTokenWrapper != nil {
		if s, ok := idTokenWrapper["subject"].(string); ok {
			return s
		}
	}
	if nestedIdTokenClaims != nil {
		if s, ok := nestedIdTokenClaims["sub"].(string); ok {
			return s
		}
	}
	return ""
}

// extractNestedClaims extracts nested claims from the id_token wrapper structure.
// Returns nestedIdTokenClaims, extClaims, deepNestedClaims
func extractNestedClaims(idTokenWrapper map[string]any) (map[string]any, map[string]any, map[string]any) {
	if idTokenWrapper == nil {
		return nil, nil, nil
	}
	nestedIdTokenClaims, _ := idTokenWrapper["id_token_claims"].(map[string]any)
	if nestedIdTokenClaims == nil {
		return nil, nil, nil
	}
	extClaims, _ := nestedIdTokenClaims["ext"].(map[string]any)
	if extClaims == nil {
		return nestedIdTokenClaims, nil, nil
	}
	deepNestedClaims, _ := extClaims["id_token_claims"].(map[string]any)
	return nestedIdTokenClaims, extClaims, deepNestedClaims
}

// selectFinalClaims selects the best available claims from multiple sources.
// Priority: access_token > ext.id_token_claims > ext (with contact_id) > session.extra
func selectFinalClaims(accessTokenClaims, deepNestedClaims, extClaims, extraClaims map[string]any) map[string]any {
	if len(accessTokenClaims) > 0 {
		return accessTokenClaims
	}
	if len(deepNestedClaims) > 0 {
		return deepNestedClaims
	}
	if len(extClaims) > 0 {
		if _, hasContactID := extClaims["contact_id"]; hasContactID {
			return extClaims
		}
	}
	if len(extraClaims) > 0 {
		return extraClaims
	}
	return nil
}

// writeTokenHookResponse writes a token enrichment response with the given claims.
func writeTokenHookResponse(rw http.ResponseWriter, claims map[string]any) error {
	hookResponse := map[string]any{
		"session": map[string]any{
			"access_token": claims,
			"id_token":     claims,
		},
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(hookResponse)
}

// buildClaimsFromLoginEvent creates a canonical claims map from a login event.
func buildClaimsFromLoginEvent(
	loginEventID string,
	tenantID string,
	partitionID string,
	accessID string,
	contactID string,
	deviceID string,
	profileID string,
	oauth2SessionID string,
) map[string]any {
	return map[string]any{
		"tenant_id":         tenantID,
		"partition_id":      partitionID,
		"access_id":         accessID,
		"contact_id":        contactID,
		"session_id":        loginEventID,
		"login_event_id":    loginEventID,
		"oauth2_session_id": oauth2SessionID,
		"device_id":         deviceID,
		"profile_id":        profileID,
		"roles":             []string{"user"},
	}
}

func claimString(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	raw, ok := claims[key]
	if !ok {
		return ""
	}
	value, ok := raw.(string)
	if !ok {
		return ""
	}
	return value
}

func missingRequiredUserClaims(claims map[string]any) []string {
	required := []string{"tenant_id", "partition_id", "access_id", "session_id", "profile_id"}
	missing := make([]string, 0, len(required))
	for _, key := range required {
		if claimString(claims, key) == "" {
			missing = append(missing, key)
		}
	}
	return missing
}

// buildCanonicalClaimsFromLoginEvent enforces strict login_event linkage before token issuance.
func (h *AuthServer) buildCanonicalClaimsFromLoginEvent(
	ctx context.Context,
	tokenObject map[string]any,
	claims map[string]any,
) (map[string]any, error) {
	clientID := extractClientID(tokenObject)
	if clientID == "" {
		return nil, fmt.Errorf("client_id not found")
	}

	var (
		loginEvent *models.LoginEvent
		err        error
	)

	loginEventID := claimString(claims, "session_id")
	if loginEventID == "" {
		loginEventID = extractLoginEventIDFromWebhook(tokenObject)
	}
	if loginEventID != "" {
		loginEvent, err = h.loginEventRepo.GetByID(ctx, loginEventID)
		if err != nil {
			return nil, fmt.Errorf("failed to look up login event by session_id: %w", err)
		}
	}

	if loginEvent == nil {
		oauth2SessionID := extractOAuth2SessionID(tokenObject)
		if oauth2SessionID == "" {
			return nil, fmt.Errorf("missing session_id and oauth2_session_id")
		}
		loginEvent, err = h.loginEventRepo.GetByOauth2SessionID(ctx, oauth2SessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to look up login event by oauth2_session_id: %w", err)
		}
	}

	if loginEvent == nil {
		return nil, fmt.Errorf("login event not found")
	}

	profileID := claimString(claims, "profile_id")
	if profileID == "" {
		profileID = loginEvent.ProfileID
	}
	if profileID == "" {
		return nil, fmt.Errorf("profile_id could not be resolved for login event")
	}

	loginEvent, err = h.ensureLoginEventTenancyAccess(ctx, loginEvent, clientID, profileID)
	if err != nil {
		return nil, err
	}

	canonical := buildClaimsFromLoginEvent(
		loginEvent.GetID(),
		loginEvent.TenantID,
		loginEvent.PartitionID,
		loginEvent.AccessID,
		loginEvent.ContactID,
		loginEvent.DeviceID,
		profileID,
		loginEvent.Oauth2SessionID,
	)
	if roles, ok := claims["roles"]; ok {
		canonical["roles"] = roles
	}
	if canonical["device_id"] == "" {
		if deviceID := claimString(claims, "device_id"); deviceID != "" {
			canonical["device_id"] = deviceID
		}
	}
	if canonical["contact_id"] == "" {
		if contactID := claimString(claims, "contact_id"); contactID != "" {
			canonical["contact_id"] = contactID
		}
	}

	return canonical, nil
}

// TokenEnrichmentEndpoint handles token enrichment requests from Ory Hydra
// This is called during initial token issuance
func (h *AuthServer) TokenEnrichmentEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	log := util.Log(ctx)

	tokenObject, err := h.parseTokenWebhookRequest(ctx, req)
	if err != nil {
		return err
	}

	tokenType := req.PathValue("tokenType")

	// Validate grant_type
	grantType := extractGrantType(tokenObject)
	if grantType == "" {
		grantType = inferGrantTypeFromTokenType(tokenType)
	}
	if grantType == "" {
		log.WithField("token_type", tokenType).Error("grant_type not found in any location")
		return h.writeWebhookError(rw, "grant_type not found")
	}

	// Extract and validate client_id
	clientID := extractClientID(tokenObject)
	if clientID == "" {
		log.Error("client_id not found in any location")
		return h.writeWebhookError(rw, "client_id not found")
	}
	log.WithField("client_id", clientID).Info("processing token enrichment for client")

	// Handle API key clients
	if isClientIDApiKey(clientID) {
		return h.handleAPIKeyEnrichment(ctx, rw, clientID)
	}

	// Handle system internal scoped tokens
	grantedScopes := extractGrantedScopes(tokenObject)
	if grantedScopes == nil {
		log.Warn("granted_scopes not found - treating as regular user token refresh")
	} else if isInternalSystemScoped(grantedScopes) {
		log.Debug("enriched token with system_internal roles")
		return writeTokenHookResponse(rw, map[string]any{"roles": []string{"system_internal"}})
	}

	// Handle regular user tokens
	return h.handleUserTokenEnrichment(ctx, rw, tokenObject)
}

// parseTokenWebhookRequest reads and parses the webhook request body.
func (h *AuthServer) parseTokenWebhookRequest(ctx context.Context, req *http.Request) (map[string]any, error) {
	log := util.Log(ctx)
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.WithError(err).Error("could not read request body")
		return nil, err
	}

	var tokenObject map[string]any
	if err = json.Unmarshal(body, &tokenObject); err != nil {
		log.WithError(err).Error("could not unmarshal request body")
		return nil, err
	}

	log.WithField("payload_keys", getMapKeys(tokenObject)).Info("token enrichment webhook received")
	return tokenObject, nil
}

// writeWebhookError writes a JSON error response.
func (h *AuthServer) writeWebhookError(rw http.ResponseWriter, errMsg string) error {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusForbidden)
	return json.NewEncoder(rw).Encode(map[string]string{"error": errMsg})
}

// handleAPIKeyEnrichment handles token enrichment for API key clients.
func (h *AuthServer) handleAPIKeyEnrichment(ctx context.Context, rw http.ResponseWriter, clientID string) error {
	apiKeyModel, err := h.apiKeyRepo.GetByKey(ctx, clientID)
	if err != nil {
		util.Log(ctx).WithError(err).Error("could not find api key")
		return err
	}

	roles := []string{"system_external"}
	if apiKeyModel.Scope != "" {
		var scopeList []string
		if json.Unmarshal([]byte(apiKeyModel.Scope), &scopeList) == nil {
			roles = scopeList
		}
	}

	return writeTokenHookResponse(rw, map[string]any{
		"tenant_id":    apiKeyModel.TenantID,
		"partition_id": apiKeyModel.PartitionID,
		"roles":        roles,
	})
}

// handleUserTokenEnrichment handles token enrichment for regular user tokens.
func (h *AuthServer) handleUserTokenEnrichment(ctx context.Context, rw http.ResponseWriter, tokenObject map[string]any) error {
	log := util.Log(ctx)
	session, sessionOk := tokenObject["session"].(map[string]any)
	if !sessionOk {
		log.WithField("session_type", fmt.Sprintf("%T", tokenObject["session"])).Warn("session is not a map")
	} else {
		log.WithField("session_keys", getMapKeys(session)).Debug("session structure")
	}

	// Extract claims from various Hydra v2 locations
	accessTokenClaims, _ := session["access_token"].(map[string]any)
	idTokenWrapper, _ := session["id_token"].(map[string]any)
	extraClaims, _ := session["extra"].(map[string]any)
	nestedIdTokenClaims, extClaims, deepNestedClaims := extractNestedClaims(idTokenWrapper)

	log.WithFields(map[string]any{
		"access_token_keys":     getMapKeys(accessTokenClaims),
		"id_token_wrapper_keys": getMapKeys(idTokenWrapper),
		"nested_id_token_keys":  getMapKeys(nestedIdTokenClaims),
		"ext_claims_keys":       getMapKeys(extClaims),
		"deep_nested_keys":      getMapKeys(deepNestedClaims),
		"extra_keys":            getMapKeys(extraClaims),
	}).Debug("extracted session claims from all locations")

	// Select claims from session or fall back to database lookup
	finalClaims := selectFinalClaims(accessTokenClaims, deepNestedClaims, extClaims, extraClaims)
	if finalClaims == nil {
		finalClaims = h.lookupClaimsFromDB(ctx, tokenObject, idTokenWrapper, nestedIdTokenClaims, session)
	} else {
		log.Debug("using claims from session")
	}

	if len(finalClaims) == 0 {
		log.Warn("no session claims found for regular user token")
		return h.writeWebhookError(rw, "missing user claims in consent session")
	}

	canonicalClaims, err := h.buildCanonicalClaimsFromLoginEvent(ctx, tokenObject, finalClaims)
	if err != nil {
		log.WithError(err).Warn("token enrichment rejected: login_event mapping failed")
		return h.writeWebhookError(rw, "unable to map token to login event")
	}

	if missing := missingRequiredUserClaims(canonicalClaims); len(missing) > 0 {
		log.WithField("missing_claims", missing).Warn("token enrichment rejected: required claims missing")
		return h.writeWebhookError(rw, "required user claims missing")
	}

	log.WithField("claims_keys", getMapKeys(canonicalClaims)).Info("enriching token with canonical user claims")
	return writeTokenHookResponse(rw, canonicalClaims)
}

// lookupClaimsFromDB attempts to look up claims from the database using login event ID or OAuth2 session ID.
func (h *AuthServer) lookupClaimsFromDB(ctx context.Context, tokenObject, idTokenWrapper, nestedIdTokenClaims, session map[string]any) map[string]any {
	log := util.Log(ctx)
	subject := extractSubjectFromSession(idTokenWrapper, nestedIdTokenClaims)

	// Try login event ID first (most direct)
	if loginEventID := extractLoginEventIDFromWebhook(tokenObject); loginEventID != "" {
		log.WithField("login_event_id", loginEventID).Debug("attempting login event lookup by ID from claims")
		if loginEvent, err := h.loginEventRepo.GetByID(ctx, loginEventID); err == nil && loginEvent != nil {
			if subject == "" {
				subject = loginEvent.ProfileID
			}
			log.WithField("login_event_id", loginEvent.GetID()).Info("enriched token with claims from login event ID lookup")
			return buildClaimsFromLoginEvent(
				loginEvent.GetID(),
				loginEvent.TenantID,
				loginEvent.PartitionID,
				loginEvent.AccessID,
				loginEvent.ContactID,
				loginEvent.DeviceID,
				subject,
				loginEvent.Oauth2SessionID,
			)
		} else {
			log.WithError(err).WithField("login_event_id", loginEventID).Warn("login event not found by ID - token will be missing claims")
		}
		return nil
	}

	// Fallback: try OAuth2 session ID lookup
	if oauth2SessionID := extractOAuth2SessionID(tokenObject); oauth2SessionID != "" {
		log.WithField("oauth2_session_id", oauth2SessionID).Debug("attempting login event lookup by Hydra session ID")
		if loginEvent, err := h.loginEventRepo.GetByOauth2SessionID(ctx, oauth2SessionID); err == nil && loginEvent != nil {
			if subject == "" {
				subject = loginEvent.ProfileID
			}
			log.WithFields(map[string]any{
				"login_event_id":    loginEvent.GetID(),
				"oauth2_session_id": oauth2SessionID,
			}).Info("enriched token with claims from OAuth2 session ID lookup")
			return buildClaimsFromLoginEvent(
				loginEvent.GetID(),
				loginEvent.TenantID,
				loginEvent.PartitionID,
				loginEvent.AccessID,
				loginEvent.ContactID,
				loginEvent.DeviceID,
				subject,
				loginEvent.Oauth2SessionID,
			)
		} else {
			log.WithError(err).WithField("oauth2_session_id", oauth2SessionID).Warn("login event not found for Hydra session ID - token will be missing claims")
		}
		return nil
	}

	log.WithFields(map[string]any{
		"subject":      subject,
		"payload_keys": getMapKeys(tokenObject),
		"session_keys": getMapKeys(session),
	}).Warn("no login_event_id or oauth2_session_id found - cannot look up login event")
	return nil
}

// getMapKeys returns the keys of a map for logging purposes.
func getMapKeys(m map[string]any) []string {
	if m == nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
