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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/events"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	hydraclientgo "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/util"
)

type serviceAccountAuthContext struct {
	ClientID         string
	ServiceAccountID string
	TenantID         string
	PartitionID      string
	ProfileID        string
	Type             string
	AccessID         string
}

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
// Priority: access_token > ext.id_token_claims > ext (complete tenancy pair) > session.extra
//
// tenant_id and partition_id are always treated as a pair: a source that only
// carries one of them is not preferred over a fuller source, and is never
// considered "complete consent extras" on its own.
func selectFinalClaims(accessTokenClaims, deepNestedClaims, extClaims, extraClaims map[string]any) map[string]any {
	if len(accessTokenClaims) > 0 {
		return accessTokenClaims
	}
	if len(deepNestedClaims) > 0 {
		return deepNestedClaims
	}
	if len(extClaims) > 0 && ClaimsHaveTenancyPair(extClaims) {
		// Consent-set extras always carry the full tenancy pair (unlike
		// contact_id which may be empty and omitted by Hydra's JSON
		// serialisation for some flows).
		return extClaims
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

// writeTokenHookResponseWithSubject writes a token enrichment response.
//
// Platform invariant (docs/IDENTITY_AND_AUTHORIZATION.md):
//
//	JWT sub === profile_id always.
//
// subject must be the profile_id (bot profile for service accounts). We always
// write profile_id into access/id token claims and return top-level "subject"
// so Hydra can set sub when supported.
//
// Hydra v26 client_credentials still forces wire sub=client_id and ignores the
// hook subject field. Frame NormalizeIdentity() then rewrites in-process
// Subject to profile_id after JWT validation — never treat client_id as actor.
func writeTokenHookResponseWithSubject(rw http.ResponseWriter, claims map[string]any, subject string) error {
	if claims != nil && subject != "" {
		// profile_id must always be present — it is the authorization actor
		// and the source Frame uses to normalise JWT sub.
		claims["profile_id"] = subject
	}
	hookResponse := map[string]any{
		"session": map[string]any{
			"access_token": claims,
			"id_token":     claims,
		},
		// Requested JWT sub. Hydra v26 may ignore this for client_credentials;
		// profile_id claim + Frame NormalizeIdentity still enforce the invariant.
		"subject": subject,
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
	}
}

func buildServiceAccountClaims(
	loginEventID string,
	sa *serviceAccountAuthContext,
	accessID string,
	roles []string,
) (map[string]any, error) {
	if sa == nil {
		return nil, errors.New("service account context is required")
	}
	tenantID, partitionID := NormalizeTenancyPair(sa.TenantID, sa.PartitionID)
	if !ValidTenancyPair(tenantID, partitionID) {
		return nil, ErrIncompleteTenancyPair
	}

	// Flat claims only — Hydra already nests the whole access_token map under
	// JWT "ext" when mirror_top_level_claims is on. Nesting another "ext" here
	// produced ext.ext.service_account_id and broke permission registration
	// ownership checks (403). Keep service_account_id at the same level as
	// profile_id so Frame claims.Ext["service_account_id"] resolves.
	claims := map[string]any{
		"tenant_id":          tenantID,
		"partition_id":       partitionID,
		"roles":              roles,
		"profile_id":         sa.ProfileID,
		"session_id":         loginEventID,
		"login_event_id":     loginEventID,
		"service_account_id": sa.ServiceAccountID,
	}
	if accessID != "" {
		claims["access_id"] = accessID
	}
	return claims, nil
}

// extractSessionAccessTokenClaims extracts the access_token claims from the session object.
// These claims were set server-side during consent and are trusted.
func extractSessionAccessTokenClaims(tokenObject map[string]any) map[string]any {
	session, ok := tokenObject["session"].(map[string]any)
	if !ok {
		return nil
	}
	claims, ok := session["access_token"].(map[string]any)
	if !ok || len(claims) == 0 {
		return nil
	}
	return claims
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

// loginEventRoles extracts the "roles" list stored in a login event's Properties.
// Returns nil if not present, letting callers fall back to a default.
func loginEventRoles(loginEvent *models.LoginEvent) []string {
	if loginEvent == nil || loginEvent.Properties == nil {
		return nil
	}
	raw, ok := loginEvent.Properties["roles"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		roles := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				roles = append(roles, s)
			}
		}
		if len(roles) > 0 {
			return roles
		}
	}
	return nil
}

func missingRequiredUserClaims(claims map[string]any) []string {
	required := []string{"access_id", "session_id", "profile_id"}
	missing := make([]string, 0, len(required)+2)

	// Tenancy is atomic: either both tenant_id and partition_id are present,
	// or both are reported missing so partial pairs never pass validation.
	if !ClaimsHaveTenancyPair(claims) {
		missing = append(missing, "tenant_id", "partition_id")
	}

	for _, key := range required {
		if claimString(claims, key) == "" {
			missing = append(missing, key)
		}
	}
	return missing
}

// reconstructClaimsFromLoginEvent rebuilds claims from the login event DB when
// consent-set claims are incomplete. It preserves roles from the incoming claims
// (set at consent time) rather than re-fetching them from the partition service.
func (h *AuthServer) reconstructClaimsFromLoginEvent(
	ctx context.Context,
	tokenObject map[string]any,
	claims map[string]any,
) (map[string]any, error) {
	log := util.Log(ctx)

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

	// Preserve roles from consent-set claims; fallback to login event properties, then ["user"].
	if roles := claims["roles"]; roles != nil {
		canonical["roles"] = roles
	} else if roles := loginEventRoles(loginEvent); roles != nil {
		canonical["roles"] = roles
	} else {
		log.Warn("no roles in consent claims or login event - defaulting to user")
		canonical["roles"] = []string{"user"}
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
// This is called during initial token issuance.
//
// Parent budget keeps Hydra's token_hook under the p99 envelope even on a cold
// SA cache miss (Hydra admin + Valkey). Warm path is typically << 50ms.
func (h *AuthServer) TokenEnrichmentEndpoint(rw http.ResponseWriter, req *http.Request) error {
	parent := req.Context()
	// Cold budget is the worst-case envelope; warm SA hits finish far sooner.
	log := util.Log(parent)

	tokenObject, err := h.parseTokenWebhookRequest(parent, req)
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
	log = log.WithField("client_id", clientID)
	parent = util.ContextWithLogger(parent, log)

	// Handle service account scoped tokens (system_internal or system_external).
	// For client_credentials grants Hydra does NOT call consent — only this webhook.
	// Normalise them through a durable login_event so every service-account login
	// is traceable and refreshes preserve the same event linkage.
	grantedScopes := extractGrantedScopes(tokenObject)
	if grantType == "client_credentials" {
		return h.handleServiceAccountEnrichment(parent, rw, tokenObject, clientID, tokenType, grantType, grantedScopes)
	}

	// Handle regular user tokens
	return h.handleUserTokenEnrichment(parent, rw, tokenObject, clientID, tokenType, grantType, grantedScopes)
}

// parseTokenWebhookRequest reads and parses the webhook request body.
func (h *AuthServer) parseTokenWebhookRequest(parent context.Context, req *http.Request) (map[string]any, error) {
	log := util.Log(parent)
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

	log.WithField("payload_keys", getMapKeys(tokenObject)).Debug("token enrichment webhook received")
	return tokenObject, nil
}

// writeWebhookError writes a permanent denial (403) so Hydra treats the token
// mint as access_denied.
func (h *AuthServer) writeWebhookError(rw http.ResponseWriter, errMsg string) error {
	return h.writeWebhookErrorStatus(rw, http.StatusForbidden, errMsg)
}

// writeWebhookErrorStatus writes a JSON error with an explicit status.
// Use 5xx for transient failures so Hydra/clients can retry instead of
// permanently failing with access_denied.
func (h *AuthServer) writeWebhookErrorStatus(rw http.ResponseWriter, status int, errMsg string) error {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	return json.NewEncoder(rw).Encode(map[string]string{"error": errMsg})
}

// handleServiceAccountEnrichment handles token enrichment for service account
// client_credentials tokens (both internal and external).
//
// Hot path: shared Frame cache (GenericCache on RawCache) → Hydra admin on miss
// → claims with stable session_id. Durable login_events audit is emitted to the
// Frame events queue and never blocks token issuance when claims are complete.
func (h *AuthServer) handleServiceAccountEnrichment(parent context.Context, rw http.ResponseWriter, tokenObject map[string]any, clientID, tokenType, grantType string, grantedScopes []string) error {
	log := util.Log(parent).WithField("client_id", clientID)
	start := time.Now()

	sa, fromCache, err := h.lookupServiceAccountByClientIDCached(parent, clientID)
	if err != nil {
		// Permanent miss → 403 (access_denied). Transient Hydra/network → 503
		// so Hydra does not permanently fail every M2M mint during a blip.
		if isDefinitiveServiceAccountMiss(err) {
			log.WithError(err).Error("service account lookup failed (permanent)")
			return h.writeWebhookError(rw, "service account not found")
		}
		log.WithError(err).Error("service account lookup failed (transient)")
		return h.writeWebhookErrorStatus(rw, http.StatusServiceUnavailable, "service account lookup temporarily unavailable")
	}

	// Validate scope matches SA type
	if err = validateScopeMatchesSAType(grantedScopes, sa.Type); err != nil {
		log.WithError(err).Error("scope/type mismatch")
		return h.writeWebhookError(rw, err.Error())
	}

	// Pass SA type directly as the role — no transformation
	// NOTE: Profile type validation (BOT for internal, PERSON/INSTITUTION for
	// external) is enforced at SA creation time, not here.
	roles := []string{sa.Type}

	sessionClaims := extractSessionAccessTokenClaims(tokenObject)
	sessionID := stableSASessionID(clientID)

	accessID := sa.AccessID
	if accessID == "" {
		accessID = claimString(sessionClaims, "access_id")
	}

	claims, claimsErr := buildServiceAccountClaims(sessionID, sa, accessID, roles)
	if claimsErr != nil {
		log.WithError(claimsErr).Error("service account claims incomplete")
		return h.writeWebhookError(rw, "incomplete tenancy claims")
	}

	// Durable audit is off the hot path via Frame events (queue-backed).
	// Token issuance never waits on DB INSERT.
	h.emitServiceAccountLoginAudit(parent, clientID, sa, sessionID, tokenType, grantType, grantedScopes)

	log.WithFields(map[string]any{
		"login_event_id": sessionID,
		"profile_id":     sa.ProfileID,
		"partition_id":   sa.PartitionID,
		"tenant_id":      sa.TenantID,
		"sa_type":        sa.Type,
		"token_type":     tokenType,
		"grant_type":     grantType,
		"sa_cache_hit":   fromCache,
		"duration_ms":    time.Since(start).Milliseconds(),
	}).Info("enriched service account token")

	// Override JWT sub to profile_id — for client_credentials Hydra defaults
	// sub to the client_id, but the canonical identity is the profile_id.
	return writeTokenHookResponseWithSubject(rw, claims, sa.ProfileID)
}

// lookupServiceAccountByClientIDCached uses Frame GenericCache over the shared
// RawCache backend (memory / NATS KV / Valkey).
func (h *AuthServer) lookupServiceAccountByClientIDCached(
	parent context.Context,
	clientID string,
) (*serviceAccountAuthContext, bool, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, false, fmt.Errorf("client_id is required")
	}
	if sa, neg, ok := h.getCachedServiceAccount(parent, clientID); ok {
		if neg {
			return nil, true, fmt.Errorf("service account not found (cached)")
		}
		return sa, true, nil
	}

	sa, err := h.lookupServiceAccountByClientID(parent, clientID)
	if err != nil {
		// Only negative-cache definitive "not found" / incomplete metadata.
		// Timeouts and transport errors must not poison the warm path for 2s —
		// that turns a single Hydra blip into a wave of token_hook 403s.
		if isDefinitiveServiceAccountMiss(err) {
			h.setCachedServiceAccountNegative(parent, clientID, saNegativeCacheTTL)
		}
		return nil, false, fmt.Errorf("lookup service account %q: %w", clientID, err)
	}
	h.setCachedServiceAccount(parent, clientID, sa, saClaimsCacheTTL)
	return sa, false, nil
}

// isDefinitiveServiceAccountMiss reports whether the error means the client
// will never succeed without operator action (missing client / metadata),
// as opposed to a transient Hydra or network failure.
func isDefinitiveServiceAccountMiss(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	msg := strings.ToLower(err.Error())
	// Hydra / our wrappers surface these for permanent client problems.
	for _, needle := range []string{
		"not found",
		"does not exist",
		"metadata missing",
		"metadata incomplete",
		"404",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	// Deadline / timeout wording without context.DeadlineExceeded wrap.
	for _, needle := range []string{
		"timeout",
		"deadline exceeded",
		"connection refused",
		"connection reset",
		"temporary failure",
		"i/o timeout",
		"unavailable",
	} {
		if strings.Contains(msg, needle) {
			return false
		}
	}
	// Unknown permanent-looking failures: do not cache (prefer retry).
	return false
}

// emitServiceAccountLoginAudit publishes durable audit work to the Frame events
// queue. Failures are logged only — token response is not blocked.
func (h *AuthServer) emitServiceAccountLoginAudit(
	parent context.Context,
	clientID string,
	sa *serviceAccountAuthContext,
	sessionID string,
	tokenType string,
	grantType string,
	grantedScopes []string,
) {
	if h == nil || sa == nil {
		return
	}
	if h.eventsMan == nil {
		util.Log(parent).WithField("client_id", clientID).
			Debug("sa login audit not emitted — events manager not configured")
		return
	}

	payload := &events.ServiceAccountLoginAuditPayload{
		LoginEventID:     sessionID,
		ClientID:         clientID,
		ServiceAccountID: sa.ServiceAccountID,
		TenantID:         sa.TenantID,
		PartitionID:      sa.PartitionID,
		ProfileID:        sa.ProfileID,
		AccessID:         sa.AccessID,
		SAType:           sa.Type,
		TokenType:        tokenType,
		GrantType:        grantType,
	}
	if len(grantedScopes) > 0 {
		payload.GrantedScopes = append([]string(nil), grantedScopes...)
	}
	if err := h.eventsMan.Emit(parent, events.EventKeyServiceAccountLoginAudit, payload); err != nil {
		util.Log(parent).WithError(err).WithFields(map[string]any{
			"client_id":      clientID,
			"login_event_id": sessionID,
		}).Warn("failed to emit sa login audit event")
	}
}

func (h *AuthServer) lookupServiceAccountByClientID(
	parent context.Context,
	clientID string,
) (*serviceAccountAuthContext, error) {
	if strings.TrimSpace(clientID) == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	client, err := h.defaultHydraCli.GetOAuth2Client(parent, clientID)
	if err != nil {
		return nil, err
	}

	return serviceAccountFromHydraClient(client, clientID)
}

func serviceAccountFromHydraClient(
	client *hydraclientgo.OAuth2Client,
	clientID string,
) (*serviceAccountAuthContext, error) {
	if client == nil {
		return nil, fmt.Errorf("hydra client is required")
	}

	metadata, ok := client.GetMetadata().(map[string]any)
	if !ok {
		return nil, fmt.Errorf("hydra client metadata missing for client_id %s", clientID)
	}

	tenantID, _ := metadata["tenant_id"].(string)
	partitionID, _ := metadata["partition_id"].(string)
	profileID, _ := metadata["profile_id"].(string)
	clientType, _ := metadata["type"].(string)
	accessID, _ := metadata["access_id"].(string)
	serviceAccountID, _ := metadata["service_account_id"].(string)
	if profileID == "" {
		profileID = clientID
	}
	if clientType == "" {
		scope := strings.Fields(strings.TrimSpace(client.GetScope()))
		if slices.Contains(scope, SATypeInternal) {
			clientType = SATypeInternal
		} else if slices.Contains(scope, SATypeExternal) {
			clientType = SATypeExternal
		}
	}

	if tenantID == "" || partitionID == "" || profileID == "" || clientType == "" {
		return nil, fmt.Errorf("hydra client metadata incomplete for client_id %s", clientID)
	}

	return &serviceAccountAuthContext{
		ClientID:         clientID,
		ServiceAccountID: serviceAccountID,
		TenantID:         tenantID,
		PartitionID:      partitionID,
		ProfileID:        profileID,
		Type:             clientType,
		AccessID:         accessID,
	}, nil
}

// TODO: Move profile type validation to SA creation time in the tenancy service.
// Internal SAs must be attached to BOT profiles; external SAs to PERSON/INSTITUTION.
// This cannot run in the token webhook because it creates a circular dependency:
// token → webhook → profile service → needs token → webhook → ...

// handleUserTokenEnrichment handles token enrichment for regular user tokens.
// Consent is the single authority for all token claims including roles.
// The webhook passes through complete consent-set claims and only reconstructs
// from the login event DB when claims are missing (edge case).
func (h *AuthServer) handleUserTokenEnrichment(parent context.Context, rw http.ResponseWriter, tokenObject map[string]any, clientID, tokenType, grantType string, grantedScopes []string) error {
	log := util.Log(parent)
	session, sessionOk := tokenObject["session"].(map[string]any)
	if !sessionOk {
		log.WithFields(map[string]any{
			"session_type": fmt.Sprintf("%T", tokenObject["session"]),
			"client_id":    clientID,
		}).Warn("session is not a map")
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
		finalClaims = h.lookupClaimsFromDB(parent, tokenObject, idTokenWrapper, nestedIdTokenClaims, session)
	}

	if len(finalClaims) == 0 {
		log.Warn("no session claims found for regular user token")
		return h.writeWebhookError(rw, "missing user claims in consent session")
	}

	// If the session claims contain non-user roles (internal/external),
	// pass them through directly. These tokens were set server-side during consent
	// and do not require login event lookup — but the tenancy pair is still required.
	if isNonUserRole(finalClaims["roles"]) {
		if !ClaimsHaveTenancyPair(finalClaims) {
			log.Warn("token enrichment rejected: non-user roles without complete tenancy pair")
			return h.writeWebhookError(rw, "incomplete tenancy claims")
		}
		log.Debug("non-user role detected in session claims - passing through without login event lookup")
		return writeTokenHookResponse(rw, finalClaims)
	}

	// Fast path: if all required claims are present from consent, pass through directly.
	// This avoids DB and partition service calls during token refresh.
	if missing := missingRequiredUserClaims(finalClaims); len(missing) == 0 {
		h.traceUserTokenWebhook(parent, tokenObject, finalClaims, tokenType, grantType, grantedScopes)
		log.WithFields(map[string]any{
			"client_id":      clientID,
			"login_event_id": claimString(finalClaims, "session_id"),
			"token_type":     tokenType,
			"grant_type":     grantType,
		}).Debug("complete consent claims - passing through without DB reconstruction")
		return writeTokenHookResponse(rw, finalClaims)
	}

	// Slow path: claims incomplete — reconstruct from login event DB, preserving consent-set roles.
	canonicalClaims, err := h.reconstructClaimsFromLoginEvent(parent, tokenObject, finalClaims)
	if err != nil {
		log.WithError(err).Warn("token enrichment rejected: login_event mapping failed")
		return h.writeWebhookError(rw, "unable to map token to login event")
	}

	if missing := missingRequiredUserClaims(canonicalClaims); len(missing) > 0 {
		log.WithField("missing_claims", missing).Warn("token enrichment rejected: required claims missing")
		return h.writeWebhookError(rw, "required user claims missing")
	}

	h.traceUserTokenWebhook(parent, tokenObject, canonicalClaims, tokenType, grantType, grantedScopes)
	log.WithField("claims_keys", getMapKeys(canonicalClaims)).Debug("enriching token with reconstructed user claims")
	return writeTokenHookResponse(rw, canonicalClaims)
}

func (h *AuthServer) getOrCreateLoginRecord(parent context.Context, profileID, clientID, source string) (*models.Login, error) {
	var (
		login *models.Login
		err   error
	)

	if profileID != "" {
		login, err = h.loginRepo.GetByProfileID(parent, profileID)
		if err != nil && !data.ErrorIsNoRows(err) {
			return nil, err
		}
	}

	if login != nil && login.ClientID != "" && login.ClientID != clientID {
		login = nil
	}

	if login == nil {
		login = &models.Login{
			ProfileID: profileID,
			ClientID:  clientID,
			Source:    source,
		}
		login.GenID(parent)
		if err = h.loginRepo.Create(parent, login); err != nil {
			return nil, err
		}
	}

	return login, nil
}

func (h *AuthServer) recordTokenWebhookTrace(
	parent context.Context,
	loginEvent *models.LoginEvent,
	tokenType string,
	grantType string,
	principalType string,
	grantedScopes []string,
) {
	if loginEvent == nil {
		return
	}

	props := loginEvent.Properties
	if props == nil {
		props = data.JSONMap{}
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	tracePayload := map[string]any{
		"last_seen_at":   now,
		"token_type":     tokenType,
		"grant_type":     grantType,
		"principal_type": principalType,
	}
	if len(grantedScopes) > 0 {
		tracePayload["granted_scopes"] = append([]string(nil), grantedScopes...)
	}

	if existingTrace, ok := props["token_webhook"].(map[string]any); ok {
		for key, value := range existingTrace {
			tracePayload[key] = value
		}
	}
	if _, ok := tracePayload["first_seen_at"]; !ok {
		tracePayload["first_seen_at"] = now
	}
	if currentCount, ok := tracePayload["count"].(float64); ok {
		tracePayload["count"] = int(currentCount) + 1
	} else if currentCount, ok := tracePayload["count"].(int); ok {
		tracePayload["count"] = currentCount + 1
	} else {
		tracePayload["count"] = 1
	}

	props["token_webhook"] = tracePayload
	loginEvent.Properties = props
	if _, err := h.loginEventRepo.Update(parent, loginEvent, "properties"); err != nil {
		util.Log(parent).WithError(err).WithField("login_event_id", loginEvent.GetID()).
			Warn("failed to persist token webhook trace on login event")
	}
}

func (h *AuthServer) traceUserTokenWebhook(
	parent context.Context,
	tokenObject map[string]any,
	claims map[string]any,
	tokenType string,
	grantType string,
	grantedScopes []string,
) {
	loginEventID := claimString(claims, "session_id")
	if loginEventID == "" {
		loginEventID = extractLoginEventIDFromWebhook(tokenObject)
	}
	if loginEventID == "" {
		util.Log(parent).WithFields(map[string]any{
			"token_type": tokenType,
			"grant_type": grantType,
		}).Warn("token webhook did not contain a login_event reference for user tracing")
		return
	}

	loginEvent, err := h.loginEventRepo.GetByID(parent, loginEventID)
	if err != nil {
		util.Log(parent).WithError(err).WithField("login_event_id", loginEventID).
			Warn("failed to look up login event while tracing token webhook")
		return
	}
	if loginEvent == nil {
		return
	}

	h.recordTokenWebhookTrace(parent, loginEvent, tokenType, grantType, "user", grantedScopes)
	util.Log(parent).WithFields(map[string]any{
		"login_event_id": loginEvent.GetID(),
		"profile_id":     loginEvent.ProfileID,
		"partition_id":   loginEvent.PartitionID,
		"tenant_id":      loginEvent.TenantID,
		"token_type":     tokenType,
		"grant_type":     grantType,
	}).Debug("traced token webhook against user login event")
}

// lookupClaimsFromDB attempts to look up claims from the database using login event ID or OAuth2 session ID.
// This is a fallback path when no session claims exist at all. Roles default to ["user"] since
// consent-set roles are unavailable in this edge case.
func (h *AuthServer) lookupClaimsFromDB(parent context.Context, tokenObject, idTokenWrapper, nestedIdTokenClaims, session map[string]any) map[string]any {
	log := util.Log(parent)
	subject := extractSubjectFromSession(idTokenWrapper, nestedIdTokenClaims)

	// Try login event ID first (most direct)
	if loginEventID := extractLoginEventIDFromWebhook(tokenObject); loginEventID != "" {
		log.WithField("login_event_id", loginEventID).Debug("attempting login event lookup by ID from claims")
		if loginEvent, err := h.loginEventRepo.GetByID(parent, loginEventID); err == nil && loginEvent != nil {
			if subject == "" {
				subject = loginEvent.ProfileID
			}
			log.WithField("login_event_id", loginEvent.GetID()).Warn("DB fallback: reconstructing claims from login event")
			claims := buildClaimsFromLoginEvent(
				loginEvent.GetID(),
				loginEvent.TenantID,
				loginEvent.PartitionID,
				loginEvent.AccessID,
				loginEvent.ContactID,
				loginEvent.DeviceID,
				subject,
				loginEvent.Oauth2SessionID,
			)
			if roles := loginEventRoles(loginEvent); roles != nil {
				claims["roles"] = roles
			} else {
				claims["roles"] = []string{"user"}
			}
			return claims
		} else {
			log.WithError(err).WithField("login_event_id", loginEventID).Warn("login event not found by ID - token will be missing claims")
		}
		return nil
	}

	// Fallback: try OAuth2 session ID lookup
	if oauth2SessionID := extractOAuth2SessionID(tokenObject); oauth2SessionID != "" {
		log.WithField("oauth2_session_id", oauth2SessionID).Debug("attempting login event lookup by Hydra session ID")
		if loginEvent, err := h.loginEventRepo.GetByOauth2SessionID(parent, oauth2SessionID); err == nil && loginEvent != nil {
			if subject == "" {
				subject = loginEvent.ProfileID
			}
			log.WithFields(map[string]any{
				"login_event_id":    loginEvent.GetID(),
				"oauth2_session_id": oauth2SessionID,
			}).Warn("DB fallback: reconstructing claims from login event")
			claims := buildClaimsFromLoginEvent(
				loginEvent.GetID(),
				loginEvent.TenantID,
				loginEvent.PartitionID,
				loginEvent.AccessID,
				loginEvent.ContactID,
				loginEvent.DeviceID,
				subject,
				loginEvent.Oauth2SessionID,
			)
			if roles := loginEventRoles(loginEvent); roles != nil {
				claims["roles"] = roles
			} else {
				claims["roles"] = []string{"user"}
			}
			return claims
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
