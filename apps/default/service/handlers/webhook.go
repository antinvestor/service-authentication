package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
	request, ok := tokenObject["request"].(map[string]any)
	if !ok {
		return ""
	}

	// grant_types is a JSON array which unmarshals to []any, not []string
	if raw, ok := request["grant_types"].([]any); ok && len(raw) == 1 {
		if s, ok := raw[0].(string); ok {
			return s
		}
	}

	// Fallback: singular grant_type string
	if gt, ok := request["grant_type"].(string); ok {
		return gt
	}

	return ""
}

// TokenEnrichmentEndpoint handles token enrichment requests from Ory Hydra
// This is called during initial token issuance
func (h *AuthServer) TokenEnrichmentEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	log := util.Log(ctx)

	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.WithError(err).Error("could not read request body")
		return err
	}

	var tokenObject map[string]any
	err = json.Unmarshal(body, &tokenObject)
	if err != nil {
		log.WithError(err).Error("could not unmarshal request body")
		return err
	}

	// Log the incoming payload for debugging
	payloadKeys := make([]string, 0, len(tokenObject))
	for k := range tokenObject {
		payloadKeys = append(payloadKeys, k)
	}
	log.WithField("payload_keys", payloadKeys).Info("token enrichment webhook received")

	grantType := extractGrantType(tokenObject)
	if grantType == "" {
		log.WithField("request", body).Error("grant_type not found in any location (session, request, requester, top-level)")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusForbidden)
		return json.NewEncoder(rw).Encode(map[string]string{"error": "grant_type not found"})
	}

	// Extract client_id from multiple possible locations
	clientID := extractClientID(tokenObject)
	if clientID == "" {
		log.Error("client_id not found in any location (session, request, requester, top-level)")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusForbidden)
		return json.NewEncoder(rw).Encode(map[string]string{"error": "client_id not found"})
	}

	log.WithField("client_id", clientID).Info("processing token enrichment for client")

	if isClientIDApiKey(clientID) {

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
				roles = scopeList
			}
		}

		tokenMap := map[string]any{
			"tenant_id":    apiKeyModel.TenantID,
			"partition_id": apiKeyModel.PartitionID,
			"roles":        roles,
		}

		// Return only the session object per Hydra's expected webhook response format
		// See: https://www.ory.com/docs/hydra/guides/claims-at-refresh
		hookResponse := map[string]any{
			"session": map[string]any{
				"access_token": tokenMap,
				"id_token":     tokenMap,
			},
		}

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(hookResponse)
	}

	// Extract granted_scopes from multiple possible locations
	grantedScopes := extractGrantedScopes(tokenObject)
	if grantedScopes == nil {
		// For token refresh, granted_scopes might not be in the expected location
		// Don't fail - just log and treat as regular user pass-through
		log.Warn("granted_scopes not found - treating as regular user token refresh")
	} else if isInternalSystemScoped(grantedScopes) {
		tokenMap := map[string]any{"roles": []string{"system_internal"}}

		hookResponse := map[string]any{
			"session": map[string]any{
				"access_token": tokenMap,
				"id_token":     tokenMap,
			},
		}

		log.Debug("enriched token with system_internal roles")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(hookResponse)
	}

	// Regular user: extract session claims and return them explicitly.
	// With mirror_top_level_claims: false, we must actively return claims
	// for them to appear in the access token.
	session, sessionOk := tokenObject["session"].(map[string]any)
	if !sessionOk {
		log.WithField("session_type", fmt.Sprintf("%T", tokenObject["session"])).Warn("session is not a map")
	} else {
		log.WithField("session_keys", getMapKeys(session)).Debug("session structure")
	}

	// Hydra v2 stores claims in multiple possible locations:
	// 1. session.access_token / session.id_token (standard - but often empty in v2)
	// 2. session.extra (Hydra v2 alternative)
	// 3. session.id_token.id_token_claims (nested structure in v2)
	accessTokenClaims, _ := session["access_token"].(map[string]any)
	idTokenWrapper, _ := session["id_token"].(map[string]any)
	extraClaims, _ := session["extra"].(map[string]any)

	// Check for nested id_token_claims within session.id_token
	var nestedIdTokenClaims map[string]any
	if idTokenWrapper != nil {
		nestedIdTokenClaims, _ = idTokenWrapper["id_token_claims"].(map[string]any)
	}

	// Log what we found in all locations
	log.WithFields(map[string]any{
		"access_token_keys":        getMapKeys(accessTokenClaims),
		"id_token_wrapper_keys":    getMapKeys(idTokenWrapper),
		"nested_id_token_keys":     getMapKeys(nestedIdTokenClaims),
		"extra_keys":               getMapKeys(extraClaims),
		"access_token_nil":         accessTokenClaims == nil,
		"nested_id_token_nil":      nestedIdTokenClaims == nil,
		"extra_nil":                extraClaims == nil,
	}).Debug("extracted session claims from all locations")

	// Determine which claims to use (check multiple locations)
	var finalClaims map[string]any
	if accessTokenClaims != nil && len(accessTokenClaims) > 0 {
		finalClaims = accessTokenClaims
		log.Debug("using session.access_token claims")
	} else if nestedIdTokenClaims != nil && len(nestedIdTokenClaims) > 0 {
		finalClaims = nestedIdTokenClaims
		log.WithField("nested_keys", getMapKeys(nestedIdTokenClaims)).Info("using session.id_token.id_token_claims")
	} else if extraClaims != nil && len(extraClaims) > 0 {
		finalClaims = extraClaims
		log.WithField("extra_keys", getMapKeys(extraClaims)).Info("using session.extra as claims")
	}

	// If we have session claims from consent, return them so Hydra includes them in the token
	if finalClaims != nil && len(finalClaims) > 0 {
		hookResponse := map[string]any{
			"session": map[string]any{
				"access_token": finalClaims,
				"id_token":     finalClaims,
			},
		}
		log.WithField("claims_keys", getMapKeys(finalClaims)).Info("enriching token with consent session claims")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(hookResponse)
	}

	// No session claims found - this shouldn't happen for a valid consent flow
	log.Warn("no session claims found for regular user - token will be missing custom claims")
	rw.WriteHeader(http.StatusNoContent)
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
