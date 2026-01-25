package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pitabwire/frame/client"
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

// GetOauth2ClientById obtains a client id
func GetOauth2ClientById(ctx context.Context, cl client.Manager,
	oauth2ServiceAdminHost string, clientID string) (int, []byte, error) {

	oauth2AdminURI := fmt.Sprintf("%s%s/%s", oauth2ServiceAdminHost, "/admin/clients", clientID)

	resultStatus, resultBody, err := cl.Invoke(ctx, http.MethodGet, oauth2AdminURI, nil, nil)
	if err != nil {
		return 0, nil, err
	}
	return resultStatus, resultBody, err
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

// TokenEnrichmentEndpoint handles token enrichment requests from Ory Hydra
// This is called during both initial token issuance and token refresh
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

	response := tokenObject

	// Ensure session object exists in the response
	sessionData, ok := tokenObject["session"].(map[string]any)
	if !ok {
		// Initialise session if not present
		sessionData = make(map[string]any)
		response["session"] = sessionData
		log.Warn("session object not present in webhook payload - initialising empty")
	} else {
		// Log session structure for debugging
		sessionKeys := make([]string, 0, len(sessionData))
		for k := range sessionData {
			sessionKeys = append(sessionKeys, k)
		}
		log.WithField("session_keys", sessionKeys).Info("webhook session structure")

		// Log access_token keys if present
		if accessToken, ok := sessionData["access_token"].(map[string]any); ok {
			atKeys := make([]string, 0, len(accessToken))
			for k := range accessToken {
				atKeys = append(atKeys, k)
			}
			log.WithField("access_token_keys", atKeys).Info("session.access_token keys")
		} else {
			log.Info("session.access_token not present or not a map")
		}
	}

	// Extract client_id from multiple possible locations
	clientID := extractClientID(tokenObject)
	if clientID == "" {
		log.Error("client_id not found in any location (session, request, requester, top-level)")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
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

		response["session"].(map[string]any)["access_token"] = tokenMap
		response["session"].(map[string]any)["id_token"] = tokenMap

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(response)
	}

	// Extract granted_scopes from multiple possible locations
	grantedScopes := extractGrantedScopes(tokenObject)
	if grantedScopes == nil {
		// For token refresh, granted_scopes might not be in the expected location
		// Don't fail - just log and treat as regular user pass-through
		log.Warn("granted_scopes not found - treating as regular user token refresh")
	} else if isInternalSystemScoped(grantedScopes) {
		roles := []string{"system_internal"}
		// This is an internal system client
		response["session"].(map[string]any)["access_token"] = map[string]any{"roles": roles}
		response["session"].(map[string]any)["id_token"] = map[string]any{"roles": roles}
		log.Info("enriched token with system_internal roles")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(response)
	}

	// Handle as regular user - session extras from consent should already be present
	// The session.access_token and session.id_token contain the extras set at consent time
	// We pass them through unchanged so Hydra includes them in the refreshed token
	log.Info("passing through session for regular user token")

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(response)

}
