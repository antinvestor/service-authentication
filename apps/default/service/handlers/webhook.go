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

// extractGrantedScopes extracts and normalizes granted_scopes to []string
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

// TokenEnrichmentEndpoint handles token enrichment requests
func (h *AuthServer) TokenEnrichmentEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	// Use native Go SDK path variable extraction
	// tokenType := req.PathValue("tokenType")

	body, err := io.ReadAll(req.Body)
	if err != nil {
		util.Log(ctx).WithError(err).Error("could not read request body")
		return err
	}

	var tokenObject map[string]any
	err = json.Unmarshal(body, &tokenObject)
	if err != nil {
		util.Log(ctx).WithError(err).Error("could not unmarshal request body")
		return err
	}

	response := tokenObject

	sessionData, ok := tokenObject["session"].(map[string]any)
	if !ok {
		sessionData, ok = tokenObject["client"].(map[string]any)
		if !ok {
			util.Log(ctx).Error("no session or client data found")
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusBadRequest)
			return json.NewEncoder(rw).Encode(map[string]string{"error": "client/session data not found"})
		}
	}

	clientID, ok := sessionData["client_id"].(string)
	if !ok {
		util.Log(ctx).Error("client_id not found or invalid")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(rw).Encode(map[string]string{"error": "client_id not found"})
	}

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

	// Extract granted_scopes from multiple possible locations efficiently
	grantedScopes := extractGrantedScopes(tokenObject)
	if grantedScopes == nil {
		util.Log(ctx).Error("granted_scopes not found in any location (top-level, requester, or request)")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(rw).Encode(map[string]string{"error": "granted_scopes not found"})
	}

	if isInternalSystemScoped(grantedScopes) {

		roles := []string{"system_internal"}
		// This is an internal system client
		response["session"].(map[string]any)["access_token"] = map[string]any{"roles": roles}
		response["session"].(map[string]any)["id_token"] = map[string]any{"roles": roles}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(response)

	}

	// Handle as regular user token should already have everything
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(response)

}
