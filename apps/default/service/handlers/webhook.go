package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/pitabwire/frame/client"
	"github.com/pitabwire/frame/security/openid"
	"github.com/pitabwire/util"
)

// extractGrantedScopes efficiently extracts granted_scopes from multiple possible locations in the webhook payload
func extractGrantedScopes(tokenObject map[string]any) []any {
	var scopes []any
	var ok bool
	if scopes, ok = tokenObject["granted_scopes"].([]any); ok {
		return scopes
	}

	request, ok := tokenObject["request"].(map[string]any)
	if ok {
		if scopes, ok = request["granted_scopes"].([]any); ok {
			return scopes
		}
	}

	if request, ok = tokenObject["requester"].(map[string]any); ok {
		if scopes, ok = request["granted_scopes"].([]any); ok {
			return scopes
		}
	}

	return nil
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
	tokenType := req.PathValue("tokenType")

	logger := util.Log(ctx)

	body, err := io.ReadAll(req.Body)
	if err != nil {
		logger.WithError(err).Error("could not read request body")
		return err
	}

	logger = logger.WithField("tokenType", tokenType).WithField("token_data", string(body))
	logger.Info("received a request to update id token")

	var tokenObject map[string]any
	err = json.Unmarshal(body, &tokenObject)
	if err != nil {
		logger.WithError(err).Error("could not unmarshal request body")
		return err
	}

	response := tokenObject

	sessionData, ok := tokenObject["session"].(map[string]any)
	if !ok {
		sessionData, ok = tokenObject["client"].(map[string]any)
		if !ok {
			logger.Error("no session or client data found")
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusBadRequest)
			return json.NewEncoder(rw).Encode(map[string]string{"error": "client/session data not found"})
		}
	}

	clientID, ok := sessionData["client_id"].(string)
	if !ok {
		logger.Error("client_id not found or invalid")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(rw).Encode(map[string]string{"error": "client_id not found"})
	}

	if strings.HasPrefix(clientID, constApiKeyIDPrefix) {

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
		logger.Info("granted_scopes not found in any location (top-level, requester, or request)")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(rw).Encode(map[string]string{"error": "granted_scopes not found"})
	}

	if slices.Contains(grantedScopes, openid.ConstSystemScopeInternal) {

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
