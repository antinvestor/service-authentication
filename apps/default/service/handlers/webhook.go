package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pitabwire/frame"
)

// GetOauth2ClientById obtains a client id
func GetOauth2ClientById(ctx context.Context,
	oauth2ServiceAdminHost string, clientID string) (int, []byte, error) {

	service := frame.Svc(ctx)

	oauth2AdminURI := fmt.Sprintf("%s%s/%s", oauth2ServiceAdminHost, "/admin/clients", clientID)

	resultStatus, resultBody, err := service.InvokeRestService(ctx, http.MethodGet, oauth2AdminURI, nil, nil)
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

	logger := h.service.Log(ctx)

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

	// sessionData, ok := tokenObject["session"].(map[string]any)
	// if !ok {
	// 	logger.Error("session data not found or invalid")
	// 	rw.Header().Set("Content-Type", "application/json")
	// 	rw.WriteHeader(http.StatusBadRequest)
	// 	return json.NewEncoder(rw).Encode(map[string]string{"error": "session data not found"})
	// }

	clientData, ok := tokenObject["client"].(map[string]any)
	if !ok {
		logger.Error("client data not found or invalid")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(rw).Encode(map[string]string{"error": "client data not found"})
	}

	clientID, ok := clientData["client_id"].(string)
	if !ok {
		logger.Error("client_id not found or invalid")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(rw).Encode(map[string]string{"error": "client_id not found"})
	}

	// Check if this is an API key client
	apiKeyModel, err := h.apiKeyRepo.GetByKey(ctx, clientID)
	if err != nil {
		h.service.Log(ctx).WithError(err).Error("could not find api key")
		return err
	}

	if apiKeyModel == nil {
		// Not an API key, handle as regular user token

		partitionObj, err := h.partitionCli.GetPartition(ctx, clientID)
		if err != nil {
			logger.WithError(err).Error("could not get partition by profile id")
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusInternalServerError)
			return json.NewEncoder(rw).Encode(map[string]string{"error": "could not get partition"})
		}

		tokenMap := map[string]any{
			"tenant_id":    partitionObj.GetTenantId(),
			"partition_id": partitionObj.GetId(),
			"roles":        []string{"user"},
		}

		response["session"].(map[string]any)["access_token"] = tokenMap
		response["session"].(map[string]any)["id_token"] = tokenMap

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(response)
	}

	// This is an API key client - handle as external service
	roles := []string{"system_external"}

	if apiKeyModel.Scope != "" {
		var scopeList []string
		err := json.Unmarshal([]byte(apiKeyModel.Scope), &scopeList)
		if err == nil {
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
