package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/antinvestor/service-authentication/service/models"
	"github.com/gorilla/mux"
	"github.com/pitabwire/frame"
	"io"
	"net/http"
	"strings"
)

// GetOauth2ClientById obtains a client id
func GetOauth2ClientById(ctx context.Context,
	oauth2ServiceAdminHost string, clientID string) (int, []byte, error) {

	service := frame.FromContext(ctx)

	oauth2AdminURI := fmt.Sprintf("%s%s/%s", oauth2ServiceAdminHost, "/admin/clients", clientID)

	resultStatus, resultBody, err := service.InvokeRestService(ctx, http.MethodGet, oauth2AdminURI, nil, nil)
	if err != nil {
		return 0, nil, err
	}
	return resultStatus, resultBody, err
}

func TokenEnrichmentEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	service := frame.FromContext(ctx)

	params := mux.Vars(req)
	tokenType := params["tokenType"]

	logger := service.L()

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
		logger.WithError(err).Error("could not decode request body")
		return err
	}

	response := map[string]map[string]map[string]string{
		"session": {
			"access_token": {
				"roles": "unknown",
			},
			"id_token": {
				"roles": "unknown",
			},
		},
	}

	sessionObject, ok := tokenObject["session"]
	if !ok {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(response)
	}

	session, ok1 := sessionObject.(map[string]any)
	if !ok1 {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(response)
	}

	clientID := session["client_id"].(string)
	isSystemToken := false
	var roles []string
	entityName := ""

	oauth2Config, ok := service.Config().(frame.ConfigurationOAUTH2)
	if ok {
		oauth2ServiceAdminHost := oauth2Config.GetOauth2ServiceAdminURI()

		_, cBody, err0 := GetOauth2ClientById(ctx, oauth2ServiceAdminHost, clientID)
		if err0 != nil {
			return err0
		}

		var clientObject map[string]any
		err = json.Unmarshal(cBody, &clientObject)
		if err != nil {
			logger.WithError(err).Error("could not decode client object")
			return err
		}
		entityName = clientObject["client_name"].(string)

		grantTypes, ok0 := clientObject["grant_types"].([]any)
		if ok0 {

			if len(grantTypes) == 1 {
				grantType, ok6 := grantTypes[0].(string)
				if ok6 && grantType == "client_credentials" {
					isSystemToken = true
				}
			}
		}
	}

	if !isSystemToken {

		// For end users only add roles and service names
		roles = append(roles, "user")

		tokenMap := map[string]string{
			"roles":        strings.Join(roles, ","),
			"service_name": entityName,
		}

		response["session"]["access_token"] = tokenMap
		response["session"]["id_token"] = tokenMap

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(response)

	}

	var apiKeyModel models.APIKey
	err = service.DB(ctx, true).Find(&apiKeyModel, "key = ? ", clientID).Error
	if err != nil {

		logger.WithError(err).Info("could not get api key for client id")

		if !frame.DBErrorIsRecordNotFound(err) {
			return err
		}

		// These represent the core services that work generally on all entities
		roles = append(roles, "system_internal")

		tokenMap := map[string]string{
			"roles":        strings.Join(roles, ","),
			"service_name": entityName,
		}

		response["session"]["access_token"] = tokenMap
		response["session"]["id_token"] = tokenMap

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(response)

	}

	// These are mostly external services with limited tenancy
	roles = append(roles, "system_external")

	tokenMap := map[string]string{
		"tenant_id":    apiKeyModel.TenantID,
		"partition_id": apiKeyModel.PartitionID,
		"roles":        strings.Join(roles, ","),
		"service_name": entityName,
	}

	response["session"]["access_token"] = tokenMap
	response["session"]["id_token"] = tokenMap

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(response)
}
