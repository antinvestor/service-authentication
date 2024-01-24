package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/antinvestor/service-authentication/service/models"
	"github.com/gorilla/mux"
	"github.com/pitabwire/frame"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	partitionAPI := partitionv1.FromContext(ctx)

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
				"role": "unknown",
			},
			"id_token": {
				"role": "unknown",
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

	idTokenObject, ok2 := session["id_token"]
	if !ok2 {

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(response)
	}

	idToken, ok3 := idTokenObject.(map[string]any)
	if !ok3 {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(response)
	}

	clientID := session["client_id"].(string)
	profileID := idToken["subject"].(string)
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
		logger = logger.WithField("client_object", clientObject)
	}

	logger.Info("*** decision point for request")

	if clientID == profileID || profileID == "" {

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

		profileID = apiKeyModel.ProfileID
		partitionID := apiKeyModel.PartitionID
		roles = append(roles, "system_external")

		var access *partitionv1.AccessObject
		access, err = partitionAPI.GetAccessByPartitionIdProfileId(ctx, partitionID, profileID)
		if err != nil {
			st, ok := status.FromError(err)
			if !ok || st.Code() != codes.NotFound {
				access, err = partitionAPI.CreateAccessByPartitionID(ctx, partitionID, profileID)
			}

			if err != nil {
				logger.WithError(err).
					WithField("partition_id", partitionID).
					WithField("profile_id", profileID).
					Error(" there was an error getting access")
				return err
			}
		}

		partition := access.GetPartition()

		tokenMap := map[string]string{
			"tenant_id":       partition.GetTenantId(),
			"partition_id":    partition.GetId(),
			"partition_state": partition.GetState().String(),
			"access_id":       access.GetAccessId(),
			"access_state":    access.GetState().String(),
			"roles":           strings.Join(roles, ","),
			"service_name":    entityName,
		}

		response["session"]["access_token"] = tokenMap
		response["session"]["id_token"] = tokenMap

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		return json.NewEncoder(rw).Encode(response)

	}

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
