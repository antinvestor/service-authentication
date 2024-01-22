package handlers

import (
	"encoding/json"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/antinvestor/service-authentication/service/models"
	"github.com/pitabwire/frame"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"log"
	"net/http"
	"strings"
)

func TokenEnrichmentEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	service := frame.FromContext(ctx)
	partitionAPI := partitionv1.FromContext(ctx)

	logger := service.L()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		logger.WithError(err).Error("could not read request body")
		return err
	}

	logger.WithField("token_data", string(body)).Info("received a request to update id token")

	var tokenObject map[string]interface{}
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
	if ok {

		session, ok1 := sessionObject.(map[string]any)
		if ok1 {

			idTokenObject, ok2 := session["id_token"]
			if ok2 {

				idToken, ok3 := idTokenObject.(map[string]any)
				if ok3 {

					clientID := session["client_id"].(string)
					profileID := idToken["subject"].(string)
					var roles []string
					entityName := ""

					if clientID == profileID {

						var apiKeyModel models.APIKey
						err = service.DB(ctx, true).Find(&apiKeyModel, "key = ? ", clientID).Error
						if err != nil {
							return err
						}

						profileID = apiKeyModel.ProfileID
						entityName = apiKeyModel.Name
						roles = append(roles, "system_product")

					} else {
						roles = append(roles, "user")
					}

					access, err := partitionAPI.GetAccessByClientIdProfileId(ctx, clientID, profileID)
					if err != nil {
						st, ok := status.FromError(err)
						if !ok || st.Code() != codes.NotFound {
							access, err = partitionAPI.CreateAccessByClientID(ctx, clientID, profileID)
						}

						if err != nil {
							log.Printf(" ShowConsentEndpoint -- there was an error getting access %+v", err)
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
						"name":            entityName,
					}

					response["session"]["access_token"] = tokenMap
					response["session"]["id_token"] = tokenMap

				}
			}
		}

	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(response)
}
