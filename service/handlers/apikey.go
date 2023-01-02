package handlers

import (
	"encoding/json"
	"github.com/antinvestor/service-authentication/service/models"
	"github.com/antinvestor/service-authentication/utils"
	"github.com/pitabwire/frame"
	"net/http"
	"strings"
)

type apiKey struct {
	ID       string
	Name     string
	ClientID string
	Scope    string
}

func CreateApiKeyEndpoint(rw http.ResponseWriter, req *http.Request) error {

	//TODO: secure api key
	ctx := req.Context()
	apiKeyLength := 16
	apiKeySecretLength := 16

	apiKeyClient := req.FormValue("api_key_client")
	apiKeyName := req.FormValue("api_key_name")
	apiKeyScope := req.FormValue("api_key_scope")
	apiKeyAudience := req.FormValue("api_key_audience")
	var apiKeyAudienceList []string
	if apiKeyAudience != "" {
		apiKeyAudienceList = strings.Split(apiKeyAudience, ",")
	}

	apiKeyMetadataJson := req.FormValue("api_key_metadata")
	var metadata map[string]string
	if apiKeyMetadataJson != "" {

		err := json.Unmarshal([]byte(apiKeyMetadataJson), &metadata)
		if err != nil {
			return err
		}
	}

	service := frame.FromContext(ctx)

	apiKeyValue, err := utils.GenerateRandomString(apiKeyLength)
	if err != nil {
		return err
	}
	hashedApiKeyValue := utils.HashStringSecret(apiKeyValue)

	apiKeySecret, err := utils.GenerateRandomString(apiKeySecretLength)
	if err != nil {
		return err
	}

	err = service.RegisterForJwtWithParams(ctx, apiKeyName, apiKeyValue, apiKeySecret, apiKeyScope, apiKeyAudienceList, metadata)
	if err != nil {
		return err
	}

	apiky := models.APIKey{
		Name:     apiKeyName,
		ClientID: apiKeyClient,
		Key:      hashedApiKeyValue,
		Hash:     apiKeySecret,
		Scope:    apiKeyScope,
	}

	err = service.DB(ctx, true).Create(&apiky).Error
	if err != nil {
		return err
	}

	apiObj := apiKey{
		ID:       apiky.ID,
		Name:     apiky.Name,
		ClientID: apiky.ClientID,
		Scope:    apiky.Scope,
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusCreated)
	return json.NewEncoder(rw).Encode(apiObj)
}

func ListApiKeyEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	service := frame.FromContext(ctx)

	clientID := req.FormValue("client_id")

	var apiKeyList []models.APIKey
	err := service.DB(ctx, true).Find(&apiKeyList, "client_id = ?", clientID).Error

	if err != nil {
		return err
	}

	var apiObjects []apiKey
	for _, apiobj := range apiKeyList {

		apiObjects = append(apiObjects, apiKey{
			ID:       apiobj.ID,
			Name:     apiobj.Name,
			ClientID: apiobj.ClientID,
			Scope:    apiobj.Scope,
		})
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusCreated)
	return json.NewEncoder(rw).Encode(apiObjects)
}

func DeleteApiKeyEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	service := frame.FromContext(ctx)

	apiKeyID := req.FormValue("api_key_id")

	var apiKeyModel models.APIKey
	err := service.DB(ctx, true).Find(&apiKeyModel, "id = ?", apiKeyID).Error
	if err != nil {
		return err
	}

	err = service.DB(ctx, false).Delete(&apiKeyModel, "id = ?", apiKeyID).Error
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusAccepted)
	return nil
}
