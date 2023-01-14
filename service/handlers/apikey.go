package handlers

import (
	"encoding/json"
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/service/models"
	"github.com/antinvestor/service-authentication/utils"
	"github.com/gorilla/mux"
	"github.com/pitabwire/frame"
	"net/http"
)

type apiKey struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	ClientID string            `json:"clientId"`
	Scope    string            `json:"scope"`
	Audience []string          `json:"audience"`
	Metadata map[string]string `json:"metadata"`

	Key       string `json:"apiKey"`
	KeySecret string `json:"apiKeySecret"`
}

func CreateAPIKeyEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	apiKeyLength := 16
	apiKeySecretLength := 16

	decoder := json.NewDecoder(req.Body)
	var akey apiKey
	err := decoder.Decode(&akey)
	if err != nil {
		return err
	}

	service := frame.FromContext(ctx)
	claims := frame.ClaimsFromContext(ctx)

	apiKeyValue, err := utils.GenerateRandomString(apiKeyLength)
	if err != nil {
		return err
	}
	hashedAPIKeyValue := utils.HashStringSecret(apiKeyValue)

	apiKeySecret, err := utils.GenerateRandomString(apiKeySecretLength)
	if err != nil {
		return err
	}

	cfg := service.Config().(*config.AuthenticationConfig)

	jwtServerURL := cfg.GetOauth2ServiceAdminURI()

	err = service.RegisterForJwtWithParams(ctx,
		jwtServerURL, akey.Name, apiKeyValue, apiKeySecret,
		akey.Scope, akey.Audience, akey.Metadata)
	if err != nil {
		return err
	}

	apiky := models.APIKey{
		Name:      akey.Name,
		ClientID:  akey.ClientID,
		ProfileID: claims.ProfileID,
		Key:       hashedAPIKeyValue,
		Hash:      apiKeySecret,
		Scope:     akey.Scope,
	}

	audBytes, err := json.Marshal(akey.Audience)
	if err != nil {
		return err
	}

	apiky.Metadata = string(audBytes)
	metadataBytes, err := json.Marshal(akey.Metadata)
	if err != nil {
		return err
	}
	apiky.Metadata = string(metadataBytes)

	err = service.DB(ctx, true).Create(&apiky).Error
	if err != nil {
		return err
	}

	akey.ID = apiky.ID
	akey.Key = hashedAPIKeyValue
	akey.KeySecret = apiKeySecret

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusCreated)
	return json.NewEncoder(rw).Encode(akey)
}

func ListAPIKeyEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	service := frame.FromContext(ctx)
	claims := frame.ClaimsFromContext(ctx)

	var apiKeyList []models.APIKey
	err := service.DB(ctx, true).Find(&apiKeyList, "profile_id = ?", claims.ProfileID).Error

	if err != nil {
		return err
	}

	apiObjects := []apiKey{}
	for _, apiobj := range apiKeyList {

		aky := apiKey{
			ID:       apiobj.ID,
			Name:     apiobj.Name,
			ClientID: apiobj.ClientID,
			Scope:    apiobj.Scope,
		}

		apiObjects = append(apiObjects, aky)
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusCreated)
	return json.NewEncoder(rw).Encode(apiObjects)
}

func GetAPIKeyEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	service := frame.FromContext(ctx)
	claims := frame.ClaimsFromContext(ctx)

	params := mux.Vars(req)
	apiKeyID := params["ApiKeyId"]

	var apiKeyModel models.APIKey
	err := service.DB(ctx, true).Find(&apiKeyModel, "id = ? AND profile_id = ?", apiKeyID, claims.ProfileID).Error
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusAccepted)
	return nil
}

func DeleteAPIKeyEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	service := frame.FromContext(ctx)
	claims := frame.ClaimsFromContext(ctx)

	params := mux.Vars(req)
	apiKeyID := params["ApiKeyId"]

	var apiKeyModel models.APIKey
	err := service.DB(ctx, true).Find(&apiKeyModel, "id = ? AND profile_id = ?", apiKeyID, claims.ProfileID).Error
	if err != nil {
		return err
	}

	err = service.DB(ctx, false).Delete(&apiKeyModel, "id = ? AND profile_id = ?", apiKeyID, claims.ProfileID).Error
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusAccepted)
	return nil
}
