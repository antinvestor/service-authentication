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
	service := frame.FromContext(ctx)
	claims := frame.ClaimsFromContext(ctx)

	apiKeySecretLength := 32

	decoder := json.NewDecoder(req.Body)
	var akey apiKey
	err := decoder.Decode(&akey)
	if err != nil {
		service.L(ctx).WithError(err).Error("could not decode request body")
		return err
	}

	apiKeySecret := utils.GenerateRandomStringEfficient(apiKeySecretLength)

	cfg := service.Config().(*config.AuthenticationConfig)

	jwtServerURL := cfg.GetOauth2ServiceAdminURI()

	jwtClient, err := service.RegisterForJwtWithParams(ctx,
		jwtServerURL, akey.Name, apiKeySecret,
		akey.Scope, akey.Audience, akey.Metadata)
	if err != nil {
		service.L(ctx).WithError(err).Error("could not register jwt params")
		return err
	}

	jwtClientID := jwtClient["client_id"].(string)
	subject, _ := claims.GetSubject()
	apiky := models.APIKey{
		Name:      akey.Name,
		ProfileID: subject,
		Key:       jwtClientID,
		Hash:      apiKeySecret,
		Scope:     akey.Scope,
	}

	audBytes, err := json.Marshal(akey.Audience)
	if err != nil {
		service.L(ctx).WithError(err).Error("could not marshal audience")
		return err
	}

	apiky.Audience = string(audBytes)

	metadataBytes, err := json.Marshal(akey.Metadata)
	if err != nil {
		service.L(ctx).WithError(err).Error("could not marshal metadata")
		return err
	}
	apiky.Metadata = string(metadataBytes)

	err = service.DB(ctx, true).Create(&apiky).Error
	if err != nil {
		service.L(ctx).WithError(err).Error("could create api key in database")
		return err
	}

	akey.ID = apiky.ID
	akey.Key = jwtClientID
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
	subject, _ := claims.GetSubject()

	err := service.DB(ctx, true).Find(&apiKeyList, "profile_id = ?", subject).Error

	if err != nil {
		return err
	}

	apiObjects := make([]apiKey, len(apiKeyList))
	for i, apiobject := range apiKeyList {
		apiObjects[i] = apiKey{
			ID:    apiobject.ID,
			Name:  apiobject.Name,
			Scope: apiobject.Scope,
		}
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
	subject, _ := claims.GetSubject()
	err := service.DB(ctx, true).Find(&apiKeyModel, "id = ? AND profile_id = ?", apiKeyID, subject).Error
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
	subject, _ := claims.GetSubject()
	err := service.DB(ctx, true).Find(&apiKeyModel, "id = ? AND profile_id = ?", apiKeyID, subject).Error
	if err != nil {
		return err
	}

	cfg := service.Config().(*config.AuthenticationConfig)

	jwtServerURL := cfg.GetOauth2ServiceAdminURI()

	err = service.UnRegisterForJwt(ctx, jwtServerURL, apiKeyModel.Key)
	if err != nil {
		return err
	}

	err = service.DB(ctx, false).Delete(&apiKeyModel, "id = ? AND profile_id = ?", apiKeyID, subject).Error
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusAccepted)
	return nil
}
