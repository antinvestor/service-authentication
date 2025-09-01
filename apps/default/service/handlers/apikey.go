package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/pitabwire/frame"
)

const constApiKeyIDPrefix = "api_key"

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

func (h *AuthServer) CreateAPIKeyEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	claims := frame.ClaimsFromContext(ctx)
	if claims == nil {
		return errors.New("no credentials detected")
	}

	apiKeySecretLength := 32

	decoder := json.NewDecoder(req.Body)
	var akey apiKey
	err := decoder.Decode(&akey)
	if err != nil {
		h.service.Log(ctx).WithError(err).Error("could not decode request body")
		return err
	}

	apiKeySecret := utils.GenerateRandomStringEfficient(apiKeySecretLength)

	jwtServerURL := h.config.GetOauth2ServiceAdminURI()

	apiKeyID := constApiKeyIDPrefix + utils.GenerateRandomStringEfficient(32)

	jwtClient, err := h.service.RegisterForJwtWithParams(ctx,
		jwtServerURL, akey.Name, apiKeyID, apiKeySecret,
		akey.Scope, akey.Audience, akey.Metadata)
	if err != nil {
		h.service.Log(ctx).WithError(err).Error("could not register jwt params")
		return err
	}

	jwtClientID := jwtClient["client_id"].(string)
	subject, _ := claims.GetSubject()
	apiky := models.APIKey{
		Name:      akey.Name,
		ProfileID: subject,
		Key:       apiKeyID,
		Hash:      apiKeySecret,
		Scope:     akey.Scope,
	}
	apiky.GenID(ctx)

	audBytes, err := json.Marshal(akey.Audience)
	if err != nil {
		h.service.Log(ctx).WithError(err).Error("could not marshal audience")
		return err
	}

	apiky.Audience = string(audBytes)

	apiky.Metadata = map[string]any{}

	for k,v := range akey.Metadata{
		apiky.Metadata[k] = v
	}

	err = h.apiKeyRepo.Save(ctx, &apiky)
	if err != nil {
		h.service.Log(ctx).WithError(err).Error("could create api key in database")
		return err
	}

	akey.ID = apiky.ID
	akey.Key = jwtClientID
	akey.KeySecret = apiKeySecret

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusCreated)
	return json.NewEncoder(rw).Encode(akey)
}

func (h *AuthServer) ListAPIKeyEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	claims := frame.ClaimsFromContext(ctx)

	if claims == nil {
		return errors.New("no credentials detected")
	}

	subject, _ := claims.GetSubject()

	apiKeyList, err := h.apiKeyRepo.GetByProfileID(ctx, subject)
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
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(apiObjects)
}

func (h *AuthServer) GetAPIKeyEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	claims := frame.ClaimsFromContext(ctx)
	if claims == nil {
		return errors.New("no credentials detected")
	}

	// Use native Go SDK path variable extraction
	apiKeyID := req.PathValue("ApiKeyId")

	subject, _ := claims.GetSubject()
	apiKeyModel, err := h.apiKeyRepo.GetByIDAndProfile(ctx, apiKeyID, subject)
	if err != nil {
		if frame.ErrorIsNoRows(err) {
			rw.WriteHeader(http.StatusNotFound)
			return nil
		}

		return err
	}

	// Return the API key information (without sensitive data)
	miniApiKey := apiKey{
		ID:       apiKeyModel.ID,
		Name:     apiKeyModel.Name,
		Scope:    apiKeyModel.Scope,
		Audience: []string{}, // Parse from apiKeyModel.Audience if needed
		Metadata: make(map[string]string),
	}

	// Convert metadata from frame.JSONMap to map[string]string
	for key, value := range apiKeyModel.Metadata {
		if strValue, ok := value.(string); ok {
			miniApiKey.Metadata[key] = strValue
		}
	}

	// Parse audience if it's stored as JSON
	if apiKeyModel.Audience != "" {
		var audience []string
		err = json.Unmarshal([]byte(apiKeyModel.Audience), &audience)
		if err == nil {
			miniApiKey.Audience = audience
		}
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(miniApiKey)
}

func (h *AuthServer) DeleteAPIKeyEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	claims := frame.ClaimsFromContext(ctx)
	if claims == nil {
		return errors.New("no credentials detected")
	}

	// Use native Go SDK path variable extraction
	apiKeyID := req.PathValue("ApiKeyId")

	subject, _ := claims.GetSubject()
	apiKeyModel, err := h.apiKeyRepo.GetByIDAndProfile(ctx, apiKeyID, subject)
	if err != nil {
		if frame.ErrorIsNoRows(err) {
			rw.WriteHeader(http.StatusNotFound)
			return nil
		}
		return err
	}

	jwtServerURL := h.config.GetOauth2ServiceAdminURI()

	err = h.service.UnRegisterForJwt(ctx, jwtServerURL, apiKeyModel.Key)
	if err != nil {
		return err
	}

	err = h.apiKeyRepo.Delete(ctx, apiKeyID, subject)
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusAccepted)
	return nil
}
