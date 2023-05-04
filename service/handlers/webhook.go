package handlers

import (
	"encoding/json"
	"github.com/pitabwire/frame"
	"io"
	"net/http"
)

func TokenEnrichmentEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	service := frame.FromContext(ctx)

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
				"role": "user",
			},
			"id_token": {
				"role": "user",
			},
		},
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(response)
}
