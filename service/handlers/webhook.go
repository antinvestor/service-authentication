package handlers

import (
	"encoding/json"
	"github.com/pitabwire/frame"
	"net/http"
)

func TokenEnrichmentEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	service := frame.FromContext(ctx)

	logger := service.L()

	decoder := json.NewDecoder(req.Body)
	var tokenObject map[string]interface{}
	err := decoder.Decode(&tokenObject)
	if err != nil {
		logger.WithError(err).Error("could not decode request body")
		return err
	}

	logger.Info("received a request to update id token")
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
