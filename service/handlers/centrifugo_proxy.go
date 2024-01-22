package handlers

import (
	"encoding/json"
	"github.com/pitabwire/frame"
	"io"
	"net/http"
)

// CentrifugoProxySubscribeEndpoint implementation is based on : https://centrifugal.dev/docs/server/proxy#subscribe-proxy
func CentrifugoProxySubscribeEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	service := frame.FromContext(ctx)

	logger := service.L()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		logger.WithError(err).Error("could not read request body")
		return err
	}

	logger.WithField("subscription_data", string(body)).Info("received a subscription request")

	var subscriptionReq map[string]any
	err = json.Unmarshal(body, &subscriptionReq)
	if err != nil {
		logger.WithError(err).Error("could not decode subscription request")
		return err
	}

	response := map[string]map[string]string{"result": {}}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(response)
}
