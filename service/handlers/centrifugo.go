package handlers

import (
	"encoding/json"
	"fmt"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/gorilla/mux"
	"github.com/pitabwire/frame"
	"io"
	"net/http"
	"strings"
)

// CentrifugoProxyEndpoint implementation is based on : https://centrifugal.dev/docs/server/proxy#subscribe-proxy
func CentrifugoProxyEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	service := frame.FromContext(ctx)
	profileCli := profilev1.FromContext(ctx)
	claims := frame.ClaimsFromContext(ctx)

	params := mux.Vars(req)

	logger := service.L().
		WithField("path_var", params)

	body, err := io.ReadAll(req.Body)
	if err != nil {
		logger.WithError(err).Error("could not read request body")
		return err
	}

	logger.WithField("proxy_data", string(body)).Info("received a proxy action")

	var subscriptionReq map[string]any
	err = json.Unmarshal(body, &subscriptionReq)
	if err != nil {
		logger.WithError(err).Error("could not decode subscription request")
		return err
	}

	subject, _ := claims.GetSubject()
	result := map[string]any{
		"user": subject,
	}

	if params["ProxyAction"] == "connect" {

		relationships, err := profileCli.ListRelationships(ctx, "", 0)

		if err != nil {
			logger.WithError(err).Error("could not list relationships")
		}

		var channelSlice []string

		for relationship := range relationships {

			parentEntry := relationship.GetParentEntry()
			childEntry := relationship.GetChildEntry()

			if parentEntry.GetObjectName() == subject && strings.ToLower(childEntry.GetObjectName()) != "profile" {

				channel := fmt.Sprintf("%s:%s", childEntry.GetObjectName(), childEntry.GetObjectId())
				channelSlice = append(channelSlice, channel)

			}
		}

		result["channels"] = channelSlice

	}

	response := map[string]map[string]any{"result": result}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(response)
}
