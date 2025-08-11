package handlers

import (
	"context"
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/utils"
)

func initTemplatePayload(ctx context.Context) map[string]any {
	payload := make(map[string]any)

	deviceId := utils.DeviceIDFromContext(ctx)
	payload["DeviceID"] = deviceId

	return payload
}

func (h *AuthServer) IndexEndpoint(rw http.ResponseWriter, req *http.Request) error {
	if req.Referer() != "" {
		http.Redirect(rw, req, req.Referer(), http.StatusSeeOther)
	}

	err := indexTmpl.Execute(rw, initTemplatePayload(req.Context()))

	return err
}
