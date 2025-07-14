package handlers

import (
	"context"
	"html/template"
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/utils"
)

var indexTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/index.html"))

func initTemplatePayload(ctx context.Context) map[string]any {
	payload := make(map[string]any)

	deviceId := utils.DeviceIDFromContext(ctx)
	payload["DeviceID"] = deviceId

	return payload
}

func IndexEndpoint(rw http.ResponseWriter, req *http.Request) error {
	if req.Referer() != "" {
		http.Redirect(rw, req, req.Referer(), http.StatusSeeOther)
	}

	err := indexTmpl.Execute(rw, initTemplatePayload(req.Context()))

	return err
}
