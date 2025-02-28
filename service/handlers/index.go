package handlers

import (
	"context"
	"github.com/antinvestor/service-authentication/utils"
	"html/template"
	"net/http"
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
