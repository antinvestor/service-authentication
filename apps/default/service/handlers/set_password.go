package handlers

import (
	"net/http"

	"github.com/gorilla/csrf"
)

func (h *AuthServer) SetPasswordEndpoint(rw http.ResponseWriter, req *http.Request) error {

	payload := initTemplatePayload(req.Context())
	payload["error"] = ""
	payload[csrf.TemplateTag] = csrf.TemplateField(req)

	err := setPasswordTmpl.Execute(rw, payload)

	return err
}
