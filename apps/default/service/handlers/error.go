package handlers

import (
	"net/http"

	"github.com/gorilla/csrf"
)

func (h *AuthServer) ErrorEndpoint(rw http.ResponseWriter, req *http.Request) error {

	errorTitle := req.FormValue("error")
	errorDescription := req.FormValue("error_description")

	payload := initTemplatePayload(req.Context())
	payload["errorTitle"] = errorTitle
	payload["errorDescription"] = errorDescription
	payload[csrf.TemplateTag] = csrf.TemplateField(req)

	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusInternalServerError)
	err := errorTmpl.Execute(rw, payload)

	return err
}
