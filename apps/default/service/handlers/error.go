package handlers

import (
	"github.com/gorilla/csrf"
	"html/template"
	"net/http"
)

var errorTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/error.html"))

func ErrorEndpoint(rw http.ResponseWriter, req *http.Request) error {

	errorTitle := req.FormValue("error")
	errorDescription := req.FormValue("error_description")

	payload := initTemplatePayload(req.Context())
	payload["errorTitle"] = errorTitle
	payload["errorDescription"] = errorDescription
	payload[csrf.TemplateTag] = csrf.TemplateField(req)

	err := errorTmpl.Execute(rw, payload)

	return err
}
