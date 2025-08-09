package handlers

import (
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"
)

var forgotTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/forgot.html"))

func (h *AuthServer) ForgotEndpoint(rw http.ResponseWriter, req *http.Request) error {

	payload := initTemplatePayload(req.Context())
	payload["error"] = ""
	payload[csrf.TemplateTag] = csrf.TemplateField(req)

	err := forgotTmpl.Execute(rw, payload)

	// if req.Method == "POST" {}

	return err
}
