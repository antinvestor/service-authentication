package handlers

import (
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"
)

var setPasswordTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/set_password.html"))

func SetPasswordEndpoint(rw http.ResponseWriter, req *http.Request) error {

	payload := initTemplatePayload(req.Context())
	payload["error"] = ""
	payload[csrf.TemplateTag] = csrf.TemplateField(req)

	err := setPasswordTmpl.Execute(rw, payload)

	return err
}
