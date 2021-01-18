package handlers

import (
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"
)

var setPasswordTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/set_password.html"))

func SetPasswordEndpoint(rw http.ResponseWriter, req *http.Request) error {

	err := setPasswordTmpl.Execute(rw, map[string]interface{}{
		"error":          "",
		csrf.TemplateTag: csrf.TemplateField(req),
	})

	return err
}
