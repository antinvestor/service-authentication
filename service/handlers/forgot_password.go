package handlers

import (
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"
)

var forgotTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/forgot.html"))

func ForgotEndpoint(rw http.ResponseWriter, req *http.Request) error {

	err := forgotTmpl.Execute(rw, map[string]interface{}{
		"error":          "",
		csrf.TemplateTag: csrf.TemplateField(req),
	})

	if req.Method == "POST" {

	}

	return err
}
