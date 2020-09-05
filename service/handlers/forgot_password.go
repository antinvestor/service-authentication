package handlers

import (
	"github.com/antinvestor/service-authentication/utils"
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/opentracing/opentracing-go"
)

var forgotTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/forgot.html"))

func ForgotEndpoint(env *utils.Env, rw http.ResponseWriter, req *http.Request) error {

	span, _ := opentracing.StartSpanFromContext(req.Context(), "ForgotEndpoint")
	defer span.Finish()

	err := forgotTmpl.Execute(rw, map[string]interface{}{
		"error":          "",
		csrf.TemplateTag: csrf.TemplateField(req),
	})

	if req.Method == "POST" {

	}

	return err
}
