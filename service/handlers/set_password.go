package handlers

import (
	"github.com/antinvestor/service-authentication/utils"
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/opentracing/opentracing-go"
)

var setPasswordTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/set_password.html"))

func SetPasswordEndpoint(env *utils.Env, rw http.ResponseWriter, req *http.Request) error {

	span, _ := opentracing.StartSpanFromContext(req.Context(), "SetPasswordEndpoint")
	defer span.Finish()

	err := setPasswordTmpl.Execute(rw, map[string]interface{}{
		"error":          "",
		csrf.TemplateTag: csrf.TemplateField(req),
	})

	return err
}
