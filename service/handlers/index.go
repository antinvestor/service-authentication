package handlers

import (
	"antinvestor.com/service/auth/utils"
	"html/template"
	"net/http"

	"github.com/opentracing/opentracing-go"
)

var indexTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/index.html"))

func IndexEndpoint(env *utils.Env, rw http.ResponseWriter, req *http.Request) error {

	span, _ := opentracing.StartSpanFromContext(req.Context(), "IndexEndpoint")
	defer span.Finish()

	if req.Referer() != "" {
		http.Redirect(rw, req, req.Referer(), http.StatusSeeOther)
	}

	err := indexTmpl.Execute(rw, map[string]interface{}{})

	return err
}
