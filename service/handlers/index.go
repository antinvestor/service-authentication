package handlers

import (
	"github.com/antinvestor/service-authentication/config"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"html/template"
	"net/http"

	"github.com/go-errors/errors"
)

var indexTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/index.html"))

func IndexEndpoint(rw http.ResponseWriter, req *http.Request) error {

	if req.Referer() != "" {
		http.Redirect(rw, req, req.Referer(), http.StatusSeeOther)
	}

	err := indexTmpl.Execute(rw, map[string]interface{}{})

	return errors.Wrap(err, 1)
}

func getLocalizer(req *http.Request) *i18n.Localizer {

	bundle, _ := req.Context().Value(config.CtxBundleKey).(*i18n.Bundle)

	lang := req.FormValue("lang")
	accept := req.Header.Get("Accept-Language")
	return i18n.NewLocalizer(bundle, lang, accept)

}
