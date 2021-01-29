package handlers

import (
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
