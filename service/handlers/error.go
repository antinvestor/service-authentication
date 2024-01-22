package handlers

import (
	"html/template"
	"net/http"
)

var errorTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/error.html"))

func ErrorEndpoint(rw http.ResponseWriter, req *http.Request) error {

	errorTitle := req.FormValue("error")
	errorDescription := req.FormValue("error_description")

	err := errorTmpl.Execute(rw, map[string]any{
		"errorTitle":       errorTitle,
		"errorDescription": errorDescription,
	})

	return err
}
