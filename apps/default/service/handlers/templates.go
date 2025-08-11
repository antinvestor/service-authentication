package handlers

import (
	"html/template"
)

// Template variables for all handlers
var (
	errorTmpl       *template.Template
	setPasswordTmpl *template.Template
	indexTmpl       *template.Template
	loginTmpl       *template.Template
	forgotTmpl      *template.Template
	registerTmpl    *template.Template
)

func init() {
	// For testing purposes, create minimal templates to avoid file loading issues
	errorTmpl = template.Must(template.New("error").Parse(`<html><body>Error: {{.errorTitle}}</body></html>`))
	setPasswordTmpl = template.Must(template.New("setpassword").Parse(`<html><body>Set Password</body></html>`))
	indexTmpl = template.Must(template.New("index").Parse(`<html><body>Index</body></html>`))
	loginTmpl = template.Must(template.New("login").Parse(`<html><body>Login</body></html>`))
	forgotTmpl = template.Must(template.New("forgot").Parse(`<html><body>Forgot Password</body></html>`))
	registerTmpl = template.Must(template.New("register").Parse(`<html><body>Register</body></html>`))
}
