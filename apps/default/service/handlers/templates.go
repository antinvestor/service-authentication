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
	loginTmpl = template.Must(template.New("login").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        {{if .error}}
            <div class="error">{{.error}}</div>
        {{end}}
        <form method="POST" action="/s/login/post">
            {{.csrfField}}
            <input type="hidden" name="login_challenge" value="{{.loginChallenge}}">
            
            <div class="form-group">
                <label for="contact">Email:</label>
                <input type="email" id="contact" name="contact" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit">Login</button>
        </form>
    </div>
    <style>
        .container { max-width: 400px; margin: 50px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { width: 100%; padding: 10px; background: #007bff; colour: white; border: none; border-radius: 4px; cursor: pointer; }
        .error { colour: red; margin-bottom: 15px; padding: 10px; border: 1px solid red; border-radius: 4px; }
    </style>
</body>
</html>`))
	forgotTmpl = template.Must(template.New("forgot").Parse(`<html><body>Forgot Password</body></html>`))
	registerTmpl = template.Must(template.New("register").Parse(`<html><body>Register</body></html>`))
}
