package handlers

import (
	"antinvestor.com/service/auth/models"
	"antinvestor.com/service/auth/service/profile"
	"antinvestor.com/service/auth/utils"
	"context"
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/opentracing/opentracing-go"

	"antinvestor.com/service/auth/hydra"
)

var loginTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/login.html"))

func ShowLoginEndpoint(env *utils.Env, rw http.ResponseWriter, req *http.Request) error {

	span, ctx := opentracing.StartSpanFromContext(req.Context(), "SubmitLoginEndpoint")
	defer span.Finish()

	loginchallenge := req.FormValue("login_challenge")

	getLogReq, err := hydra.GetLoginRequest(ctx, loginchallenge)
	if err != nil {
		return err
	}

	if getLogReq.Get("skip").Bool() {

		accLogReq, err := hydra.AcceptLoginRequest(ctx, loginchallenge, map[string]interface{}{
			"subject": getLogReq.Get("subject").String(),
		})

		if err != nil {
			return err
		}

		http.Redirect(rw, req, accLogReq.Get("redirect_to").String(), http.StatusSeeOther)

	} else {

		env.Logger.Infof("CSRF DATA : %v", req.Context().Value("gorilla.csrf.Form"))

		err := loginTmpl.Execute(rw, map[string]interface{}{
			"error":          "",
			"loginChallenge": loginchallenge,
			csrf.TemplateTag: csrf.TemplateField(req),
		})

		return err
	}

	return nil

}

func SubmitLoginEndpoint(env *utils.Env, rw http.ResponseWriter, req *http.Request) error {

	span, ctx := opentracing.StartSpanFromContext(req.Context(), "SubmitLoginEndpoint")
	defer span.Finish()

	loginchallenge := req.PostForm.Get("login_challenge")
	contact := req.PostForm.Get("contact")
	password := req.PostForm.Get("password")

	profileObj, login, err := getLoginCredentials(env, ctx, contact, password)
	err = postLoginChecks(env, ctx, profileObj, login, err, req)
	if err != nil {
		env.Logger.Info("Could not login user because :%v", err)

		//TODO: In the event the user can't pass tests for long enough remember to use
		//hydra.RejectLoginRequest()

		err := loginTmpl.Execute(rw, map[string]interface{}{
			"error":          "unable to log you in ",
			"loginChallenge": loginchallenge,
			csrf.TemplateTag: csrf.TemplateField(req),
		})

		return err
	}

	remember := req.PostForm.Get("rememberme") == "remember"

	rememberDuration := 3600
	if remember {
		rememberDuration = 0
	}

	accLogReq, err := hydra.AcceptLoginRequest(req.Context(), loginchallenge, map[string]interface{}{
		"subject":      profileObj.GetID(),
		"remember":     remember,
		"remember_for": rememberDuration,
	})

	if err != nil {
		return err
	}

	http.Redirect(rw, req, accLogReq.Get("redirect_to").String(), http.StatusSeeOther)

	return nil
}

func postLoginChecks(env *utils.Env, ctx context.Context, object *profile.ProfileObject, login *models.Login, err error, request *http.Request) error {

	if err != nil{
		return err
	}

	return nil
}

func getLoginCredentials(env *utils.Env, ctx context.Context, contact string, password string) (*profile.ProfileObject, *models.Login, error) {

	profileObj, err := getProfileByContact(env, ctx, contact)
	if err != nil {
		return nil, nil, err
	}

	login := models.Login{}
	profileHash := utils.HashStringSecret(profileObj.GetID())

	if err := env.GetRDb(ctx).First(login, "ProfileHash = ?", profileHash).Error; err != nil {
		return profileObj, nil, err
	}

	crypt := utils.NewBCrypt()
	passwordHash, err := crypt.Hash(ctx, []byte(password))
	if err != nil {
		return profileObj, &login, err
	}

	err = crypt.Compare(ctx, []byte(login.PasswordHash), passwordHash)
	if err != nil {
		return profileObj, &login, err
	}

	return profileObj, &login, nil

}
