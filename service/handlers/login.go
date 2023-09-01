package handlers

import (
	"context"
	"github.com/antinvestor/service-authentication/service/models"
	"github.com/antinvestor/service-authentication/utils"
	papi "github.com/antinvestor/service-profile-api"
	"github.com/pitabwire/frame"
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"

	"github.com/antinvestor/service-authentication/hydra"
)

var loginTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/login.html"))

func ShowLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	service := frame.FromContext(ctx)

	loginchallenge := req.FormValue("login_challenge")

	logger := service.L().WithField("endpoint", "ShowLoginEndpoint").WithField("login_challange", loginchallenge)

	getLogReq, err := hydra.GetLoginRequest(ctx, loginchallenge)
	if err != nil {
		logger.WithError(err).Info(" couldn't get a valid login challenge")
		return err
	}

	logger.Printf(" ShowLoginEndpoint -- %v", getLogReq)

	if getLogReq.Get("skip").Bool() {

		accLogReq, err := hydra.AcceptLoginRequest(ctx, loginchallenge, map[string]interface{}{
			"subject": getLogReq.Get("subject").String(),
		})

		if err != nil {
			return err
		}

		http.Redirect(rw, req, accLogReq.Get("redirect_to").String(), http.StatusSeeOther)

	} else {

		err := loginTmpl.Execute(rw, map[string]interface{}{
			"error":          "",
			"loginChallenge": loginchallenge,
			csrf.TemplateTag: csrf.TemplateField(req),
		})

		return err
	}

	return nil

}

func SubmitLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	service := frame.FromContext(ctx)

	loginChallenge := req.PostForm.Get("login_challenge")
	contact := req.PostForm.Get("contact")
	password := req.PostForm.Get("password")

	log := service.L().
		WithField("endpoint", "SubmitLoginEndpoint").
		WithField("login_challange", loginChallenge).
		WithField("contact", contact)

	log.Info("obtaining login credentials")
	profileObj, login, err := getLoginCredentials(ctx, contact, password)

	log.Info("handling post login credentials")
	err = postLoginChecks(ctx, profileObj, login, err, req)
	if err != nil {
		log.WithError(err).Info(" Could not login user")

		//TODO: In the event the user can't pass tests for long enough remember to use
		//hydra.RejectLoginRequest()

		err := loginTmpl.Execute(rw, map[string]interface{}{
			"error":          "unable to log you in ",
			"loginChallenge": loginChallenge,
			csrf.TemplateTag: csrf.TemplateField(req),
		})

		return err
	}

	remember := req.PostForm.Get("rememberme") == "remember"

	rememberDuration := 3600
	if remember {
		rememberDuration = 0
	}

	log.Info("accepting login request")
	accLogReq, err := hydra.AcceptLoginRequest(
		req.Context(), loginChallenge,
		map[string]interface{}{
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

func postLoginChecks(ctx context.Context, object *papi.ProfileObject,
	login *models.Login, err error, request *http.Request) error {

	if err != nil {
		return err
	}

	return nil
}

func getLoginCredentials(ctx context.Context, contact string, password string) (
	*papi.ProfileObject, *models.Login, error) {

	service := frame.FromContext(ctx)
	profileCli := papi.FromContext(ctx)

	profileObj, err := profileCli.GetProfileByContact(ctx, contact)

	if err != nil {
		return nil, nil, err
	}

	login := models.Login{}
	profileHash := utils.HashStringSecret(profileObj.GetID())

	if err := service.DB(ctx, true).First(&login, "profile_hash = ?", profileHash).Error; err != nil {
		return profileObj, nil, err
	}

	crypt := utils.NewBCrypt()

	err = crypt.Compare(ctx, login.PasswordHash, []byte(password))
	if err != nil {
		return profileObj, &login, err
	}

	return profileObj, &login, nil

}
