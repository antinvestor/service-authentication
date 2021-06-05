package handlers

import (
	"context"
	"github.com/antinvestor/service-authentication/service/models"
	"github.com/antinvestor/service-authentication/utils"
	papi "github.com/antinvestor/service-profile-api"
	"github.com/pitabwire/frame"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/csrf"

	"github.com/antinvestor/service-authentication/hydra"
)

var loginTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/login.html"))

func ShowLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	loginchallenge := req.FormValue("login_challenge")

	getLogReq, err := hydra.GetLoginRequest(ctx, loginchallenge)
	if err != nil {
		log.Printf(" ShowLoginEndpoint -- couldn't get a valid login challenge %s : %v", loginchallenge, err)
		return err
	}

	log.Printf(" ShowLoginEndpoint -- %v", getLogReq)

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

	loginchallenge := req.PostForm.Get("login_challenge")
	contact := req.PostForm.Get("contact")
	password := req.PostForm.Get("password")

	profileObj, login, err := getLoginCredentials(ctx, contact, password)

	err = postLoginChecks(ctx, profileObj, login, err, req)
	if err != nil {
		log.Printf(" SubmitLoginEndpoint -- Could not login user because :%v", err)

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

	accLogReq, err := hydra.AcceptLoginRequest(
		req.Context(), loginchallenge,
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

func postLoginChecks(ctx context.Context, object *papi.ProfileObject, login *models.Login, err error, request *http.Request) error {

	if err != nil {
		return err
	}

	return nil
}

func getLoginCredentials(ctx context.Context, contact string, password string) (*papi.ProfileObject, *models.Login, error) {

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
