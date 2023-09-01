package handlers

import (
	"context"
	"fmt"
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/service/models"
	"github.com/antinvestor/service-authentication/utils"
	papi "github.com/antinvestor/service-profile-api"
	"github.com/pitabwire/frame"
	"html/template"
	"net/http"
	"time"

	"github.com/gorilla/csrf"

	"github.com/antinvestor/service-authentication/hydra"
)

var loginTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/login.html"))

func ShowLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	service := frame.FromContext(ctx)

	cfg, ok := service.Config().(*config.AuthenticationConfig)
	if !ok {
		return fmt.Errorf("could not convert configuration correctly")
	}

	logger := service.L().WithField("endpoint", "ShowLoginEndpoint")

	defaultHydra := hydra.NewDefaultHydra(cfg.GetOauth2ServiceAdminURI())

	loginChallenge, err := hydra.GetLoginChallengeID(req)
	if err != nil {
		logger.WithError(err).Info(" couldn't get a valid login challenge")
		return err
	}

	getLogReq, err := defaultHydra.GetLoginRequest(ctx, loginChallenge)
	if err != nil {
		logger = logger.WithField("login_challange", loginChallenge)

		logger.WithError(err).Info(" couldn't get a valid login challenge")
		return err
	}

	if getLogReq.Skip {
		redirectUrl := ""
		params := hydra.AcceptLoginRequestParams{LoginChallenge: loginChallenge, IdentityID: getLogReq.GetSubject()}
		redirectUrl, err = defaultHydra.AcceptLoginRequest(ctx, params)

		if err != nil {
			return err
		}

		http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)

	} else {

		err = loginTmpl.Execute(rw, map[string]interface{}{
			"error":          "",
			"loginChallenge": loginChallenge,
			csrf.TemplateTag: csrf.TemplateField(req),
		})

		return err
	}

	return nil

}

func SubmitLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	service := frame.FromContext(ctx)

	cfg, ok := service.Config().(*config.AuthenticationConfig)
	if !ok {
		return fmt.Errorf("could not convert configuration correctly")
	}

	logger := service.L().WithField("endpoint", "ShowLoginEndpoint")

	defaultHydra := hydra.NewDefaultHydra(cfg.GetOauth2ServiceAdminURI())

	loginChallenge, err := hydra.GetLoginChallengeID(req)
	if err != nil {
		logger.WithError(err).Info(" couldn't get a valid login challenge")
		return err
	}

	contact := req.PostForm.Get("contact")
	password := req.PostForm.Get("password")

	profileObj, login, err := getLoginCredentials(ctx, contact, password)

	err = postLoginChecks(ctx, profileObj, login, err, req)
	if err != nil {
		log := service.L().
			WithField("endpoint", "SubmitLoginEndpoint").
			WithField("contact", contact)

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

	rememberDuration := int64(7 * 24 * time.Hour / time.Second)
	if remember {
		rememberDuration = 0
	}

	params := hydra.AcceptLoginRequestParams{LoginChallenge: loginChallenge, IdentityID: profileObj.GetID(), Remember: &remember, RememberDuration: &rememberDuration}

	redirectUrl, err := defaultHydra.AcceptLoginRequest(
		req.Context(), params)

	if err != nil {
		return err
	}

	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)

	return nil
}

func postLoginChecks(ctx context.Context, object *papi.ProfileObject,
	login *models.Login, err error, request *http.Request) error {

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

	if err = service.DB(ctx, true).First(&login, "profile_hash = ?", profileHash).Error; err != nil {
		return profileObj, nil, err
	}

	crypt := utils.NewBCrypt()

	err = crypt.Compare(ctx, login.PasswordHash, []byte(password))
	if err != nil {
		return profileObj, &login, err
	}

	return profileObj, &login, nil

}
