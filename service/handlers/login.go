package handlers

import (
	"context"
	"fmt"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/service/models"
	"github.com/antinvestor/service-authentication/utils"
	"github.com/gorilla/csrf"
	"github.com/pitabwire/frame"
	"html/template"
	"net/http"

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
		logger.WithError(err).Warn(" couldn't get a valid login challenge")
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
		params := &hydra.AcceptLoginRequestParams{LoginChallenge: loginChallenge, SubjectID: getLogReq.GetSubject()}
		redirectUrl, err = defaultHydra.AcceptLoginRequest(ctx, params)

		if err != nil {
			return err
		}

		http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)

	} else {

		err = loginTmpl.Execute(rw, map[string]any{
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

	logger := service.L().WithField("endpoint", "SubmitLoginEndpoint")

	defaultHydra := hydra.NewDefaultHydra(cfg.GetOauth2ServiceAdminURI())

	contact := req.PostForm.Get("contact")
	password := req.PostForm.Get("password")
	loginChallenge := req.PostForm.Get("login_challenge")

	logger = logger.WithField("contact", contact)

	profileObj, login, err := getLoginCredentials(ctx, contact, password)

	err = postLoginChecks(ctx, profileObj, contact, login, err, req)
	if err != nil {

		logger.WithError(err).Info(" Could not login user")

		//TODO: In the event the user can't pass tests for long enough remember to use
		//hydra.RejectLoginRequest()

		err = loginTmpl.Execute(rw, map[string]any{
			"error":          "unable to log you in ",
			"loginChallenge": loginChallenge,
			csrf.TemplateTag: csrf.TemplateField(req),
		})

		return err
	}

	params := &hydra.AcceptLoginRequestParams{LoginChallenge: loginChallenge, SubjectID: profileObj.GetId(), Remember: true, RememberDuration: cfg.SessionRememberDuration}

	redirectUrl, err := defaultHydra.AcceptLoginRequest(
		req.Context(), params)

	if err != nil {
		logger.WithError(err).Error("critical issue")
		return err
	}

	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)

	return nil
}

func postLoginChecks(ctx context.Context,
	profile *profilev1.ProfileObject, contact string,
	login *models.Login, err error, request *http.Request) error {

	if err != nil {
		return err
	}

	//TODO: In the event the user can't pass tests for long enough remember to use
	//hydra.RejectLoginRequest()

	return nil
}

func getLoginCredentials(ctx context.Context, contact string, password string) (*profilev1.ProfileObject, *models.Login, error) {

	service := frame.FromContext(ctx)
	profileCli := profilev1.FromContext(ctx)

	profileObj, err := profileCli.GetProfileByContact(ctx, contact)

	if err != nil {
		return nil, nil, err
	}

	login := models.Login{}
	profileHash := utils.HashStringSecret(profileObj.GetId())

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
