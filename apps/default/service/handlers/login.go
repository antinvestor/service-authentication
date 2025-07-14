package handlers

import (
	"context"
	"fmt"
	"html/template"
	"net/http"

	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/gorilla/csrf"
	"github.com/pitabwire/frame"
)

var loginTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/login.html"))

func ShowLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	service := frame.Svc(ctx)

	cfg, ok := service.Config().(*config.AuthenticationConfig)
	if !ok {
		return fmt.Errorf("could not convert configuration correctly")
	}

	logger := service.Log(ctx).WithField("endpoint", "ShowLoginEndpoint")

	defaultHydra := hydra.NewDefaultHydra(cfg.GetOauth2ServiceAdminURI())

	loginChallenge, err := hydra.GetLoginChallengeID(req)
	if err != nil {
		logger.WithError(err).Warn(" couldn't get a valid login challenge")
		return err
	}

	getLogReq, err := defaultHydra.GetLoginRequest(ctx, loginChallenge)
	if err != nil {
		logger = logger.WithField("login_challenge", loginChallenge)

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

		payload := initTemplatePayload(req.Context())
		payload["error"] = ""
		payload["loginChallenge"] = loginChallenge
		payload[csrf.TemplateTag] = csrf.TemplateField(req)

		err = loginTmpl.Execute(rw, payload)

		return err
	}

	return nil

}

func SubmitLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	service := frame.Svc(ctx)

	cfg, ok := service.Config().(*config.AuthenticationConfig)
	if !ok {
		return fmt.Errorf("could not convert configuration correctly")
	}

	logger := service.Log(ctx).WithField("endpoint", "SubmitLoginEndpoint")

	defaultHydra := hydra.NewDefaultHydra(cfg.GetOauth2ServiceAdminURI())

	contact := req.PostForm.Get("contact")
	password := req.PostForm.Get("password")
	loginChallenge := req.PostForm.Get("login_challenge")

	logger = logger.WithField("contact", contact)

	profileObj, login, err := getLoginCredentials(ctx, contact, password)

	err = postLoginChecks(ctx, profileObj, contact, login, err, req)
	if err != nil {

		logger.WithError(err).Info(" Could not login user")

		// TODO: In the event the user can't pass tests for long enough remember to use
		// hydra.RejectLoginRequest()

		payload := initTemplatePayload(req.Context())
		payload["error"] = "unable to log you in "
		payload["loginChallenge"] = loginChallenge
		payload[csrf.TemplateTag] = csrf.TemplateField(req)

		err = loginTmpl.Execute(rw, payload)

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

func postLoginChecks(_ context.Context,
	_ *profilev1.ProfileObject, _ string,
	_ *models.Login, err error, _ *http.Request) error {

	if err != nil {
		return err
	}

	// TODO: In the event the user can't pass tests for long enough remember to use
	// hydra.RejectLoginRequest()

	return nil
}

func getLoginCredentials(ctx context.Context, contact string, password string) (*profilev1.ProfileObject, *models.Login, error) {

	service := frame.Svc(ctx)
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
