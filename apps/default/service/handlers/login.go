package handlers

import (
	"context"
	"errors"
	"html/template"
	"net/http"

	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/gorilla/csrf"
)

var loginTmpl = template.Must(template.ParseFiles("tmpl/auth_base.html", "tmpl/login.html"))

func (h *AuthServer) ShowLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()

	logger := h.service.Log(ctx).WithField("endpoint", "ShowLoginEndpoint")

	defaultHydra := hydra.NewDefaultHydra(h.config.GetOauth2ServiceAdminURI())

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

func (h *AuthServer) SubmitLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	logger := h.service.Log(ctx).WithField("endpoint", "SubmitLoginEndpoint")

	defaultHydra := hydra.NewDefaultHydra(h.config.GetOauth2ServiceAdminURI())

	contact := req.PostForm.Get("contact")
	password := req.PostForm.Get("password")
	loginChallenge := req.PostForm.Get("login_challenge")

	logger = logger.WithField("contact", contact)

	profileObj, _, err := getLoginCredentials(ctx, h.loginRepo, contact, password)

	if err != nil {
		logger.WithError(err).Warn("could not get login credentials")

		payload := initTemplatePayload(req.Context())
		payload["error"] = "unable to log you in "
		payload["loginChallenge"] = loginChallenge
		payload[csrf.TemplateTag] = csrf.TemplateField(req)

		err = loginTmpl.Execute(rw, payload)

		return err
	}

	params := &hydra.AcceptLoginRequestParams{LoginChallenge: loginChallenge, SubjectID: profileObj.GetId(), Remember: true, RememberDuration: h.config.SessionRememberDuration}

	redirectUrl, err := defaultHydra.AcceptLoginRequest(
		req.Context(), params)

	if err != nil {
		logger.WithError(err).Error("critical issue")
		return err
	}

	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)

	return nil
}

//
// func postLoginChecks(_ context.Context,
// 	_ *profilev1.ProfileObject, _ string,
// 	_ *models.Login, err error, _ *http.Request) error {
//
// 	if err != nil {
// 		return err
// 	}
//
// 	// TODO: In the event the user can't pass tests for long enough remember to use
// 	// hydra.RejectLoginRequest()
//
// 	return nil
// }

func getLoginCredentials(ctx context.Context, loginRepo repository.LoginRepository, contact string, password string) (*profilev1.ProfileObject, *models.Login, error) {

	profileCli := profilev1.FromContext(ctx)

	profileObj, err := profileCli.GetProfileByContact(ctx, contact)

	if err != nil {
		return nil, nil, err
	}

	profileHash := utils.HashStringSecret(profileObj.GetId())

	login, err := loginRepo.GetByProfileHash(ctx, profileHash)
	if err != nil {
		return profileObj, nil, err
	}

	if login == nil {
		return profileObj, nil, errors.New("login not found")
	}

	crypt := utils.NewBCrypt()

	err = crypt.Compare(ctx, login.PasswordHash, []byte(password))
	if err != nil {
		return profileObj, login, err
	}

	return profileObj, login, nil

}
