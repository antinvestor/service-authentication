package handlers

import (
	"context"
	"errors"
	"net/http"

	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/gorilla/csrf"
)

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
	
	// Debug logging for POST request handling
	logger.Info("SubmitLoginEndpoint called - POST request received")
	logger.WithField("method", req.Method).WithField("url", req.URL.String()).Info("Request details")

	defaultHydra := hydra.NewDefaultHydra(h.config.GetOauth2ServiceAdminURI())

	// Parse form data before accessing PostForm
	if err := req.ParseForm(); err != nil {
		logger.WithError(err).Error("failed to parse form data")
		return err
	}
	
	logger.Info("Form data parsed successfully")

	contact := req.PostForm.Get("contact")
	password := req.PostForm.Get("password")
	loginChallenge := req.PostForm.Get("login_challenge")
	
	logger.WithField("contact", contact).WithField("has_password", password != "").WithField("has_challenge", loginChallenge != "").Info("Form fields extracted")

	logger = logger.WithField("contact", contact)

	if contact == "" || password == "" || loginChallenge == "" {
		logger.Error("missing required fields")
		return h.showLoginWithError(rw, req, loginChallenge, "All fields are required")
	}

	// Debug: Log the authentication attempt
	logger.Info("DEBUG: Starting authentication process")

	profileObj, loginRecord, err := h.getLoginCredentials(ctx, contact, password)

	if err != nil {
		logger.WithError(err).Error("DEBUG: getLoginCredentials failed")
		return h.showLoginWithError(rw, req, loginChallenge, "unable to log you in")
	}
	
	// Debug: Log successful authentication
	logger.WithField("profile_id", profileObj.GetId()).WithField("has_login_record", loginRecord != nil).Info("DEBUG: Authentication successful")

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

// showLoginWithError displays the login form with an error message
func (h *AuthServer) showLoginWithError(rw http.ResponseWriter, req *http.Request, loginChallenge, errorMsg string) error {
	payload := initTemplatePayload(req.Context())
	payload["error"] = errorMsg
	payload["loginChallenge"] = loginChallenge
	payload[csrf.TemplateTag] = csrf.TemplateField(req)

	return loginTmpl.Execute(rw, payload)
}

func (h *AuthServer) getLoginCredentials(ctx context.Context, contact string, password string) (*profilev1.ProfileObject, *models.Login, error) {


	profileObj, err := h.profileCli.GetProfileByContact(ctx, contact)

	if err != nil {
		return nil, nil, err
	}

	profileHash := utils.HashStringSecret(profileObj.GetId())

	login, err := h.loginRepo.GetByProfileHash(ctx, profileHash)
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
