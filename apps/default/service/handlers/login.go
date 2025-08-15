package handlers

import (
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/gorilla/csrf"
	"github.com/markbates/goth/gothic"
)

const SessionKeyStorageName = "login-storage"
const SessionKeyLoginChallenge = "login_challenge"

func (h *AuthServer) ShowLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	svc := h.service
	logger := svc.Log(ctx).WithField("endpoint", "ShowLoginEndpoint")

	// Store loginChallenge in session before OAuth redirect
	session, err := gothic.Store.Get(req, SessionKeyStorageName)
	if err != nil {
		logger.WithError(err).Error("failed to get session")
		return err
	}

	// Clean up the session value after retrieving it
	delete(session.Values, SessionKeyLoginChallenge)
	err = session.Save(req, rw)
	if err != nil {
		logger.WithError(err).Warn("failed to save session after cleanup")
	}

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
		return nil

	}

	session.Values[SessionKeyLoginChallenge] = loginChallenge
	err = session.Save(req, rw)
	if err != nil {
		logger.WithError(err).Error("failed to save login_challenge to session")
		return err
	}

	payload := initTemplatePayload(req.Context())

	payload["error"] = ""
	payload[csrf.TemplateTag] = csrf.TemplateField(req)

	for k, val := range h.loginOptions {
		payload[k] = val
	}

	return loginTmpl.Execute(rw, payload)

}
