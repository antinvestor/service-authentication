package handlers

import (
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/gorilla/csrf"
)

func (h *AuthServer) ShowLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	svc := h.service
	logger := svc.Log(ctx).WithField("endpoint", "ShowLoginEndpoint")

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

		for k, val := range h.loginOptions {
			payload[k] = val
		}

		err = loginTmpl.Execute(rw, payload)

		return err
	}

	return nil

}
