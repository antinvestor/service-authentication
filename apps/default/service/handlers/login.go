package handlers

import (
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/pitabwire/util"
)

const SessionKeyLoginStorageName = "login-storage"
const SessionKeyLoginChallenge = "login_challenge"
const SessionKeyClientID = "client_id"

func (h *AuthServer) ShowLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()

	// Store loginChallenge in session before OAuth redirect
	session, err := h.getLogginSession().Get(req, SessionKeyLoginStorageName)
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to get session")
		return err
	}

	// Clean up the session value after retrieving it
	delete(session.Values, SessionKeyLoginChallenge)
	err = session.Save(req, rw)
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to save session after cleanup")
	}

	hydraCli := h.defaultHydraCli

	loginChallenge, err := hydra.GetLoginChallengeID(req)
	if err != nil {
		util.Log(ctx).WithError(err).Error("couldn't get a valid login challenge")
		return err
	}

	getLogReq, err := hydraCli.GetLoginRequest(ctx, loginChallenge)
	if err != nil {
		util.Log(ctx).WithError(err).Error("couldn't get a valid login challenge")
		return err
	}

	if getLogReq.Skip {
		redirectUrl := ""
		params := &hydra.AcceptLoginRequestParams{LoginChallenge: loginChallenge, SubjectID: getLogReq.GetSubject()}
		redirectUrl, err = hydraCli.AcceptLoginRequest(ctx, params, "auto refresh")

		if err != nil {
			return err
		}

		http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)
		return nil

	}

	session.Values[SessionKeyLoginChallenge] = loginChallenge

	client := getLogReq.GetClient()
	clientId, ok := client.GetClientIdOk()
	if ok {
		session.Values[SessionKeyClientID] = *clientId
	}
	err = session.Save(req, rw)
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to save login_challenge to session")
		return err
	}

	payload := initTemplatePayload(req.Context())

	payload["error"] = ""

	for k, val := range h.loginOptions {
		payload[k] = val
	}

	return loginTmpl.Execute(rw, payload)

}
