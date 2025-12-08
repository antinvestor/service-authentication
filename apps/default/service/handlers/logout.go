package handlers

import (
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/pitabwire/util"
)

func (h *AuthServer) ShowLogoutEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	logger := util.Log(ctx).WithField("endpoint", "ShowLoginEndpoint")

	hydraCli := h.defaultHydraCli

	logoutChallenge, err := hydra.GetLogoutChallengeID(req)
	if err != nil {
		logger.WithError(err).Info(" couldn't get a valid login challenge")
		return err
	}

	_, err = hydraCli.GetLogoutRequest(req.Context(), logoutChallenge)
	if err != nil {
		return err
	}

	redirectUrl, err := hydraCli.AcceptLogoutRequest(req.Context(), &hydra.AcceptLogoutRequestParams{LogoutChallenge: logoutChallenge})

	if err != nil {
		return err
	}

	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)

	return nil
}
