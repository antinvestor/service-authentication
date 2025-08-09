package handlers

import (
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/hydra"
)

func (h *AuthServer) ShowLogoutEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	logger := h.service.Log(ctx).WithField("endpoint", "ShowLoginEndpoint")

	defaultHydra := hydra.NewDefaultHydra(h.config.GetOauth2ServiceAdminURI())

	logoutChallenge, err := hydra.GetLogoutChallengeID(req)
	if err != nil {
		logger.WithError(err).Info(" couldn't get a valid login challenge")
		return err
	}

	_, err = defaultHydra.GetLogoutRequest(req.Context(), logoutChallenge)
	if err != nil {
		return err
	}

	redirectUrl, err := defaultHydra.AcceptLogoutRequest(req.Context(), &hydra.AcceptLogoutRequestParams{LogoutChallenge: logoutChallenge})

	if err != nil {
		return err
	}

	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)

	return nil
}
