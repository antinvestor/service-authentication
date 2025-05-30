package handlers

import (
	"fmt"
	"github.com/antinvestor/service-authentication/config"
	"github.com/pitabwire/frame"
	"net/http"

	"github.com/antinvestor/service-authentication/hydra"
)

func ShowLogoutEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	service := frame.FromContext(ctx)

	cfg, ok := service.Config().(*config.AuthenticationConfig)
	if !ok {
		return fmt.Errorf("could not convert configuration correctly")
	}

	logger := service.L(ctx).WithField("endpoint", "ShowLoginEndpoint")

	defaultHydra := hydra.NewDefaultHydra(cfg.GetOauth2ServiceAdminURI())

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
