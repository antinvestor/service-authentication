package handlers

import (
	"net/http"

	"github.com/antinvestor/service-authentication/hydra"
	"github.com/go-errors/errors"
)

func ShowLogoutEndpoint(rw http.ResponseWriter, req *http.Request) error {

	logoutChallenge := req.FormValue("logout_challenge")

	_, err := hydra.GetLogoutRequest(req.Context(), logoutChallenge)
	if err != nil {
		return errors.Wrap(err, 1)
	}

	accLogReq, err := hydra.AcceptLogoutRequest(req.Context(), logoutChallenge)

	if err != nil {
		return errors.Wrap(err, 1)
	}

	http.Redirect(rw, req, accLogReq.Get("redirect_to").String(), http.StatusSeeOther)

	return nil
}
