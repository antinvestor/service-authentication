package handlers

import (
	"net/http"

	"github.com/antinvestor/service-authentication/hydra"
)

func ShowLogoutEndpoint(rw http.ResponseWriter, req *http.Request) error {

	logoutChallenge := req.FormValue("logout_challenge")

	_, err := hydra.GetLogoutRequest(req.Context(), logoutChallenge)
	if err != nil {
		return err
	}

	accLogReq, err := hydra.AcceptLogoutRequest(req.Context(), logoutChallenge)

	if err != nil {
		return err
	}

	http.Redirect(rw, req, accLogReq.Get("redirect_to").String(), http.StatusSeeOther)

	return nil
}
