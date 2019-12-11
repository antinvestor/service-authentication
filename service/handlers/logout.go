package handlers

import (
	"antinvestor.com/service/auth/utils"
	"net/http"

	"github.com/opentracing/opentracing-go"

	"antinvestor.com/service/auth/hydra"
)

func ShowLogoutEndpoint(env *utils.Env, rw http.ResponseWriter, req *http.Request) error {
	span, _ := opentracing.StartSpanFromContext(req.Context(), "ShowLogoutEndpoint")
	defer span.Finish()

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
