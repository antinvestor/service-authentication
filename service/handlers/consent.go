package handlers

import (
	"net/http"

	"github.com/antinvestor/service-authentication/hydra"
)

func ShowConsentEndpoint(rw http.ResponseWriter, req *http.Request) error {

	consentChallenge := req.FormValue("consent_challenge")

	getConseReq, err := hydra.GetConsentRequest(req.Context(), consentChallenge)
	if err != nil {
		return err
	}

	//if getConseReq.Get("skip").Bool() {
	grantedScope := []string{}
	getConseReq.Get("requested_scope").StringSlice(grantedScope)

	grantedAudience := []string{}
	getConseReq.Get("requested_access_token_audience").StringSlice(grantedAudience)

	accLogReq, err := hydra.AcceptConsentRequest(req.Context(), consentChallenge, map[string]interface{}{
		"grant_scope":                 grantedScope,
		"grant_access_token_audience": grantedAudience,
		// The session allows us to set session data for id and access tokens can have more data like name and such
		"session": map[string]string{},
	})

	if err != nil {
		return err
	}

	http.Redirect(rw, req, accLogReq.Get("redirect_to").String(), http.StatusSeeOther)

	// For the foreseeable future we will always skip the consent page
	//if getConseReq.Get("skip").Bool() {
	//
	//} else {
	//
	//err := env.Template.ExecuteTemplate(rw, "login.html", map[string]interface{}{
	//	"error":          "",
	//	csrf.TemplateTag: csrf.TemplateField(req),
	//})

	//return err
	//}

	return nil
}
