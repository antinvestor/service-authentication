package handlers

import (
	"log"
	"net/http"
	"reflect"

	"github.com/antinvestor/service-authentication/hydra"
	"github.com/go-errors/errors"
)

func ShowConsentEndpoint(rw http.ResponseWriter, req *http.Request) error {

	consentChallenge := req.FormValue("consent_challenge")

	getConseReq, err := hydra.GetConsentRequest(req.Context(), consentChallenge)
	if err != nil {
		return errors.Wrap(err, 1)
	}

	grantedScope := getConseReq.Get("requested_scope").StringSlice()
	grantedAudience := getConseReq.Get("requested_access_token_audience").StringSlice()

	log.Print(" ShowConsentEndpoint -- scopes has the following data : ")

	log.Printf(" ShowConsentEndpoint -- requested_scope is of type %s", reflect.TypeOf(getConseReq.Get("requested_scope").Data()))

	for  _, val := range getConseReq.Get("requested_scope").Data().([]interface{}) {
		log.Printf(" ShowConsentEndpoint --  %v", val)
	}

	accLogReq, err := hydra.AcceptConsentRequest(req.Context(), consentChallenge, map[string]interface{}{
		"grant_scope":                 grantedScope,
		"grant_access_token_audience": grantedAudience,
		// The session allows us to set session data for id and access tokens can have more data like name and such
		"session": map[string]string{},
	})

	if err != nil {
		return errors.Wrap(err, 1)
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

	//return errors.Wrap(err, 1)
	//}

	return nil
}
