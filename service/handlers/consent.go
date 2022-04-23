package handlers

import (
	"github.com/antinvestor/service-authentication/hydra"
	partapi "github.com/antinvestor/service-partition-api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
	"net/http"
)

func ShowConsentEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	partitionAPI := partapi.FromContext(ctx)

	consentChallenge := req.FormValue("consent_challenge")

	getConseReq, err := hydra.GetConsentRequest(req.Context(), consentChallenge)
	if err != nil {
		return err
	}

	grantedScope := getConseReq.Get("requested_scope").Data().([]interface{})
	profileID := getConseReq.Get("subject").Str()

	client := getConseReq.Get("client").MSI()
	clientID := client["client_id"].(string)
	grantedAudience := client["audience"].([]interface{})

	access, err := partitionAPI.GetAccess(ctx, clientID, profileID)
	if err != nil {
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.NotFound {
			access, err = partitionAPI.CreateAccess(ctx, clientID, profileID)
		}

		if err != nil {
			log.Printf(" ShowConsentEndpoint -- there was an error getting access %+v", err)
			return err
		}
	}

	partition := access.GetPartition()

	sessionMap := map[string]interface{}{
		"id_token": map[string]string{
			"tenant_id":       partition.GetTenantId(),
			"partition_id":    partition.GetPartitionId(),
			"partition_state": partition.GetState().String(),
			"access_id":       access.GetAccessId(),
			"access_state":    access.GetState().String(),
		},
	}

	accLogReq, err := hydra.AcceptConsentRequest(req.Context(), consentChallenge, map[string]interface{}{
		"grant_scope":                 grantedScope,
		"grant_access_token_audience": grantedAudience,
		// The session allows us to set session data for id and access tokens can have more data like name and such
		"session": sessionMap,
	})

	if err != nil {
		return err
	}

	http.Redirect(rw, req, accLogReq.Get("redirect_to").String(), http.StatusSeeOther)

	// For the foreseeable future we will always skip the consent page
	// if getConseReq.Get("skip").Bool() {
	//
	// } else {
	//
	//err := env.Template.ExecuteTemplate(rw, "login.html", map[string]interface{}{
	//	"error":          "",
	//	csrf.TemplateTag: csrf.TemplateField(req),
	//})

	// return err
	//}

	return nil
}
