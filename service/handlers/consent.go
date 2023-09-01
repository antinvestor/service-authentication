package handlers

import (
	"fmt"
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/hydra"
	partapi "github.com/antinvestor/service-partition-api"
	"github.com/pitabwire/frame"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
	"net/http"
)

func ShowConsentEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	partitionAPI := partapi.FromContext(ctx)
	service := frame.FromContext(ctx)

	cfg, ok := service.Config().(*config.AuthenticationConfig)
	if !ok {
		return fmt.Errorf("could not convert configuration correctly")
	}

	logger := service.L().WithField("endpoint", "ShowConsentEndpoint")

	defaultHydra := hydra.NewDefaultHydra(cfg.GetOauth2ServiceAdminURI())

	consentChallenge, err := hydra.GetConsentChallengeID(req)
	if err != nil {
		logger.WithError(err).Info(" couldn't get a valid login challenge")
		return err
	}

	getConseReq, err := defaultHydra.GetConsentRequest(req.Context(), consentChallenge)
	if err != nil {
		return err
	}

	requestedScope := getConseReq.GetRequestedScope()
	profileID := getConseReq.GetSubject()

	client := getConseReq.GetClient()
	clientID := client.GetClientId()
	grantedAudience := client.GetAudience()

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

	params := hydra.AcceptConsentRequestParams{ConsentChallenge: consentChallenge, GrantScope: requestedScope, GrantAudience: grantedAudience, AdditionalParams: sessionMap}

	redirectUrl, err := defaultHydra.AcceptConsentRequest(req.Context(), params)

	if err != nil {
		return err
	}

	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)

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
