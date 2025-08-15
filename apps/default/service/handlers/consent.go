package handlers

import (
	"context"
	"net/http"

	devicev1 "github.com/antinvestor/apis/go/device/v1"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/markbates/goth/gothic"
)

func (h *AuthServer) ShowConsentEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	logger := h.service.Log(ctx)

	defaultHydra := hydra.NewDefaultHydra(h.config.GetOauth2ServiceAdminURI())

	consentChallenge, err := hydra.GetConsentChallengeID(req)
	if err != nil {
		logger.WithError(err).Info(" couldn't get a valid login challenge")
		return err
	}

	// Store loginChallenge in session before OAuth redirect
	session, err := gothic.Store.Get(req, SessionKeyStorageName)
	if err != nil {
		logger.WithError(err).Error("failed to get session")
		return err
	}

	// Clean up the session value after retrieving it
	delete(session.Values, SessionKeyLoginChallenge)
	err = session.Save(req, rw)
	if err != nil {
		logger.WithError(err).Warn("failed to save session after cleanup")
	}

	getConseReq, err := defaultHydra.GetConsentRequest(req.Context(), consentChallenge)

	if err != nil {
		return err
	}

	deviceSessionID := utils.DeviceIDFromContext(ctx)

	deviceObj, err := h.processDeviceSession(ctx, deviceSessionID, getConseReq.GetSubject())
	if err != nil && deviceObj == nil {
		logger.WithError(err).Error("could not process device id link")
		return err
	}

	client := getConseReq.GetClient()
	clientID := client.GetClientId()

	partitionObj, err := h.partitionCli.GetPartition(ctx, clientID)
	if err != nil {
		logger.WithError(err).Error("could not get partition by profile id")
		return err
	}

	tokenMap := map[string]any{
		"tenant_id":       partitionObj.GetTenantId(),
		"partition_id":    partitionObj.GetId(),
		"roles":           []string{"user"},
		"device_id":       deviceObj.GetId(),
		"login_id":  deviceObj.GetSessionId(),
		"profile_id":      getConseReq.GetSubject(),
		"profile_contact": getConseReq.GetSubject(),
	}

	params := &hydra.AcceptConsentRequestParams{
		ConsentChallenge:  consentChallenge,
		GrantScope:        getConseReq.GetRequestedScope(),
		GrantAudience:     client.GetAudience(),
		AccessTokenExtras: tokenMap,
		IdTokenExtras:     tokenMap,
	}

	redirectUrl, err := defaultHydra.AcceptConsentRequest(req.Context(), params)

	if err != nil {
		return err
	}

	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)

	// For the foreseeable future we will always skip the consent page
	// if getConseReq.Get("skip").Bool() {
	//
	// } else {

	// payload := initTemplatePayload(req.Context())
	// payload["error"] = ""
	// payload[csrf.TemplateTag] = csrf.TemplateField(req)
	//
	// err := env.Template.ExecuteTemplate(rw, "consent.html", payload)

	// return err
	// }

	return nil
}

func (h *AuthServer) processDeviceSession(ctx context.Context, deviceSessionId string, profileId string) (*devicev1.DeviceObject, error) {

	deviceCli := h.DeviceCli()

	var deviceObj *devicev1.DeviceObject
	session, err := deviceCli.Svc().GetBySessionId(ctx, &devicev1.GetBySessionIdRequest{Id: deviceSessionId})
	if err != nil {

		resp, err0 := deviceCli.Svc().Create(ctx, &devicev1.CreateRequest{
			Name:       "Error dev",
			Properties: map[string]string{"source": "consent"},
		})
		if err0 != nil {
			return nil, err0
		}
		deviceObj = resp.GetData()

	} else {
		deviceObj = session.GetData()
	}

	if deviceObj.GetProfileId() == profileId {
		return deviceObj, nil
	}

	resp, err := deviceCli.Svc().Link(ctx, &devicev1.LinkRequest{
		Id:         deviceSessionId,
		ProfileId:  profileId,
		Properties: map[string]string{"source": "consent"},
	})
	if err != nil {
		return deviceObj, err
	}

	deviceObj = resp.GetData()

	return deviceObj, nil

}
