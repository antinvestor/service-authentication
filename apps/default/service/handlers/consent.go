package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/hydra"
	"github.com/antinvestor/service-authentication/apps/default/utils"
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

	getConseReq, err := defaultHydra.GetConsentRequest(req.Context(), consentChallenge)

	if err != nil {
		return err
	}

	deviceId := utils.DeviceIDFromContext(ctx)

	deviceLinkId, err := processDeviceIdLink(ctx, h.config, deviceId, getConseReq.GetSubject())
	if err != nil {
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
		"device_id":       deviceId,
		"device_link_id":  deviceLinkId,
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

func processDeviceIdLink(_ context.Context, cfg *config.AuthenticationConfig, deviceLinkId string, profileId string) (string, error) {

	profileUrl := "https://profile.chamamobile.com/_public/device/link"
	profileUrlTokens := strings.Split(cfg.ProfileServiceURI, ":")
	if len(profileUrlTokens) == 2 {
		profileUrl = fmt.Sprintf("http://%s/_public/device/link", profileUrlTokens[0])
	}

	payload := map[string]interface{}{
		"link_id":    deviceLinkId,
		"profile_id": profileId,
	}

	// Marshal the payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Make the POST request
	resp, err := http.Post(profileUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			err = closeErr
		}
	}()

	// Check the status code
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(" failed to get device id, status : [ %d ]  message : %s ", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var responseMap map[string]any
	if err = json.Unmarshal(body, &responseMap); err != nil {
		return "", err
	}

	deviceId, ok := responseMap["id"]
	if !ok {
		deviceId = responseMap["ID"]
	}

	return deviceId.(string), nil

}
