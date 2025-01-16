package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/antinvestor/service-authentication/config"
	"github.com/antinvestor/service-authentication/hydra"
	"github.com/pitabwire/frame"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"net/http"
	"strings"
)

func ShowConsentEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	partitionAPI := partitionv1.FromContext(ctx)
	service := frame.FromContext(ctx)

	cfg, ok := service.Config().(*config.AuthenticationConfig)
	if !ok {
		return fmt.Errorf("could not convert configuration correctly")
	}

	logger := service.L(ctx)

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

	logger.WithField("consent_request", getConseReq).Info("authenticated client payload")

	requestedScope := getConseReq.GetRequestedScope()
	profileID := getConseReq.GetSubject()

	client := getConseReq.GetClient()

	clientID := client.GetClientId()
	grantedAudience := client.GetAudience()

	access, err := partitionAPI.GetAccessByClientIdProfileId(ctx, clientID, profileID)
	if err != nil {
		st, ok0 := status.FromError(err)
		if ok0 && st.Code() == codes.NotFound {
			access, err = partitionAPI.CreateAccessByClientID(ctx, clientID, profileID)
		}

		if err != nil {
			logger.WithError(err).Info("there was an error getting access")
			return err
		}
	}

	accessRoles, err := partitionAPI.ListAccessRole(ctx, access.GetAccessId())
	if err != nil {
		logger.WithError(err).Info("there was an error getting access roles")
		return err
	}

	// Create a slice to store data from the channel
	var accessRolesList []string

	// Read from the channel until it's closed
	for val := range accessRoles {
		if val.GetRole() != nil {
			accessRolesList = append(accessRolesList, val.GetRole().GetName())
		}
	}

	partition := access.GetPartition()

	deviceId := ""
	cookie, err := req.Cookie("DevLnkID")
	if err == nil {
		deviceId, err = processDeviceIdLink(ctx, cfg, cookie.Value, profileID)
		if err != nil {
			logger.WithError(err).Info("could not process for device id")
		}
	}

	tokenMap := map[string]any{
		"tenant_id":       partition.GetTenantId(),
		"partition_id":    partition.GetId(),
		"partition_state": partition.GetState().String(),
		"access_id":       access.GetAccessId(),
		"device_id":       deviceId,
		"access_state":    access.GetState().String(),
		"roles":           accessRolesList,
	}

	params := &hydra.AcceptConsentRequestParams{
		ConsentChallenge:  consentChallenge,
		GrantScope:        requestedScope,
		GrantAudience:     grantedAudience,
		Remember:          true,
		RememberDuration:  0,
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
	//
	//err := env.Template.ExecuteTemplate(rw, "login.html", map[string]any{
	//	"error":          "",
	//	csrf.TemplateTag: csrf.TemplateField(req),
	//})

	// return err
	//}

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
	defer resp.Body.Close()

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
