package handlers

import (
	"context"
	"net/http"
	"time"

	devicev1 "buf.build/gen/go/antinvestor/device/protocolbuffers/go/device/v1"
	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"google.golang.org/protobuf/types/known/structpb"
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
	session, err := h.getLogginSession().Get(req, SessionKeyLoginStorageName)
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

	deviceObj, err := h.processDeviceSession(ctx, getConseReq.GetSubject())
	if err != nil && deviceObj == nil {
		logger.WithError(err).Error("could not process device id linkage")
		return err
	}

	err = h.storeDeviceID(ctx, rw, deviceObj)
	if err != nil {
		logger.WithError(err).Error("could not store device id in cookie")
	}

	client := getConseReq.GetClient()
	clientID := client.GetClientId()

	partitionResp, err := h.partitionCli.GetPartition(ctx, connect.NewRequest(&partitionv1.GetPartitionRequest{Id: clientID}))
	if err != nil {
		logger.WithError(err).Error("could not get partition by profile id")
		return err
	}

	partitionObj := partitionResp.Msg.GetData()
	tokenMap := map[string]any{
		"tenant_id":       partitionObj.GetTenantId(),
		"partition_id":    partitionObj.GetId(),
		"roles":           []string{"user"},
		"device_id":       deviceObj.GetId(),
		"login_id":        deviceObj.GetSessionId(),
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

	h.clearDeviceSessionID(rw)

	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)
	return nil
}

func (h *AuthServer) processDeviceSession(ctx context.Context, profileId string) (*devicev1.DeviceObject, error) {

	deviceID := utils.DeviceIDFromContext(ctx)
	deviceSessionID := utils.SessionIDFromContext(ctx)

	deviceCli := h.DeviceCli()

	var deviceObj *devicev1.DeviceObject

	if deviceID != "" {
		resp, err := deviceCli.GetById(ctx, connect.NewRequest(&devicev1.GetByIdRequest{Id: []string{deviceID}}))
		if err == nil && len(resp.Msg.GetData()) > 0 {
			deviceObj = resp.Msg.GetData()[0]
		}
	}

	if deviceSessionID != "" {

		session, err := deviceCli.GetBySessionId(ctx, connect.NewRequest(&devicev1.GetBySessionIdRequest{Id: deviceSessionID}))
		if err == nil {
			deviceObj = session.Msg.GetData()
		}

	}

	props, _ := structpb.NewStruct(map[string]any{"source": "consent"})
	if deviceObj == nil {

		resp, err0 := deviceCli.Create(ctx, connect.NewRequest(&devicev1.CreateRequest{
			Name:       "Error dev",
			Properties: props,
		}))
		if err0 != nil {
			return nil, err0
		}
		deviceObj = resp.Msg.GetData()
	}

	if deviceObj.GetProfileId() == profileId {
		return deviceObj, nil
	}

	resp, err := deviceCli.Link(ctx, connect.NewRequest(&devicev1.LinkRequest{
		Id:         deviceObj.GetId(),
		ProfileId:  profileId,
		Properties: props,
	}))
	if err != nil {
		return deviceObj, err
	}

	deviceObj = resp.Msg.GetData()

	return deviceObj, nil

}

func (h *AuthServer) storeDeviceID(ctx context.Context, w http.ResponseWriter, deviceObj *devicev1.DeviceObject) error {

	deviceID := utils.DeviceIDFromContext(ctx)

	if deviceObj.GetId() == deviceID {
		return nil
	}

	// Encode and sign the device ID cookie
	encoded, encodeErr := h.loginCookieCodec[0].Encode(SessionKeyDeviceIDKey, deviceObj.GetId())
	if encodeErr != nil {
		return encodeErr
	}

	// Set the secure, signed device ID cookie (long-term)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionKeyDeviceStorageName,
		Value:    encoded,
		Path:     "/",
		MaxAge:   473040000, // 15 years
		Secure:   true,      // HTTPS-only
		HttpOnly: true,      // No JavaScript access
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(473040000 * time.Second),
	})

	return nil
}

// clearDeviceSessionID clears the device session ID cookie, forcing creation of a new session
func (h *AuthServer) clearDeviceSessionID(w http.ResponseWriter) {
	// Set an expired session cookie to clear it
	http.SetCookie(w, &http.Cookie{
		Name:     SessionKeySessionStorageName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Negative MaxAge means delete the cookie
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(-1 * time.Hour), // Set to past time
	})
}
