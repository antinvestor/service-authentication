package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	devicev1 "buf.build/gen/go/antinvestor/device/protocolbuffers/go/device/v1"
	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

// ShowConsentEndpoint handles the OAuth2 consent flow.
// It retrieves consent challenge, processes device session, and grants consent.
func (h *AuthServer) ShowConsentEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx)

	hydraCli := h.defaultHydraCli

	// Step 1: Extract consent challenge
	consentChallenge, err := hydra.GetConsentChallengeID(req)
	if err != nil {
		log.WithError(err).Warn("missing or invalid consent_challenge parameter")
		return fmt.Errorf("consent challenge required: %w", err)
	}

	// Use first 16 chars for logging
	challengePrefix := consentChallenge
	if len(challengePrefix) > 16 {
		challengePrefix = challengePrefix[:16]
	}
	log = log.WithField("consent_challenge_prefix", challengePrefix)

	// Step 2: Clean up session (remove login event ID)
	session, err := h.getLogginSession().Get(req, SessionKeyLoginStorageName)
	if err != nil {
		log.WithError(err).Warn("failed to get session for cleanup")
		// Continue anyway - session cleanup is not critical
	} else {
		delete(session.Values, SessionKeyLoginEventID)
		if saveErr := session.Save(req, rw); saveErr != nil {
			log.WithError(saveErr).Debug("failed to save session after cleanup")
		}
	}

	// Step 3: Get consent request from Hydra
	getConseReq, err := hydraCli.GetConsentRequest(ctx, consentChallenge)
	if err != nil {
		log.WithError(err).Error("hydra consent request lookup failed")
		return fmt.Errorf("failed to get consent request: %w", err)
	}

	subjectID := getConseReq.GetSubject()
	log = log.WithField("subject_id", subjectID)

	// Step 4: Process device session
	deviceObj, err := h.processDeviceSession(ctx, subjectID)
	if err != nil {
		if deviceObj == nil {
			log.WithError(err).Error("device session processing failed")
			return fmt.Errorf("failed to process device session: %w", err)
		}
		log.WithError(err).Warn("device session processing had non-fatal error")
	}

	if err = h.storeDeviceID(ctx, rw, deviceObj); err != nil {
		log.WithError(err).Debug("failed to store device ID cookie")
		// Continue - device cookie is not critical for consent
	}

	// Step 5: Get partition info for token claims
	client := getConseReq.GetClient()
	clientID := client.GetClientId()

	partitionResp, err := h.partitionCli.GetPartition(ctx, connect.NewRequest(&partitionv1.GetPartitionRequest{Id: clientID}))
	if err != nil {
		log.WithError(err).WithField("client_id", clientID).Error("partition lookup failed")
		return fmt.Errorf("failed to get partition: %w", err)
	}

	partitionObj := partitionResp.Msg.GetData()
	if partitionObj == nil {
		log.WithField("client_id", clientID).Error("partition not found")
		return fmt.Errorf("partition not found for client: %s", clientID)
	}

	// Step 6: Build token claims
	tokenMap := map[string]any{
		"tenant_id":       partitionObj.GetTenantId(),
		"partition_id":    partitionObj.GetId(),
		"roles":           []string{"user"},
		"device_id":       deviceObj.GetId(),
		"login_id":        deviceObj.GetSessionId(),
		"profile_id":      subjectID,
		"profile_contact": subjectID,
	}

	// Step 7: Accept consent and get redirect URL
	params := &hydra.AcceptConsentRequestParams{
		ConsentChallenge:  consentChallenge,
		GrantScope:        getConseReq.GetRequestedScope(),
		GrantAudience:     client.GetAudience(),
		AccessTokenExtras: tokenMap,
		IdTokenExtras:     tokenMap,
	}

	redirectURL, err := hydraCli.AcceptConsentRequest(ctx, params)
	if err != nil {
		log.WithError(err).Error("hydra accept consent request failed")
		return fmt.Errorf("failed to accept consent: %w", err)
	}

	// Step 8: Clear session cookie and redirect
	h.clearDeviceSessionID(rw)

	log.WithFields(map[string]any{
		"partition_id": partitionObj.GetId(),
		"tenant_id":    partitionObj.GetTenantId(),
		"device_id":    deviceObj.GetId(),
		"duration_ms":  time.Since(start).Milliseconds(),
	}).Info("consent granted successfully")

	http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
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
