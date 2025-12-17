package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	client "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/util"
)

const SessionKeyLoginStorageName = "login-storage"
const SessionKeyLoginEventID = "login-event-id"

func (h *AuthServer) updateTenancyForLoginEvent(ctx context.Context, loginEventID string) {

	loginEvt, ok, err := h.loginEventCache().Get(ctx, loginEventID)
	if err != nil {
		util.Log(ctx).WithError(err).Error("Failed to get login event cache")
		return
	}
	if !ok {
		util.Log(ctx).Error("Login event not found")
		return
	}

	partitionResp, err := h.partitionCli.GetPartition(ctx, connect.NewRequest(&partitionv1.GetPartitionRequest{Id: loginEvt.ClientID}))
	if err != nil {
		util.Log(ctx).WithError(err).Error("Failed to get partition")
		return
	}

	partitionObj := partitionResp.Msg.GetData()

	loginEvt.PartitionID = partitionObj.GetId()
	loginEvt.TenantID = partitionObj.GetTenantId()

	err = h.loginEventCache().Set(ctx, loginEvt.GetID(), loginEvt, time.Hour)
	if err != nil {
		util.Log(ctx).WithError(err).Error("Failed to set login event cache")
	}
}

func (h *AuthServer) createLoginEvent(ctx context.Context, loginReq *client.OAuth2LoginRequest, loginChallenge string) (*models.LoginEvent, error) {
	// Log login challenge fingerprint before storing in LoginEvent
	deviceSessionID := utils.SessionIDFromContext(ctx)

	cli, ok := loginReq.GetClientOk()
	if !ok || cli.GetClientId() == "" {
		return nil, fmt.Errorf("login can't happen without a client")
	}

	loginEvt := models.LoginEvent{
		ClientID:         cli.GetClientId(),
		LoginChallengeID: loginChallenge,
		SessionID:        deviceSessionID,
		Oauth2SessionID:  loginReq.GetSessionId(),
	}
	loginEvt.ID = util.IDString()

	err := h.loginEventCache().Set(ctx, loginEvt.GetID(), loginEvt, time.Hour)
	if err != nil {
		return nil, err
	}

	return &loginEvt, nil
}

func (h *AuthServer) ShowLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()

	hydraCli := h.defaultHydraCli

	loginChallenge, err := hydra.GetLoginChallengeID(req)
	if err != nil {
		util.Log(ctx).WithError(err).Error("couldn't get a valid login challenge")
		return err
	}

	getLogReq, err := hydraCli.GetLoginRequest(ctx, loginChallenge)
	if err != nil {
		util.Log(ctx).WithError(err).Error("couldn't get a valid login challenge")
		return err
	}

	if getLogReq.Skip {
		redirectUrl := ""
		params := &hydra.AcceptLoginRequestParams{LoginChallenge: loginChallenge, SubjectID: getLogReq.GetSubject()}
		redirectUrl, err = hydraCli.AcceptLoginRequest(ctx, params, "auto refresh")

		if err != nil {
			return err
		}

		http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)
		return nil

	}

	loginEvent, err := h.createLoginEvent(ctx, getLogReq, loginChallenge)
	if err != nil {
		return err
	}
	defer h.updateTenancyForLoginEvent(ctx, loginEvent.GetID())

	payload := initTemplatePayload(req.Context())
	payload[pathValueLoginEventID] = loginEvent.GetID()
	payload["error"] = ""

	for k, val := range h.loginOptions {
		payload[k] = val
	}

	return loginTmpl.Execute(rw, payload)

}
