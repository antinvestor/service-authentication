package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/apis/go/common"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	KeyProfileName        = "au_name"
	pathValueLoginEventID = "loginEventId"
)

func (h *AuthServer) ShowVerificationEndpoint(rw http.ResponseWriter, req *http.Request) error {

	loginEventID := req.PathValue(pathValueLoginEventID)
	profileName := req.FormValue("profile_name")
	errorMsg := req.FormValue("error")

	payload := initTemplatePayload(req.Context())
	payload["login_event_id"] = loginEventID
	payload["profile_name"] = profileName

	if errorMsg != "" {
		payload["error"] = errorMsg
	}

	err := verifyContactTmpl.Execute(rw, payload)
	if err != nil {
		return err
	}

	return nil

}

func (h *AuthServer) SubmitVerificationEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()

	// Check if this is verification code submission or contact submission
	verificationCode := req.FormValue("verification_code")
	profileName := req.FormValue("profile_name")

	loginEventID := req.PathValue(pathValueLoginEventID)

	loginEvt, ok, err := h.loginEventCache().Get(ctx, loginEventID)
	if err != nil {
		util.Log(ctx).WithError(err).Error("Failed to get login event cache")
		return err
	}
	if !ok {
		util.Log(ctx).Error("Login event not found")
		http.Redirect(rw, req, "/error?error=login_event_not_found&error_description=Ensure that you don't manipulate url data manually", http.StatusSeeOther)
		return fmt.Errorf("login event not found")
	}

	// If verification code is provided, handle verification code submission
	if verificationCode != "" && loginEventID != "" {
		return h.handleVerificationCodeSubmission(rw, req, loginEventID, profileName, verificationCode)
	}

	// Otherwise, handle contact submission (original logic)
	contact := req.PostForm.Get("contact")

	// Also check FormValue as fallback
	contactFormValue := req.FormValue("contact")

	// Use FormValue if PostForm is empty
	if contact == "" && contactFormValue != "" {
		contact = contactFormValue
	}

	internalRedirectLinkToSignIn := fmt.Sprintf("/s/login?login_challenge=%s", loginEvt.LoginChallengeID)

	result, err := h.profileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{Contact: contact}))
	if err != nil {

		if !frame.ErrorIsNotFound(err) {
			util.Log(ctx).WithError(err).Error("failed to get profile - redirecting to login")
			http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
			return nil
		}
	}

	var existingProfile *profilev1.ProfileObject
	contactID := ""

	if result != nil {
		existingProfile = result.Msg.GetData()

		if existingProfile != nil {
			for _, profileContact := range existingProfile.GetContacts() {
				if strings.EqualFold(contact, profileContact.GetDetail()) {
					contactID = profileContact.GetId()
				}
			}
		}
	}

	if contactID == "" {

		// don't have this contact in existence so we create it
		contactResp, err0 := h.profileCli.CreateContact(ctx, connect.NewRequest(&profilev1.CreateContactRequest{
			Contact: contact,
		}))
		if err0 != nil {
			util.Log(ctx).WithError(err0).Error("could not create/find existing contact")
			http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
			return nil
		}

		contactID = contactResp.Msg.GetData().GetId()
	}

	verificationID := util.IDString()

	loginEvent, err := h.storeLoginAttempt(ctx, &loginEvt, models.LoginSourceDirect, existingProfile.GetId(), contactID, verificationID, nil)
	if err != nil {
		util.Log(ctx).WithError(err).Error("could not store login attempt - redirecting to login")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return err
	}

	ctx = common.SetPartitionInfo(ctx, loginEvt)

	_, err = h.profileCli.CreateContactVerification(ctx, connect.NewRequest(&profilev1.CreateContactVerificationRequest{
		Id:               verificationID,
		ContactId:        contactID,
		DurationToExpire: "15m",
	}))
	if err != nil {
		util.Log(ctx).WithError(err).Error("could not create contact verification - redirecting to login")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return err
	}
	// Extract profile name from properties or use a default
	var properties data.JSONMap
	properties = properties.FromProtoStruct(existingProfile.GetProperties())
	profileName = properties.GetString(KeyProfileName)
	return h.showVerificationPage(rw, req, loginEvent.GetID(), profileName, "")
}

func (h *AuthServer) storeLoginAttempt(ctx context.Context, loginEvt *models.LoginEvent, source models.LoginSource, profileID, contactID string, verificationID string, extra map[string]any) (*models.LoginEvent, error) {

	login, err := h.loginRepo.GetByProfileID(ctx, profileID)
	if err != nil {

		if !data.ErrorIsNoRows(err) {
			return nil, err
		}

		login = &models.Login{
			ProfileID: profileID,
			Source:    string(source),
		}
		login.GenID(ctx)
		login.PartitionID = loginEvt.PartitionID
		login.TenantID = loginEvt.TenantID
		err = h.loginRepo.Create(ctx, login)
		if err != nil {
			return nil, err
		}
	}

	loginEvt.LoginID = login.GetID()
	loginEvt.DeviceID = utils.DeviceIDFromContext(ctx)
	loginEvt.VerificationID = verificationID
	loginEvt.ContactID = contactID

	loginEvt.Properties = extra

	err = h.loginEventRepo.Create(ctx, loginEvt)
	if err != nil {
		return nil, err
	}

	return loginEvt, nil
}

// showVerificationPage displays the login form with an error message
func (h *AuthServer) showVerificationPage(rw http.ResponseWriter, req *http.Request, loginEventID, profileName, errorMsg string) error {

	verificationPage := fmt.Sprintf("/s/verify/contact/%s?login_event_id=%s", loginEventID, loginEventID)

	if profileName != "" {
		verificationPage = fmt.Sprintf("%s&profile_name=%s", verificationPage, profileName)
	}

	if errorMsg != "" {
		verificationPage = fmt.Sprintf("%s&error=%s", verificationPage, errorMsg)
	}

	http.Redirect(rw, req, verificationPage, http.StatusSeeOther)
	return nil
}

// handleVerificationCodeSubmission processes verification code submission
func (h *AuthServer) handleVerificationCodeSubmission(rw http.ResponseWriter, req *http.Request, loginEventID, profileName, verificationCode string) error {
	ctx := req.Context()

	// Get login event to retrieve contact information and login challenge
	loginEvent, err := h.loginEventRepo.GetByID(ctx, loginEventID)
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to get login event")
		return h.showVerificationPage(rw, req, loginEventID, profileName, "Login event not found")
	}

	// Verify the verification code with profile service
	verifyReq := &profilev1.CheckVerificationRequest{
		Id:   loginEvent.VerificationID,
		Code: verificationCode,
	}

	verifyResp, err := h.profileCli.CheckVerification(ctx, connect.NewRequest(verifyReq))
	if err != nil {
		util.Log(ctx).WithError(err).Error("verification code verification failed")
		return h.showVerificationPage(rw, req, loginEventID, profileName, "Invalid verification code")
	}

	if verifyResp.Msg.GetCheckAttempts() > 3 {
		util.Log(ctx).Error("verification code verification failed after too many attempts")
		return h.showVerificationPage(rw, req, loginEventID, profileName, "Too many failed attempts")
	}

	if !verifyResp.Msg.GetSuccess() {
		util.Log(ctx).Error("verification code verification returned false")
		return h.showVerificationPage(rw, req, loginEventID, profileName, "Invalid verification code")
	}

	var profileObj *profilev1.ProfileObject
	resp, err := h.profileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{Contact: loginEvent.ContactID}))
	if err == nil {
		profileObj = resp.Msg.GetData()
	} else {
		// Check if it's a "not found" error, which is expected for new users
		if frame.ErrorIsNotFound(err) {
			// Profile not found - this is expected for new users, we'll create one below
		} else {
			// Unexpected error occurred
			util.Log(ctx).WithError(err).Error("failed to get profile by contact")
			return err
		}
	}

	if profileObj == nil {

		properties, _ := structpb.NewStruct(map[string]any{
			KeyProfileName: profileName,
		})

		res, err0 := h.profileCli.Create(ctx, connect.NewRequest(&profilev1.CreateRequest{
			Type:       profilev1.ProfileType_PERSON,
			Contact:    loginEvent.ContactID,
			Properties: properties,
		}))
		if err0 != nil {
			util.Log(ctx).WithError(err0).Error("failed to create new profile by contact & name")
			return err0
		}

		profileObj = res.Msg.GetData()
	}

	// Complete OAuth2 login flow using login_challenge from loginEvent
	loginChallenge := loginEvent.LoginChallengeID

	hydraCli := h.defaultHydraCli
	params := &hydra.AcceptLoginRequestParams{
		LoginChallenge:   loginChallenge,
		SubjectID:        profileObj.GetId(),
		Remember:         true,
		RememberDuration: h.config.SessionRememberDuration,
	}

	redirectUrl, err := hydraCli.AcceptLoginRequest(ctx, params, "third party")
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to accept login request")
		return h.showVerificationPage(rw, req, loginEventID, profileName, "Login completion failed")
	}

	// Redirect to complete OAuth2 flow
	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)
	return nil
}
