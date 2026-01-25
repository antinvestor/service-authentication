package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

// Verification flow error definitions
var (
	ErrContactRequired          = errors.New("contact is required")
	ErrVerificationCodeRequired = errors.New("verification code is required")
	ErrVerificationFailed       = errors.New("verification failed")
	ErrTooManyAttempts          = errors.New("too many verification attempts")
	ErrProfileCreationFailed    = errors.New("failed to create profile")
)

const (
	KeyProfileName        = "au_name"
	pathValueLoginEventID = "loginEventId"
)

func (h *AuthServer) ShowVerificationEndpoint(rw http.ResponseWriter, req *http.Request) error {

	loginEventID := req.PathValue(pathValueLoginEventID)
	profileName := req.FormValue("profile_name")
	contactType := req.FormValue("contact_type")
	errorMsg := req.FormValue("error")

	payload := initTemplatePayload(req.Context())
	payload["login_event_id"] = loginEventID
	payload["profile_name"] = profileName
	payload["contact_type"] = contactType

	if errorMsg != "" {
		payload["error"] = errorMsg
	}

	err := verifyContactTmpl.Execute(rw, payload)
	if err != nil {
		return err
	}

	return nil

}

// SubmitVerificationEndpoint handles both contact submission and verification code submission.
// For contact submission: creates verification and sends code to user's contact.
// For code submission: validates code and completes the login flow.
func (h *AuthServer) SubmitVerificationEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx)

	loginEventID := req.PathValue(pathValueLoginEventID)
	verificationCode := req.FormValue("verification_code")
	profileName := req.FormValue("profile_name")

	log = log.WithField("login_event_id", loginEventID)

	// Step 1: Retrieve login event from cache
	loginEvt, err := h.getLoginEventFromCache(ctx, loginEventID)
	if err != nil {
		log.WithError(err).Error("cache lookup failed for login event")
		return err
	}
	ctx = util.SetTenancy(ctx, loginEvt)

	// Step 2: Route to appropriate handler based on request type
	if verificationCode != "" {
		log.Debug("handling verification code submission")
		return h.handleVerificationCodeSubmission(rw, req, loginEventID, profileName, verificationCode)
	}

	// Step 3: Handle contact submission
	contact := req.FormValue("contact")
	if contact == "" {
		log.Warn("contact submission missing contact value")
		return h.showVerificationPage(rw, req, loginEventID, profileName, "", "Contact is required")
	}

	log = log.WithField("contact_prefix", contact[:min(3, len(contact))]+"***")
	internalRedirectLinkToSignIn := "/s/login?login_challenge=" + url.QueryEscape(loginEvt.LoginChallengeID)

	// Step 4: Look up or create profile for contact
	var existingProfile *profilev1.ProfileObject
	var contactID string
	var contactType profilev1.ContactType

	result, err := h.profileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{Contact: contact}))
	if err != nil && !frame.ErrorIsNotFound(err) {
		log.WithError(err).Error("profile lookup failed")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return nil
	}

	if result != nil {
		existingProfile = result.Msg.GetData()
		if existingProfile != nil {
			// Find matching contact ID
			for _, profileContact := range existingProfile.GetContacts() {
				if strings.EqualFold(contact, profileContact.GetDetail()) {
					contactID = profileContact.GetId()
					contactType = profileContact.GetType()
					break
				}
			}
		}
	}

	// Step 5: Create contact if not found
	if contactID == "" {
		contactResp, createErr := h.profileCli.CreateContact(ctx, connect.NewRequest(&profilev1.CreateContactRequest{
			Contact: contact,
		}))
		if createErr != nil {
			log.WithError(createErr).Error("failed to create contact")
			http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
			return nil
		}
		contactID = contactResp.Msg.GetData().GetId()
		contactType = contactResp.Msg.GetData().GetType()
		log.WithField("contact_id", contactID).Debug("new contact created")
	}

	// Step 6: Store login attempt
	verificationID := util.IDString()
	profileID := ""
	if existingProfile != nil {
		profileID = existingProfile.GetId()
	}

	loginEvent, err := h.storeLoginAttempt(ctx, loginEvt, models.LoginSourceDirect, profileID, contactID, verificationID, nil)
	if err != nil {
		log.WithError(err).Error("failed to store login attempt")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return err
	}

	// Step 7: Create verification and send code
	ctx = util.SetTenancy(ctx, loginEvt)
	_, err = h.profileCli.CreateContactVerification(ctx, connect.NewRequest(&profilev1.CreateContactVerificationRequest{
		Id:               verificationID,
		ContactId:        contactID,
		DurationToExpire: "15m",
	}))
	if err != nil {
		log.WithError(err).Error("failed to create contact verification")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return err
	}

	// Step 8: Extract profile name and show verification page
	if existingProfile != nil {
		var properties data.JSONMap
		properties = properties.FromProtoStruct(existingProfile.GetProperties())
		if name := properties.GetString(KeyProfileName); name != "" {
			profileName = name
		}
	}

	log.WithFields(map[string]any{
		"verification_id": verificationID,
		"contact_type":    contactType.String(),
		"duration_ms":     time.Since(start).Milliseconds(),
	}).Info("verification code sent")

	return h.showVerificationPage(rw, req, loginEvent.GetID(), profileName, contactType.String(), "")
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
func (h *AuthServer) showVerificationPage(rw http.ResponseWriter, req *http.Request, loginEventID, profileName, contactType, errorMsg string) error {

	verificationPage := fmt.Sprintf("/s/verify/contact/%s?login_event_id=%s", loginEventID, loginEventID)

	if profileName != "" {
		verificationPage = fmt.Sprintf("%s&profile_name=%s", verificationPage, url.QueryEscape(profileName))
	}

	if contactType != "" {
		verificationPage = fmt.Sprintf("%s&contact_type=%s", verificationPage, url.QueryEscape(contactType))
	}

	if errorMsg != "" {
		verificationPage = fmt.Sprintf("%s&error=%s", verificationPage, url.QueryEscape(errorMsg))
	}

	http.Redirect(rw, req, verificationPage, http.StatusSeeOther)
	return nil
}

// handleVerificationCodeSubmission processes verification code submission and completes the login flow.
func (h *AuthServer) handleVerificationCodeSubmission(rw http.ResponseWriter, req *http.Request, loginEventID, profileName, verificationCode string) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx).WithField("login_event_id", loginEventID)
	contactType := req.FormValue("contact_type")

	// Step 1: Get login event from database
	loginEvent, err := h.loginEventRepo.GetByID(ctx, loginEventID)
	if err != nil {
		log.WithError(err).Error("login event not found in database")
		return h.showVerificationPage(rw, req, loginEventID, profileName, contactType, "Session not found. Please start again.")
	}

	log = log.WithField("verification_id", loginEvent.VerificationID)

	// Step 2: Verify the code with profile service
	verifyResp, err := h.profileCli.CheckVerification(ctx, connect.NewRequest(&profilev1.CheckVerificationRequest{
		Id:   loginEvent.VerificationID,
		Code: verificationCode,
	}))
	if err != nil {
		log.WithError(err).Error("verification service call failed")
		return h.showVerificationPage(rw, req, loginEventID, profileName, contactType, "Verification failed. Please try again.")
	}

	attempts := verifyResp.Msg.GetCheckAttempts()
	maxAttempts := int32(h.config.AuthProviderContactLoginMaxVerificationAttempts)
	if maxAttempts == 0 {
		maxAttempts = 3 // Default fallback
	}

	if attempts > maxAttempts {
		log.WithFields(map[string]any{
			"attempts":     attempts,
			"max_attempts": maxAttempts,
		}).Warn("verification attempts exceeded")
		return h.showVerificationPage(rw, req, loginEventID, profileName, contactType, "Too many failed attempts. Please request a new code.")
	}

	if !verifyResp.Msg.GetSuccess() {
		log.WithField("attempts", attempts).Debug("verification code incorrect")
		return h.showVerificationPage(rw, req, loginEventID, profileName, contactType, "Invalid verification code")
	}

	log.Debug("verification code validated successfully")

	// Step 3: Get or create profile
	var profileObj *profilev1.ProfileObject
	resp, err := h.profileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{Contact: loginEvent.ContactID}))
	if err == nil {
		profileObj = resp.Msg.GetData()
	} else if !frame.ErrorIsNotFound(err) {
		log.WithError(err).Error("profile lookup failed")
		return err
	}

	if profileObj == nil {
		log.Debug("creating new profile for contact")
		properties, _ := structpb.NewStruct(map[string]any{
			KeyProfileName: profileName,
		})

		res, createErr := h.profileCli.Create(ctx, connect.NewRequest(&profilev1.CreateRequest{
			Type:       profilev1.ProfileType_PERSON,
			Contact:    loginEvent.ContactID,
			Properties: properties,
		}))
		if createErr != nil {
			log.WithError(createErr).Error("profile creation failed")
			return fmt.Errorf("%w: %v", ErrProfileCreationFailed, createErr)
		}
		profileObj = res.Msg.GetData()
		log.WithField("profile_id", profileObj.GetId()).Info("new profile created")
	}

	// Step 4: Complete OAuth2 login flow
	params := &hydra.AcceptLoginRequestParams{
		LoginChallenge:   loginEvent.LoginChallengeID,
		SubjectID:        profileObj.GetId(),
		Remember:         true,
		RememberDuration: h.config.SessionRememberDuration,
	}

	redirectURL, err := h.defaultHydraCli.AcceptLoginRequest(ctx, params, "contact_verification")
	if err != nil {
		log.WithError(err).Error("hydra accept login request failed")
		return h.showVerificationPage(rw, req, loginEventID, profileName, contactType, "Login completion failed. Please try again.")
	}

	log.WithFields(map[string]any{
		"profile_id":  profileObj.GetId(),
		"duration_ms": time.Since(start).Milliseconds(),
	}).Info("login completed successfully")

	http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
	return nil
}
