package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/gorilla/csrf"
	"github.com/pitabwire/frame"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const KeyProfileName = "au_name"

func (h *AuthServer) ShowVerificationEndpoint(rw http.ResponseWriter, req *http.Request) error {

	loginEventID := req.FormValue("login_event_id")
	profileName := req.FormValue("profile_name")
	errorMsg := req.FormValue("error")

	payload := initTemplatePayload(req.Context())
	payload["login_event_id"] = loginEventID
	payload["profile_name"] = profileName
	payload[csrf.TemplateTag] = csrf.TemplateField(req)

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
	svc := h.service
	logger := svc.Log(ctx).WithField("endpoint", "SubmitVerificationEndpoint")

	// Check if this is verification code submission or contact submission
	verificationCode := req.FormValue("verification_code")
	loginEventID := req.FormValue("login_event_id")
	profileName := req.FormValue("profile_name")

	logger.WithField("verification_code", verificationCode != "").WithField("login_event_id", loginEventID).WithField("profile_name", profileName).Info("DEBUG: Checking submission type")

	// If verification code is provided, handle verification code submission
	if verificationCode != "" && loginEventID != "" {
		logger.Info("DEBUG: Processing verification code submission")
		return h.handleVerificationCodeSubmission(rw, req, loginEventID, profileName, verificationCode)
	}

	// Otherwise, handle contact submission (original logic)
	logger.Info("DEBUG: Processing contact submission")
	contact := req.PostForm.Get("contact")
	logger.WithField("contact", contact).WithField("contact_length", len(contact)).Info("DEBUG: Received contact parameter from PostForm")

	// Also check FormValue as fallback
	contactFormValue := req.FormValue("contact")
	logger.WithField("contact_form_value", contactFormValue).WithField("form_value_length", len(contactFormValue)).Info("DEBUG: Contact from FormValue")

	// Use FormValue if PostForm is empty
	if contact == "" && contactFormValue != "" {
		contact = contactFormValue
		logger.Info("DEBUG: Using contact from FormValue instead of PostForm")
	}
	// Retrieve loginChallenge from session instead of form values
	session, err := h.getLogginSession().Get(req, SessionKeyLoginStorageName)
	if err != nil {
		logger.WithError(err).Error("failed to get session")
		http.Redirect(rw, req, "/error", http.StatusSeeOther)
		return err
	}

	// Debug: Log all session values to understand what's in the session
	logger.WithField("session_values", session.Values).Info("DEBUG: Retrieved session values")
	logger.WithField("session_id", session.ID).Info("DEBUG: Session ID")

	loginChallenge, ok := session.Values[SessionKeyLoginChallenge].(string)
	if !ok || loginChallenge == "" {
		logger.WithField("session_values", session.Values).Error("login_challenge not found in session - dumping session contents")
		http.Redirect(rw, req, "/error?error=login_challenge_not_found&error_description=Ensure that cookie storage works with your browser for continuity", http.StatusSeeOther)
		return fmt.Errorf("login_challenge not found in session")
	}

	clientID, ok := session.Values[SessionKeyClientID].(string)
	if !ok || clientID == "" {
		logger.Error("clientID not found in session")
		http.Redirect(rw, req, "/error?error=client_id_not_found&error_description=Ensure that cookie storage works with your browser for continuity", http.StatusSeeOther)
		return fmt.Errorf("client id not found in session")
	}

	internalRedirectLinkToSignIn := fmt.Sprintf("/s/login?login_challenge=%s", loginChallenge)

	existingProfile, err := h.profileCli.GetProfileByContact(ctx, contact)
	if err != nil {
		st, errOk := status.FromError(err)
		if !errOk || st.Code() != codes.NotFound {
			logger.WithError(err).Error("DEBUG: failed to get profile - redirecting to login")
			http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)

			return nil
		}
		logger.Info("DEBUG: Profile not found (NotFound error) - will create new contact")
	} else {
		logger.WithField("profile_id", existingProfile.GetId()).Info("DEBUG: Found existing profile")
	}

	contactID := ""
	if existingProfile != nil {
		for _, profileContact := range existingProfile.GetContacts() {
			if strings.EqualFold(contact, profileContact.GetDetail()) {
				contactID = profileContact.GetId()
			}
		}
	}

	if contactID == "" {

		// don't have this contact in existence so we create it
		contactResp, err0 := h.profileCli.Svc().CreateContact(ctx, &profilev1.CreateContactRequest{
			Contact: contact,
		})
		if err0 != nil {
			logger.WithError(err0).Error(" could not create/find existing contact")
			http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)

			return nil
		}

		contactID = contactResp.GetData().GetId()
	}

	logger.WithField("contact_id", contactID).Info("DEBUG: Creating contact verification")

	// Generate a verification ID that matches the required pattern [0-9a-z_-]{3,20}
	verificationID := fmt.Sprintf("ver_%d", time.Now().Unix()%1000000)
	logger.WithField("verification_id", verificationID).Info("DEBUG: Generated verification ID")

	resp, err := h.profileCli.Svc().CreateContactVerification(ctx, &profilev1.CreateContactVerificationRequest{
		Id:               verificationID,
		ContactId:        contactID,
		DurationToExpire: "15m",
	})
	if err != nil {
		logger.WithError(err).Error("DEBUG: could not create contact verification - redirecting to login")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)

		return err
	}
	logger.WithField("verification_id", resp.GetId()).Info("DEBUG: Successfully created contact verification")

	logger.Info("DEBUG: Storing login attempt")
	loginEvent, err := h.storeLoginAttempt(ctx, clientID, models.LoginSourceDirect, existingProfile.GetId(), contactID, resp.GetId(), loginChallenge, nil)
	if err != nil {
		logger.WithError(err).Error("DEBUG: could not store login attempt - redirecting to login")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)

		return err
	}
	logger.WithField("login_event_id", loginEvent.GetID()).Info("DEBUG: Successfully stored login attempt")

	// Extract profile name from properties or use a default
	profileName = existingProfile.GetProperties()[KeyProfileName]
	logger.WithField("profile_name", profileName).Info("DEBUG: Using profile name")

	return h.showVerificationPage(rw, req, loginEvent.GetID(), profileName, "")
}

func (h *AuthServer) storeLoginAttempt(ctx context.Context, clientID string, source models.LoginSource, profileID, contactID string, verificationID string, loginChallenge string, extra map[string]any) (*models.LoginEvent, error) {

	deviceSessionID := utils.SessionIDFromContext(ctx)

	partitionObj, err := h.partitionCli.GetPartition(ctx, clientID)
	if err != nil {
		return nil, err
	}

	login, err := h.loginRepo.GetByProfileID(ctx, profileID)
	if err != nil {

		if !frame.ErrorIsNoRows(err) {
			return nil, err
		}

		login = &models.Login{
			ProfileID: profileID,
			Source:    string(source),
		}
		login.GenID(ctx)
		login.PartitionID = partitionObj.GetId()
		login.TenantID = partitionObj.GetTenantId()
		err = h.loginRepo.Save(ctx, login)
		if err != nil {
			return nil, err
		}
	}

	loginEvt := &models.LoginEvent{
		LoginID:          login.GetID(),
		LoginChallengeID: loginChallenge,
		VerificationID:   verificationID,
		AccessID:         "",
		ContactID:        contactID,
	}
	loginEvt.Properties = extra
	loginEvt.PartitionID = partitionObj.GetId()
	loginEvt.TenantID = partitionObj.GetTenantId()
	loginEvt.ID = deviceSessionID

	err = h.loginEventRepo.Save(ctx, loginEvt)
	if err != nil {
		return nil, err
	}

	return loginEvt, nil
}

// showVerificationPage displays the login form with an error message
func (h *AuthServer) showVerificationPage(rw http.ResponseWriter, req *http.Request, loginEventID, profileName, errorMsg string) error {

	verificationPage := fmt.Sprintf("/s/verify/contact?login_event_id=%s", loginEventID)

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
	svc := h.service
	logger := svc.Log(ctx).WithField("endpoint", "handleVerificationCodeSubmission")

	logger.WithField("login_event_id", loginEventID).
		WithField("profile_name", profileName).
		WithField("verification_code", verificationCode).Info("DEBUG: Processing verification code submission")

	// Get login event to retrieve contact information and login challenge
	loginEvent, err := h.loginEventRepo.GetByID(ctx, loginEventID)
	if err != nil {
		logger.WithError(err).Error("failed to get login event")
		return h.showVerificationPage(rw, req, loginEventID, profileName, "Login event not found")
	}

	// Verify the verification code with profile service
	verifyReq := &profilev1.CheckVerificationRequest{
		Id:   loginEvent.VerificationID,
		Code: verificationCode,
	}

	logger.WithField("verification_id", loginEvent.VerificationID).WithField("verification_code", verificationCode).Info("DEBUG: Calling CheckVerification")

	verifyResp, err := h.profileCli.Svc().CheckVerification(ctx, verifyReq)
	if err != nil {
		logger.WithError(err).Error("verification code verification failed")
		return h.showVerificationPage(rw, req, loginEventID, profileName, "Invalid verification code")
	}

	if !verifyResp.GetSuccess() {
		logger.Error("verification code verification returned false")
		return h.showVerificationPage(rw, req, loginEventID, profileName, "Invalid verification code")
	}

	logger.Info("DEBUG: Verification code verified successfully")

	var profileObj *profilev1.ProfileObject
	resp, err := h.profileCli.Svc().GetByContact(ctx, &profilev1.GetByContactRequest{Contact: loginEvent.ContactID})
	if err == nil {
		profileObj = resp.GetData()
	}

	st, errOk := status.FromError(err)
	if !errOk || st.Code() != codes.NotFound {
		logger.WithError(err).Error("DEBUG: failed to get profile by contact")
		return err
	}

	if profileObj == nil {

		res, err0 := h.profileCli.Svc().Create(ctx, &profilev1.CreateRequest{
			Type:       profilev1.ProfileType_PERSON,
			Contact:    loginEvent.ContactID,
			Properties: map[string]string{KeyProfileName: profileName},
		})
		if err0 != nil {
			logger.WithError(err0).Error("DEBUG: failed to create new profile by contact & name")
			return err0
		}

		profileObj = res.GetData()
	}

	// Complete OAuth2 login flow using login_challenge from loginEvent
	loginChallenge := loginEvent.LoginChallengeID
	logger.WithField("login_challenge_from_event", loginChallenge).Info("DEBUG: Retrieved login_challenge from loginEvent")

	defaultHydra := hydra.NewDefaultHydra(h.config.GetOauth2ServiceAdminURI())
	params := &hydra.AcceptLoginRequestParams{
		LoginChallenge:   loginChallenge,
		SubjectID:        profileObj.GetId(),
		Remember:         true,
		RememberDuration: h.config.SessionRememberDuration,
	}

	logger.WithField("subject", loginEvent.AccessID).WithField("login_challenge", loginChallenge).Info("DEBUG: Accepting login request")

	redirectUrl, err := defaultHydra.AcceptLoginRequest(ctx, params)
	if err != nil {
		logger.WithError(err).Error("failed to accept login request")
		return h.showVerificationPage(rw, req, loginEventID, profileName, "Login completion failed")
	}

	logger.WithField("redirect_to", redirectUrl).Info("DEBUG: Login accepted, redirecting to OAuth2 flow")

	// Redirect to complete OAuth2 flow
	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)
	return nil
}
