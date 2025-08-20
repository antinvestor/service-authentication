package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	profilev1 "github.com/antinvestor/apis/go/profile/v1"
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

	contact := req.PostForm.Get("contact")
	// Retrieve loginChallenge from session instead of form values
	session, err := h.getLogginSession().Get(req, SessionKeyLoginStorageName)
	if err != nil {
		logger.WithError(err).Error("failed to get session")
		http.Redirect(rw, req, "/error", http.StatusSeeOther)
		return err
	}

	loginChallenge, ok := session.Values[SessionKeyLoginChallenge].(string)
	if !ok || loginChallenge == "" {
		logger.Error("login_challenge not found in session")
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
			logger.WithError(err).Error("failed to get profile")
			http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)

			return nil
		}
	}

	contactID := ""
	if existingProfile == nil {

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

	resp, err := h.profileCli.Svc().CreateContactVerification(ctx, &profilev1.CreateContactVerificationRequest{
		ContactId:        contactID,
		DurationToExpire: "15m",
	})
	if err != nil {
		logger.WithError(err).Error(" contact not linked to profile found")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)

		return err
	}

	loginEvent, err := h.storeLoginAttempt(ctx, clientID, models.LoginSourceDirect, existingProfile.GetId(), contactID, resp.GetId(), loginChallenge, nil)
	if err != nil {

		logger.WithError(err).Error(" contact not log login attempt")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)

		return err
	}

	profileName := strings.Join([]string{existingProfile.GetProperties()[KeyProfileName]}, " ")

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

	verificationPage := fmt.Sprintf("/s/verify/contact?login_event_id=%s&profile_name=%s", loginEventID, profileName)

	if errorMsg != "" {
		verificationPage = fmt.Sprintf("%s&error=%s", verificationPage, errorMsg)
	}

	http.Redirect(rw, req, verificationPage, http.StatusSeeOther)
	return nil
}
