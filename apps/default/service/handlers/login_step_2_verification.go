package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

func (h *AuthServer) VerificationEndpointShow(rw http.ResponseWriter, req *http.Request) error {

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
