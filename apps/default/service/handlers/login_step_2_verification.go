package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pitabwire/util"
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
	ctx := req.Context()

	loginEventID := req.PathValue(pathValueLoginEventID)
	profileName := req.FormValue("profile_name")
	contactType := req.FormValue("contact_type")
	errorMsg := req.FormValue("error")

	// Validate login event exists (either in cache or database)
	if loginEventID != "" {
		_, err := h.getLoginEventFromCache(ctx, loginEventID)
		if err != nil {
			// Try database as fallback
			_, dbErr := h.loginEventRepo.GetByID(ctx, loginEventID)
			if dbErr != nil {
				http.Redirect(rw, req, "/error?error=session_expired", http.StatusSeeOther)
				return nil
			}
		}
	}

	payload := initTemplatePayload(ctx)
	payload["login_event_id"] = loginEventID
	payload["profile_name"] = profileName
	payload["contact_type"] = contactType

	if errorMsg != "" {
		payload["error"] = errorMsg
	}

	return verifyContactTmpl.Execute(rw, payload)
}

// showVerificationPage redirects to the verification form with optional error message
func (h *AuthServer) showVerificationPage(rw http.ResponseWriter, req *http.Request, loginEventID, profileName, contactType, errorMsg string) error {
	// Build query parameters using url.Values for proper encoding
	params := url.Values{}
	params.Set("login_event_id", loginEventID)

	if profileName != "" {
		params.Set("profile_name", profileName)
	}
	if contactType != "" {
		params.Set("contact_type", contactType)
	}
	if errorMsg != "" {
		params.Set("error", errorMsg)
	}

	verificationPage := fmt.Sprintf("/s/verify/contact/%s?%s", url.PathEscape(loginEventID), params.Encode())

	log := util.Log(req.Context())
	log.WithField("redirect_url", verificationPage).Info("Redirecting to :", verificationPage)

	http.Redirect(rw, req, verificationPage, http.StatusSeeOther)
	return nil
}
