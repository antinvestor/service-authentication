package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

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

	// Default resend values
	initialCooldown := 30 // seconds
	resendsLeft := 3

	// Validate login event exists and get resend info
	if loginEventID != "" {
		loginEvent, err := h.getLoginEventFromCache(ctx, loginEventID)
		if err != nil {
			// Try database as fallback
			loginEvent, err = h.loginEventRepo.GetByID(ctx, loginEventID)
			if err != nil {
				http.Redirect(rw, req, "/error?error=session_expired", http.StatusSeeOther)
				return nil
			}
		}

		// Calculate resends left from login event properties
		if loginEvent != nil && loginEvent.Properties != nil {
			resendCount := getResendCount(loginEvent.Properties)
			resendsLeft = maxResendAttempts - resendCount
			if resendsLeft < 0 {
				resendsLeft = 0
			}

			// If there have been resends, adjust initial cooldown based on last resend
			if resendCount > 0 {
				lastResendAt := getLastResendAt(loginEvent.Properties)
				if !lastResendAt.IsZero() {
					waitDuration := resendWaitDurations[min(resendCount-1, len(resendWaitDurations)-1)]
					nextAllowedTime := lastResendAt.Add(waitDuration)
					if nextAllowedTime.After(time.Now()) {
						initialCooldown = int(time.Until(nextAllowedTime).Seconds())
					} else {
						initialCooldown = 0 // Can resend immediately
					}
				}
			}
		}
	}

	payload := initTemplatePayload(ctx)
	payload["login_event_id"] = loginEventID
	payload["profile_name"] = profileName
	payload["contact_type"] = contactType
	payload["initial_cooldown"] = initialCooldown
	payload["resends_left"] = resendsLeft

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
