package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

// Login submission error definitions
var (
	ErrLoginLocked                  = errors.New("login is locked")
	ErrVerificationAttemptsExceeded = errors.New("verification attempts exceeded")
	ErrVerificationCodeIncorrect    = errors.New("verification code is incorrect")
)

// VerificationEndpointSubmit handles the final login submission of verification results.
// This is called after the user has verified their contact via code.
func (h *AuthServer) VerificationEndpointSubmit(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx)

	// Step 1: Get loginEventID from URL path (primary) with form fallback
	loginEventID := req.PathValue(pathValueLoginEventID)
	if loginEventID == "" {
		// Fallback to form data for backwards compatibility
		if err := req.ParseForm(); err != nil {
			log.WithError(err).Error("failed to parse form data")
			return fmt.Errorf("failed to parse form: %w", err)
		}
		loginEventID = req.PostForm.Get("login_event_id")
	}

	if loginEventID == "" {
		log.Warn("login submission missing login_event_id")
		http.Redirect(rw, req, "/error?error=missing_login_event_id", http.StatusSeeOther)
		return nil
	}

	// Step 2: Parse remaining form data
	if err := req.ParseForm(); err != nil {
		log.WithError(err).Error("failed to parse form data")
		return fmt.Errorf("failed to parse form: %w", err)
	}

	profileName := req.PostForm.Get("profile_name")
	verificationCode := strings.TrimSpace(req.PostForm.Get("verification_code"))
	contactType := req.PostForm.Get("contact_type")

	log = log.WithField("login_event_id", loginEventID)
	log.WithField("code_length", len(verificationCode)).Debug("verification code received")

	// Step 3: Retrieve login event from database
	loginEvent, err := h.loginEventRepo.GetByID(ctx, loginEventID)
	if err != nil {
		if data.ErrorIsNoRows(err) {
			log.Warn("login event not found")
			http.Redirect(rw, req, "/not-found", http.StatusSeeOther)
			return nil
		}
		log.WithError(err).Error("failed to retrieve login event")
		return err
	}

	// Step 3.5: Set tenancy context for profile service calls
	ctx = util.SetTenancy(ctx, loginEvent)

	// Step 4: Verify the login credentials
	profileID, err := h.verifyProfileLogin(ctx, loginEvent, verificationCode)
	if err != nil {
		log.WithError(err).Debug("login verification failed")
		return h.showVerificationPage(rw, req, loginEventID, profileName, contactType, err.Error())
	}

	// Step 5: Validate profile ID before proceeding
	if profileID == "" {
		log.Error("profile ID is empty after verification - cannot complete login")
		return h.showVerificationPage(rw, req, loginEventID, profileName, contactType, "Login failed. Please try again.")
	}

	// Step 6: Update profile name if provided
	if profileName != "" {
		_, err = h.updateProfileName(ctx, profileID, profileName)
		if err != nil {
			log.WithError(err).Error("failed to update profile name")
			return err
		}
	}

	// Step 7: Complete OAuth2 login flow
	params := &hydra.AcceptLoginRequestParams{
		LoginChallenge: loginEvent.LoginChallengeID,
		SubjectID:      profileID,
		SessionID:      loginEvent.ID,

		ExtendSession:    true,
		Remember:         true,
		RememberDuration: h.config.SessionRememberDuration,
	}

	loginContext := map[string]any{
		"login_event_id": loginEvent.GetID(),
	}

	redirectURL, err := h.defaultHydraCli.AcceptLoginRequest(ctx, params, loginContext, "2_factor", loginEvent.ContactID)
	if err != nil {
		log.WithError(err).Error("hydra accept login request failed")
		return err
	}

	log.WithFields(map[string]any{
		"profile_id":  profileID,
		"duration_ms": time.Since(start).Milliseconds(),
	}).Info("login submission completed successfully")

	http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
	return nil
}

func (h *AuthServer) updateProfileName(ctx context.Context, profileID string, profileName string) (*profilev1.ProfileObject, error) {

	props, _ := structpb.NewStruct(map[string]any{KeyProfileName: profileName})

	response, err := h.profileCli.Update(ctx, connect.NewRequest(&profilev1.UpdateRequest{
		Id:         profileID,
		Properties: props,
	}))

	if err != nil {
		return nil, err
	}

	return response.Msg.GetData(), nil

}

// verifyProfileLogin verifies the login credentials and returns the profile ID.
// For direct logins, it validates the verification code. For provider logins, it returns immediately.
func (h *AuthServer) verifyProfileLogin(ctx context.Context, event *models.LoginEvent, code string) (string, error) {
	log := util.Log(ctx).WithFields(map[string]any{
		"login_event_id": event.GetID(),
		"login_id":       event.LoginID,
	})

	// Step 1: Get login record
	login, err := h.loginRepo.GetByID(ctx, event.LoginID)
	if err != nil {
		log.WithError(err).Error("failed to retrieve login record")
		return "", fmt.Errorf("failed to get login: %w", err)
	}

	// Step 2: Check if login is locked
	if !login.Locked.IsZero() {
		log.WithField("locked_at", login.Locked).Warn("login is locked")
		return "", ErrLoginLocked
	}

	// Step 3: For provider logins (no verification ID on the event), skip code verification.
	// The verification ID is only set for direct (contact-based) login flows.
	if event.VerificationID == "" {
		log.WithField("source", login.Source).Debug("provider login - skipping verification")
		return login.ProfileID, nil
	}

	// Step 4: Verify the code for direct logins
	log.WithFields(map[string]any{
		"verification_id": event.VerificationID,
		"code_length":     len(code),
	}).Debug("checking verification code")

	resp, err := h.profileCli.CheckVerification(ctx, connect.NewRequest(&profilev1.CheckVerificationRequest{
		Id:   event.VerificationID,
		Code: code,
	}))
	if err != nil {
		log.WithError(err).Error("verification service call failed")
		return "", fmt.Errorf("verification failed: %w", err)
	}

	maxAttempts := h.config.AuthProviderContactLoginMaxVerificationAttempts
	if maxAttempts == 0 {
		maxAttempts = 3 // Default fallback
	}

	attempts := int(resp.Msg.GetCheckAttempts())
	if attempts > maxAttempts {
		log.WithFields(map[string]any{
			"attempts":     attempts,
			"max_attempts": maxAttempts,
		}).Warn("verification attempts exceeded")
		return "", ErrVerificationAttemptsExceeded
	}

	if !resp.Msg.GetSuccess() {
		log.WithField("attempts", attempts).Debug("verification code incorrect")
		return "", ErrVerificationCodeIncorrect
	}

	// Step 5: Create profile if needed (first-time login)
	if login.ProfileID == "" {
		log.Debug("creating profile for first-time login")
		properties, _ := structpb.NewStruct(map[string]any{"src": "direct"})

		results, createErr := h.profileCli.Create(ctx, connect.NewRequest(&profilev1.CreateRequest{
			Type:       profilev1.ProfileType_PERSON,
			Contact:    event.ContactID,
			Properties: properties,
		}))
		if createErr != nil {
			log.WithError(createErr).Error("failed to create profile")
			return "", fmt.Errorf("failed to create profile: %w", createErr)
		}

		createdProfile := results.Msg.GetData()
		if createdProfile == nil || createdProfile.GetId() == "" {
			log.Error("profile service returned invalid profile after creation")
			return "", fmt.Errorf("profile creation returned invalid response")
		}
		login.ProfileID = createdProfile.GetId()
		if _, updateErr := h.loginRepo.Update(ctx, login, "profile_id"); updateErr != nil {
			log.WithError(updateErr).Error("failed to update login with profile_id")
			return "", fmt.Errorf("failed to update login: %w", updateErr)
		}

		log.WithField("profile_id", login.ProfileID).Info("profile created for first-time login")
	}

	return login.ProfileID, nil
}
