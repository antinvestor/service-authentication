package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

// SubmitLoginEndpoint handles the final login submission after verification.
// This is called after the user has verified their contact via code.
func (h *AuthServer) SubmitLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx)

	// Step 1: Parse form data
	if err := req.ParseForm(); err != nil {
		log.WithError(err).Error("failed to parse form data")
		return fmt.Errorf("failed to parse form: %w", err)
	}

	profileName := req.PostForm.Get("profile_name")
	verificationCode := req.PostForm.Get("verification_code")
	loginEventID := req.PostForm.Get("login_event_id")
	contactType := req.PostForm.Get("contact_type")

	if loginEventID == "" {
		log.Warn("login submission missing login_event_id")
		http.Redirect(rw, req, "/error?error=missing_login_event_id", http.StatusSeeOther)
		return nil
	}

	log = log.WithField("login_event_id", loginEventID)

	// Step 2: Retrieve login event from database
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

	// Step 3: Verify the login credentials
	profileID, err := h.verifyProfileLogin(ctx, loginEvent, verificationCode)
	if err != nil {
		log.WithError(err).Debug("login verification failed")
		return h.showVerificationPage(rw, req, loginEventID, profileName, contactType, err.Error())
	}

	// Step 4: Update profile name if provided
	profileObj, err := h.updateProfileName(ctx, profileID, profileName)
	if err != nil {
		log.WithError(err).Error("failed to update profile name")
		return err
	}

	// Step 5: Complete OAuth2 login flow
	params := &hydra.AcceptLoginRequestParams{
		LoginChallenge:   loginEvent.LoginChallengeID,
		SubjectID:        profileObj.GetId(),
		SessionID:        loginEvent.ID,
		ExtendSession:    true,
		Remember:         true,
		RememberDuration: h.config.SessionRememberDuration,
	}

	redirectURL, err := h.defaultHydraCli.AcceptLoginRequest(ctx, params, "2_factor", loginEvent.ContactID)
	if err != nil {
		log.WithError(err).Error("hydra accept login request failed")
		return err
	}

	log.WithFields(map[string]any{
		"profile_id":  profileObj.GetId(),
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

	// Step 3: For non-direct logins (providers), skip verification
	if models.LoginSource(login.Source) != models.LoginSourceDirect {
		log.WithField("source", login.Source).Debug("provider login - skipping verification")
		return login.ProfileID, nil
	}

	// Step 4: Verify the code for direct logins
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

		login.ProfileID = results.Msg.GetData().GetId()
		if _, updateErr := h.loginRepo.Update(ctx, login, "profile_id"); updateErr != nil {
			log.WithError(updateErr).Error("failed to update login with profile_id")
			return "", fmt.Errorf("failed to update login: %w", updateErr)
		}

		log.WithField("profile_id", login.ProfileID).Info("profile created for first-time login")
	}

	return login.ProfileID, nil
}
