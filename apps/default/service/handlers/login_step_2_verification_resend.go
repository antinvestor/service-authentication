package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/util"
)

// Resend verification error definitions
var (
	ErrMaxResendsExceeded = errors.New("maximum resend attempts exceeded")
	ErrResendTooSoon      = errors.New("please wait before requesting another code")
)

const (
	maxResendAttempts   = 3
	propKeyResendCount  = "resend_count"
	propKeyLastResendAt = "last_resend_at"
)

// resendWaitDurations defines the wait time required before each resend attempt.
// Index 0 = wait time before 1st resend, Index 1 = before 2nd resend, etc.
var resendWaitDurations = []time.Duration{
	30 * time.Second,  // Wait 30s before 1st resend
	60 * time.Second,  // Wait 60s before 2nd resend
	120 * time.Second, // Wait 120s before 3rd resend
}

// ResendVerificationResponse is the JSON response for the resend endpoint.
type ResendVerificationResponse struct {
	Success         bool   `json:"success"`
	Message         string `json:"message,omitempty"`
	ResendsLeft     int    `json:"resends_left"`
	WaitSeconds     int    `json:"wait_seconds,omitempty"`
	NextResendAfter int64  `json:"next_resend_after,omitempty"` // Unix timestamp
}

// VerificationResendEndpoint handles requests to resend verification codes.
// It enforces a maximum of 3 resends with increasing wait times between attempts.
func (h *AuthServer) VerificationResendEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	log := util.Log(ctx)

	loginEventID := req.PathValue(pathValueLoginEventID)
	if loginEventID == "" {
		return h.writeResendResponse(rw, http.StatusBadRequest, ResendVerificationResponse{
			Success: false,
			Message: "login event ID is required",
		})
	}

	log = log.WithField("login_event_id", loginEventID)

	// Step 1: Retrieve login event from database
	loginEvent, err := h.loginEventRepo.GetByID(ctx, loginEventID)
	if err != nil {
		if data.ErrorIsNoRows(err) {
			log.Warn("login event not found for resend request")
			return h.writeResendResponse(rw, http.StatusNotFound, ResendVerificationResponse{
				Success: false,
				Message: "login session not found or expired",
			})
		}
		log.WithError(err).Error("failed to retrieve login event")
		return err
	}

	// Step 2: Validate that this is a direct login with verification
	if loginEvent.VerificationID == "" {
		log.Warn("resend requested for non-verification login")
		return h.writeResendResponse(rw, http.StatusBadRequest, ResendVerificationResponse{
			Success: false,
			Message: "this login does not use verification codes",
		})
	}

	if loginEvent.ContactID == "" {
		log.Error("login event missing contact ID")
		return h.writeResendResponse(rw, http.StatusBadRequest, ResendVerificationResponse{
			Success: false,
			Message: "invalid login session",
		})
	}

	// Step 3: Check resend limits and timing
	resendCount := getResendCount(loginEvent.Properties)
	lastResendAt := getLastResendAt(loginEvent.Properties)

	log = log.WithField("resend_count", resendCount)

	// Check if max resends exceeded
	if resendCount >= maxResendAttempts {
		log.Warn("max resend attempts exceeded")
		return h.writeResendResponse(rw, http.StatusTooManyRequests, ResendVerificationResponse{
			Success:     false,
			Message:     "maximum resend attempts exceeded, please start a new login",
			ResendsLeft: 0,
		})
	}

	// Check if enough time has passed since last resend
	if resendCount > 0 && !lastResendAt.IsZero() {
		waitDuration := resendWaitDurations[min(resendCount-1, len(resendWaitDurations)-1)]
		nextAllowedTime := lastResendAt.Add(waitDuration)

		if time.Now().Before(nextAllowedTime) {
			waitRemaining := int(time.Until(nextAllowedTime).Seconds())
			log.WithField("wait_seconds", waitRemaining).Debug("resend requested too soon")
			return h.writeResendResponse(rw, http.StatusTooManyRequests, ResendVerificationResponse{
				Success:         false,
				Message:         fmt.Sprintf("please wait %d seconds before requesting another code", waitRemaining),
				ResendsLeft:     maxResendAttempts - resendCount,
				WaitSeconds:     waitRemaining,
				NextResendAfter: nextAllowedTime.Unix(),
			})
		}
	}

	// Step 4: Generate new verification ID and send code
	ctx = util.SetTenancy(ctx, loginEvent)
	newVerificationID := util.IDString()

	resp, err := h.profileCli.CreateContactVerification(ctx, connect.NewRequest(&profilev1.CreateContactVerificationRequest{
		Id:               newVerificationID,
		ContactId:        loginEvent.ContactID,
		DurationToExpire: "15m",
	}))
	if err != nil {
		log.WithError(err).Error("failed to create new verification")
		return h.writeResendResponse(rw, http.StatusInternalServerError, ResendVerificationResponse{
			Success: false,
			Message: "failed to send verification code, please try again",
		})
	}

	// Step 5: Update login event with new verification ID and resend tracking
	loginEvent.VerificationID = resp.Msg.GetId()
	loginEvent.Properties = updateResendTracking(loginEvent.Properties, resendCount+1)

	_, err = h.loginEventRepo.Update(ctx, loginEvent, "verification_id", "properties")
	if err != nil {
		log.WithError(err).Error("failed to update login event after resend")
		// Code was sent, so still return success but log the error
	}

	resendsLeft := maxResendAttempts - (resendCount + 1)
	log.WithFields(map[string]any{
		"new_verification_id": newVerificationID,
		"resends_left":        resendsLeft,
	}).Info("verification code resent successfully")

	// Calculate next resend wait time
	var nextWaitSeconds int
	if resendsLeft > 0 {
		nextWaitSeconds = int(resendWaitDurations[min(resendCount, len(resendWaitDurations)-1)].Seconds())
	}

	return h.writeResendResponse(rw, http.StatusOK, ResendVerificationResponse{
		Success:     true,
		Message:     "verification code sent",
		ResendsLeft: resendsLeft,
		WaitSeconds: nextWaitSeconds,
	})
}

// writeResendResponse writes a JSON response for the resend endpoint.
func (h *AuthServer) writeResendResponse(rw http.ResponseWriter, statusCode int, response ResendVerificationResponse) error {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(statusCode)
	return json.NewEncoder(rw).Encode(response)
}

// getResendCount extracts the resend count from login event properties.
func getResendCount(props data.JSONMap) int {
	if props == nil {
		return 0
	}
	if count, ok := props[propKeyResendCount]; ok {
		switch v := count.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case int64:
			return int(v)
		}
	}
	return 0
}

// getLastResendAt extracts the last resend timestamp from login event properties.
func getLastResendAt(props data.JSONMap) time.Time {
	if props == nil {
		return time.Time{}
	}
	if ts, ok := props[propKeyLastResendAt]; ok {
		switch v := ts.(type) {
		case string:
			t, _ := time.Parse(time.RFC3339, v)
			return t
		case float64:
			return time.Unix(int64(v), 0)
		case int64:
			return time.Unix(v, 0)
		}
	}
	return time.Time{}
}

// updateResendTracking updates the properties map with new resend tracking info.
func updateResendTracking(props data.JSONMap, newCount int) data.JSONMap {
	if props == nil {
		props = make(data.JSONMap)
	}
	props[propKeyResendCount] = newCount
	props[propKeyLastResendAt] = time.Now().Format(time.RFC3339)
	return props
}
