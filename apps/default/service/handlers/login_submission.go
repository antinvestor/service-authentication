package handlers

import (
	"context"
	"errors"
	"net/http"

	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame"
)

func (h *AuthServer) SubmitLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	svc := h.service

	logger := svc.Log(ctx).WithField("endpoint", "SubmitLoginEndpoint")
	logger.WithField("method", req.Method).WithField("url", req.URL.String()).Info("Request details")

	defaultHydra := hydra.NewDefaultHydra(h.config.GetOauth2ServiceAdminURI())

	// Parse form data before accessing PostForm
	if err := req.ParseForm(); err != nil {
		logger.WithError(err).Error("failed to parse form data")
		return err
	}

	profileName := req.PostForm.Get("profile_name")
	verificationCode := req.PostForm.Get("verification_code")
	loginEventID := req.PostForm.Get("login_evt_id")

	if loginEventID == "" {
		logger.Warn("missing a login event id")
		http.Redirect(rw, req, "/error", http.StatusBadRequest)
		return nil
	}

	loginEvent, err := h.loginEventRepo.GetByID(ctx, loginEventID)
	if err != nil {
		logger.WithError(err).Warn("missing a required field")
		if frame.ErrorIsNoRows(err) {
			http.Redirect(rw, req, "/not-found", http.StatusNotFound)
			return nil
		}

		return err
	}

	profileID, err := h.verifyProfileLogin(ctx, loginEvent, verificationCode)
	if err != nil {
		logger.WithError(err).Warn("could not verify submitted code")
		return h.showVerificationPage(rw, req, loginEventID, profileName, err.Error())
	}

	profileObj, err := h.updateProfileName(ctx, profileID, profileName)
	if err != nil {
		logger.WithError(err).Error("DEBUG: updateProfileName failed")
		return err
	}

	params := &hydra.AcceptLoginRequestParams{LoginChallenge: loginEvent.LoginChallengeID,
		SubjectID: profileObj.GetId(), Remember: true, RememberDuration: h.config.SessionRememberDuration}

	redirectUrl, err := defaultHydra.AcceptLoginRequest(
		req.Context(), params)

	if err != nil {
		logger.WithError(err).Error("critical issue")
		return err
	}

	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)

	return nil
}

func (h *AuthServer) updateProfileName(ctx context.Context, profileID string, profileName string) (*profilev1.ProfileObject, error) {

	response, err := h.profileCli.Svc().Update(ctx, &profilev1.UpdateRequest{
		Id: profileID,
		Properties: map[string]string{
			KeyProfileName: profileName,
		},
	})

	if err != nil {
		return nil, err
	}

	return response.GetData(), nil

}

func (h *AuthServer) verifyProfileLogin(ctx context.Context, event *models.LoginEvent, code string) (string, error) {

	login, err := h.loginRepo.GetByID(ctx, event.LoginID)
	if err != nil {
		return "", err
	}

	if !login.Locked.IsZero() {
		return "", errors.New("Login is locked")
	}

	if models.LoginSource(login.Source) != models.LoginSourceDirect {
		return login.ProfileID, nil
	}

	verificationID := event.VerificationID
	resp, err := h.profileCli.Svc().CheckVerification(ctx, &profilev1.CheckVerificationRequest{
		Id:   verificationID,
		Code: code,
	})
	if err != nil {
		return "", err
	}

	if int(resp.GetCheckAttempts()) > h.config.AuthProviderContactLoginMaxVerificationAttempts {
		return "", errors.New("Login verification attempts exceeded")
	}

	if !resp.GetSuccess() {
		return "", errors.New("Login verification code is incorrect")
	}

	return login.ProfileID, nil

}
