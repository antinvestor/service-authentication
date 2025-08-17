package handlers

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/google"
)

func (h *AuthServer) setupCookieSessions(_ context.Context, cfg *config.AuthenticationConfig) error {

	hashKey, err := hex.DecodeString(cfg.SecureCookieHashKey)
	if err != nil {
		return err
	}

	blockKey, err := hex.DecodeString(cfg.SecureCookieBlockKey)
	if err != nil {
		return err
	}

	sessionStore := sessions.NewCookieStore(hashKey, blockKey)
	sessionStore.Options.Path = "/"
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = true

	gothic.Store = sessionStore
	h.loginCookieCodec = sessionStore.Codecs

	return nil
}

func (h *AuthServer) getLogginSession() sessions.Store {
	return gothic.Store
}

func (h *AuthServer) getDeviceSession() sessions.Store {
	return gothic.Store
}

func (h *AuthServer) setupAuthProviders(_ context.Context, cfg *config.AuthenticationConfig) {

	var providers []goth.Provider

	h.loginOptions = map[string]bool{"enableContactLogin": !cfg.AuthProviderContactLoginDisabled}

	if cfg.AuthProviderGoogleClientID != "" {
		providers = append(providers, google.New(cfg.AuthProviderGoogleClientID, cfg.AuthProviderGoogleSecret, cfg.AuthProviderGoogleCallbackURL, cfg.AuthProviderGoogleScopes...))
		h.loginOptions["enableGoogleLogin"] = true
	}

	if cfg.AuthProviderMetaClientID != "" {
		providers = append(providers, facebook.New(cfg.AuthProviderMetaClientID, cfg.AuthProviderMetaSecret, cfg.AuthProviderMetaCallbackURL, cfg.AuthProviderMetaScopes...))
		h.loginOptions["enableFacebookLogin"] = true
	}

	if len(providers) > 0 {
		goth.UseProviders(providers...)
	}

}

func (h *AuthServer) providerPostUserLogin(rw http.ResponseWriter, req *http.Request, loginChallenge string) (*models.LoginEvent, error) {

	ctx := req.Context()
	svc := h.service
	logger := svc.Log(ctx).WithField("endpoint", "ProviderCallbackEndpoint")

	user, err := gothic.CompleteUserAuth(rw, req)
	if err != nil {
		return nil, err
	}

	contactDetail := user.Email
	if contactDetail == "" {
		// Check if a phonenumber was used
	}

	existingProfile, err := h.profileCli.GetProfileByContact(ctx, contactDetail)
	if err != nil {
		return nil, err
	}

	if existingProfile == nil {

		userName := user.Name

		if userName == "" {
			userName = strings.Join([]string{user.FirstName, user.LastName}, " ")
		}
		// don't have this profile in existence so we create it
		existingProfile, err = h.profileCli.CreateProfileByContactAndName(ctx, contactDetail, userName)
		if err != nil {
			return nil, err
		}
	}

	contactID := ""
	for _, profileContact := range existingProfile.GetContacts() {
		if strings.EqualFold(contactDetail, profileContact.GetDetail()) {
			contactID = profileContact.GetId()
		}
	}

	if contactID == "" {
		logger.Error(" contact not linked to profile found")
		http.Redirect(rw, req, "/error", http.StatusInternalServerError)
		return nil, nil
	}

	loginEvent, err := h.noteLoginAttempt(ctx, models.LoginSource(user.Provider), existingProfile.GetId(), contactID, "", loginChallenge, user.RawData)
	if err != nil {
		return nil, err
	}

	return loginEvent, nil
}

func (h *AuthServer) ProviderCallbackEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	svc := h.service
	logger := svc.Log(ctx).WithField("endpoint", "ProviderCallbackEndpoint")

	// Retrieve loginChallenge from session instead of form values
	session, err := h.getLogginSession().Get(req, SessionKeyStorageName)
	if err != nil {
		logger.WithError(err).Error("failed to get session")
		http.Redirect(rw, req, "/error", http.StatusSeeOther)
		return err
	}

	loginChallenge, ok := session.Values[SessionKeyLoginChallenge].(string)
	if !ok || loginChallenge == "" {
		logger.Error("login_challenge not found in session")
		http.Redirect(rw, req, "/error", http.StatusSeeOther)
		return fmt.Errorf("login_challenge not found in session")
	}

	internalRedirectLinkToSignIn := fmt.Sprintf("/s/login?login_challenge=%s", loginChallenge)

	// try to get the user without re-authenticating
	loginEvt, err := h.providerPostUserLogin(rw, req, loginChallenge)
	if err != nil {

		logger.WithError(err).Error(" user login attempt failed")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)

		return err
	}

	if loginEvt == nil {
		return nil
	}

	req.PostForm = url.Values{}
	req.PostForm.Set("login_event_id", loginEvt.GetID())
	req.PostForm.Set(csrf.TemplateTag, csrf.Token(req))
	return h.SubmitLoginEndpoint(rw, req)
}

func (h *AuthServer) ProviderLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	svc := h.service
	logger := svc.Log(ctx).WithField("endpoint", "ProviderLoginEndpoint")

	// Parse form data before accessing PostForm
	if err := req.ParseForm(); err != nil {
		logger.WithError(err).Error("failed to parse form data")
		return err
	}

	loginChallenge := req.PostFormValue("login_challenge")

	// try to get the user without re-authenticating
	loginEvt, err := h.providerPostUserLogin(rw, req, loginChallenge)
	if err != nil {
		gothic.BeginAuthHandler(rw, req)
		return nil
	}

	if loginEvt == nil {
		return nil
	}

	logger.Info("somehow we managed to auto login")

	req.PostForm = url.Values{}
	req.PostForm.Set("login_event_id", loginEvt.GetID())
	req.PostForm.Set(csrf.TemplateTag, csrf.Token(req))
	return h.SubmitLoginEndpoint(rw, req)
}
