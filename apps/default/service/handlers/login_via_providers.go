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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	logger.Info("starting provider post-login process")

	// Step 1: Complete OAuth2 authentication with provider
	logger.Debug("attempting to complete user authentication with provider")
	user, err := gothic.CompleteUserAuth(rw, req)
	if err != nil {
		logger.WithError(err).Error("failed to complete user authentication with provider")
		return nil, err
	}

	logger.With("provider", user.Provider).
		With("user_id", user.UserID).
		With("email", user.Email).
		With("name", user.Name).
		With("first_name", user.FirstName).
		With("last_name", user.LastName).
		With("avatar_url", user.AvatarURL).
		With("raw data", user.RawData).
		Info("successfully completed provider authentication")

	// Step 2: Extract contact detail from user data
	contactDetail := user.Email
	if contactDetail == "" {
		logger.Warn("no email provided by provider, checking for phone number")
		// Check if a phonenumber was used
		// TODO: Add phone number extraction logic if needed
	}

	if contactDetail == "" {
		logger.Error("no contact detail (email or phone) provided by provider")
		return nil, fmt.Errorf("no contact detail provided by provider %s", user.Provider)
	}

	logger.WithField("contact_detail", contactDetail).Debug("extracted contact detail from provider")

	// Step 3: Look up existing profile by contact
	logger.WithField("contact_detail", contactDetail).Debug("looking up existing profile by contact")
	existingProfile, err := h.profileCli.GetProfileByContact(ctx, contactDetail)
	if err != nil {
		st, errOk := status.FromError(err)
		if !errOk || st.Code() != codes.NotFound {

			logger.WithError(err).WithField("contact_detail", contactDetail).Error("failed to lookup profile by contact")
			return nil, err
		}
	}

	// Step 4: Create profile if it doesn't exist
	if existingProfile == nil {
		logger.WithField("contact_detail", contactDetail).Info("profile not found, creating new profile")

		userName := user.Name
		if userName == "" {
			userName = strings.Join([]string{user.FirstName, user.LastName}, " ")
			logger.WithField("constructed_name", userName).Debug("constructed user name from first and last name")
		}

		logger.With("contact_detail", contactDetail, "user_name", userName).Debug("creating new profile")

		existingProfile, err = h.profileCli.CreateProfileByContactAndName(ctx, contactDetail, userName)
		if err != nil {
			logger.WithError(err).With("contact_detail", contactDetail, "user_name", userName).Error("failed to create new profile")
			return nil, err
		}

		logger.WithField("profile_id", existingProfile.GetId()).Info("successfully created new profile")
	} else {
		logger.WithField("profile_id", existingProfile.GetId()).Info("found existing profile")
	}

	// Step 5: Find contact ID within the profile
	logger.WithField("profile_id", existingProfile.GetId()).Debug("searching for contact ID within profile")
	contactID := ""
	profileContacts := existingProfile.GetContacts()
	logger.WithField("contact_count", len(profileContacts)).Debug("profile has contacts")

	for i, profileContact := range profileContacts {
		logger.With("contact_index", i, "contact_id", profileContact.GetId(), "contact_detail", profileContact.GetDetail(), "contact_type", profileContact.GetType()).Debug("checking profile contact")

		if strings.EqualFold(contactDetail, profileContact.GetDetail()) {
			contactID = profileContact.GetId()
			logger.WithField("contact_id", contactID).Info("found matching contact ID")
			break
		}
	}

	if contactID == "" {
		logger.With("profile_id", existingProfile.GetId(), "contact_detail", contactDetail, "contact_count", len(profileContacts)).Error("contact not linked to profile found")
		http.Redirect(rw, req, "/error", http.StatusInternalServerError)
		return nil, nil
	}

	// Step 6: Record login attempt
	logger.With("provider", user.Provider, "profile_id", existingProfile.GetId(), "contact_id", contactID, "login_challenge", loginChallenge).Debug("recording login attempt")

	loginEvent, err := h.noteLoginAttempt(ctx, models.LoginSource(user.Provider), existingProfile.GetId(), contactID, "", loginChallenge, user.RawData)
	if err != nil {
		logger.WithError(err).With("provider", user.Provider, "profile_id", existingProfile.GetId(), "contact_id", contactID, "login_challenge", loginChallenge).Error("failed to record login attempt")
		return nil, err
	}

	logger.With("login_event_id", loginEvent.GetID(), "provider", user.Provider, "profile_id", existingProfile.GetId(), "contact_id", contactID, "login_challenge", loginChallenge).Info("successfully completed provider post-login process")

	return loginEvent, nil
}

func (h *AuthServer) ProviderCallbackEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	svc := h.service
	logger := svc.Log(ctx).WithField("endpoint", "ProviderCallbackEndpoint")

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
		http.Redirect(rw, req, "/error", http.StatusSeeOther)
		return fmt.Errorf("login_challenge not found in session")
	}

	// try to get the user without re-authenticating
	loginEvt, err := h.providerPostUserLogin(rw, req, loginChallenge)
	if err != nil {
		gothic.BeginAuthHandler(rw, req)
		return nil
	}

	logger.Info("somehow we managed to auto login")

	req.PostForm = url.Values{}
	req.PostForm.Set("login_event_id", loginEvt.GetID())
	req.PostForm.Set(csrf.TemplateTag, csrf.Token(req))
	return h.SubmitLoginEndpoint(rw, req)
}
