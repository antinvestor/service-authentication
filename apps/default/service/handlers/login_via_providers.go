package handlers

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/google"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
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
	// Disable Secure flag to allow HTTP in test environments
	// TODO: Make this configurable based on environment in production
	sessionStore.Options.Secure = false

	gothic.Store = sessionStore
	h.loginCookieCodec = sessionStore.Codecs

	return nil
}

func (h *AuthServer) getLogginSession() sessions.Store {
	return gothic.Store
}

func (h *AuthServer) setupAuthProviders(_ context.Context, cfg *config.AuthenticationConfig) {

	var providers []goth.Provider

	h.loginOptions = map[string]any{"enableContactLogin": !cfg.AuthProviderContactLoginDisabled}

	if cfg.AuthProviderGoogleClientID != "" {
		providers = append(providers, google.New(cfg.AuthProviderGoogleClientID, cfg.AuthProviderGoogleSecret, cfg.AuthProviderGoogleCallbackURL, cfg.AuthProviderGoogleScopes...))
		h.loginOptions["enableGoogleLogin"] = true
		h.loginOptions["googleClientId"] = cfg.AuthProviderGoogleClientID
		h.loginOptions["googleRedirectUri"] = cfg.AuthProviderGoogleCallbackURL
	}

	if cfg.AuthProviderMetaClientID != "" {
		providers = append(providers, facebook.New(cfg.AuthProviderMetaClientID, cfg.AuthProviderMetaSecret, cfg.AuthProviderMetaCallbackURL, cfg.AuthProviderMetaScopes...))
		h.loginOptions["enableFacebookLogin"] = true
	}

	if len(providers) > 0 {
		goth.UseProviders(providers...)
	}

}

func (h *AuthServer) providerPostUserLogin(rw http.ResponseWriter, req *http.Request, loginChallenge, clientID string) (*models.LoginEvent, error) {

	ctx := req.Context()
	logger := util.Log(ctx).WithField("endpoint", "ProviderCallbackEndpoint")

	user, err := gothic.CompleteUserAuth(rw, req)
	if err != nil {
		logger.WithError(err).Error("failed to complete user authentication with provider")
		return nil, err
	}

	contactDetail := user.Email
	if contactDetail == "" {
		logger.Warn("no contact provided by provider, checking for phone number")
		// Check if a phonenumber was used
		// TODO: Add phone number extraction logic if needed
	}

	if contactDetail == "" {
		logger.Error("no contact detail (contact or phone) provided by provider")
		return nil, fmt.Errorf("no contact detail provided by provider %s", user.Provider)
	}

	result, err := h.profileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{Contact: contactDetail}))
	if err != nil {
		if frame.ErrorIsNotFound(err) {

			logger.WithError(err).WithField("contact_detail", contactDetail).Error("failed to lookup profile by contact")
			return nil, err
		}
	}

	existingProfile := result.Msg.GetData()
	if existingProfile == nil {

		userName := user.Name
		if userName == "" {
			userName = strings.Join([]string{user.FirstName, user.LastName}, " ")
		}

		properties, _ := structpb.NewStruct(map[string]any{
			KeyProfileName: userName,
		})

		createResult, err0 := h.profileCli.Create(ctx, connect.NewRequest(&profilev1.CreateRequest{
			Type:       profilev1.ProfileType_PERSON,
			Contact:    contactDetail,
			Properties: properties,
		}))
		if err0 != nil {
			logger.WithError(err0).With("contact_detail", contactDetail, "user_name", userName).Error("failed to create new profile")
			return nil, err0
		}
		existingProfile = createResult.Msg.GetData()
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

	loginEvent, err := h.storeLoginAttempt(ctx, clientID, models.LoginSource(user.Provider), existingProfile.GetId(), contactID, "", loginChallenge, user.RawData)
	if err != nil {
		logger.WithError(err).With("provider", user.Provider, "profile_id", existingProfile.GetId(), "contact_id", contactID, "login_challenge", loginChallenge).Error("failed to record login attempt")
		return nil, err
	}

	logger.With("login_event_id", loginEvent.GetID(), "provider", user.Provider, "profile_id", existingProfile.GetId(), "contact_id", contactID).Info("successfully completed provider post-login process")

	return loginEvent, nil
}

func (h *AuthServer) ProviderCallbackEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	logger := util.Log(ctx).WithField("endpoint", "ProviderCallbackEndpoint")

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

	clientID, ok := session.Values[SessionKeyClientID].(string)
	if !ok || clientID == "" {
		logger.Error("clientID not found in session")
		http.Redirect(rw, req, "/error?error=client_id_not_found&error_description=Ensure that cookie storage works with your browser for continuity", http.StatusSeeOther)
		return fmt.Errorf("client id not found in session")
	}

	internalRedirectLinkToSignIn := fmt.Sprintf("/s/login?login_challenge=%s", loginChallenge)

	// try to get the user without re-authenticating
	loginEvt, err := h.providerPostUserLogin(rw, req, loginChallenge, clientID)
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
	return h.SubmitLoginEndpoint(rw, req)
}

func (h *AuthServer) ProviderLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	logger := util.Log(ctx).WithField("endpoint", "ProviderLoginEndpoint")

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

	clientID, ok := session.Values[SessionKeyClientID].(string)
	if !ok || clientID == "" {
		logger.Error("clientID not found in session")
		http.Redirect(rw, req, "/error?error=client_id_not_found&error_description=Ensure that cookie storage works with your browser for continuity", http.StatusSeeOther)
		return fmt.Errorf("client id not found in session")
	}

	// try to get the user without re-authenticating
	loginEvt, err := h.providerPostUserLogin(rw, req, loginChallenge, clientID)
	if err != nil {
		gothic.BeginAuthHandler(rw, req)
		return nil
	}

	logger.Info("somehow we managed to auto login")

	req.PostForm = url.Values{}
	req.PostForm.Set("login_event_id", loginEvt.GetID())
	return h.SubmitLoginEndpoint(rw, req)
}
