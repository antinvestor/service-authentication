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
	sessionStore.Options.SameSite = http.SameSiteLaxMode

	// Enable Secure flag in production (when not in test environment)
	// Test environments use HTTP, production should use HTTPS
	isTestEnv := cfg.Name() == "authentication_tests"
	sessionStore.Options.Secure = !isTestEnv

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

func (h *AuthServer) providerPostUserLogin(rw http.ResponseWriter, req *http.Request, loginEvt *models.LoginEvent) error {

	ctx := req.Context()

	user, err := gothic.CompleteUserAuth(rw, req)
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to complete user authentication with provider")
		return err
	}

	contactDetail := user.Email
	if contactDetail == "" {
		// Check if a phonenumber was used
		// TODO: Add phone number extraction logic if needed
	}

	if contactDetail == "" {
		return fmt.Errorf("no contact detail provided by provider %s", user.Provider)
	}

	result, err := h.profileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{Contact: contactDetail}))
	if err != nil {
		if !frame.ErrorIsNotFound(err) {
			util.Log(ctx).WithError(err).Error("failed to lookup profile by contact")
			return err
		}
	}

	var existingProfile *profilev1.ProfileObject
	if result != nil {
		existingProfile = result.Msg.GetData()
	}
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
			util.Log(ctx).WithError(err0).Error("failed to create new profile")
			return err0
		}
		existingProfile = createResult.Msg.GetData()
	}

	// Step 5: Find contact ID within the profile
	contactID := ""
	profileContacts := existingProfile.GetContacts()

	for _, profileContact := range profileContacts {
		if strings.EqualFold(contactDetail, profileContact.GetDetail()) {
			contactID = profileContact.GetId()
			break
		}
	}

	if contactID == "" {
		util.Log(ctx).Error("contact not linked to profile found")
		http.Redirect(rw, req, "/error", http.StatusInternalServerError)
		return nil
	}

	_, err = h.storeLoginAttempt(ctx, loginEvt, models.LoginSource(user.Provider), existingProfile.GetId(), contactID, "", user.RawData)
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to record login attempt")
		return err
	}

	return nil
}

func (h *AuthServer) ProviderCallbackEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	// Retrieve loginEventID from session instead of form values
	session, err := h.getLogginSession().Get(req, SessionKeyLoginStorageName)
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to get session")
		http.Redirect(rw, req, "/error", http.StatusSeeOther)
		return nil
	}

	loginEventID, ok := session.Values[SessionKeyLoginEventID].(string)
	if !ok || loginEventID == "" {
		util.Log(ctx).Error("login event id not found in session cookie")
		http.Redirect(rw, req, "/error", http.StatusSeeOther)
		return nil
	}

	// Clear login event ID from session to prevent replay on browser retry
	delete(session.Values, SessionKeyLoginEventID)
	_ = session.Save(req, rw)

	loginEvt, err := h.getLoginEventFromCache(ctx, loginEventID)
	if err != nil {
		util.Log(ctx).WithError(err).Error("Failed to get login event cache")
		return err
	}

	internalRedirectLinkToSignIn := "/s/login?login_challenge=" + url.QueryEscape(loginEvt.LoginChallengeID)

	// try to get the user without re-authenticating
	err = h.providerPostUserLogin(rw, req, loginEvt)
	if err != nil {
		util.Log(ctx).WithError(err).Warn("provider auth failed - redirecting to login page")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return nil
	}

	req.PostForm = url.Values{}
	req.PostForm.Set("login_event_id", loginEventID)
	if err = h.SubmitLoginEndpoint(rw, req); err != nil {
		util.Log(ctx).WithError(err).Warn("login submission failed after provider auth - redirecting to login page")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return nil
	}
	return nil
}

func (h *AuthServer) ProviderLoginEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	// Parse form data before accessing PostForm
	if err := req.ParseForm(); err != nil {
		util.Log(ctx).WithError(err).Error("failed to parse form data")
		return err
	}

	loginEventID := req.PathValue(pathValueLoginEventID)

	loginEvt, err := h.getLoginEventFromCache(ctx, loginEventID)
	if err != nil {
		util.Log(ctx).WithError(err).Error("Failed to get login event cache")
		return err
	}

	// try to get the user without re-authenticating
	err = h.providerPostUserLogin(rw, req, loginEvt)
	if err != nil {

		session, sessErr := h.getLogginSession().Get(req, SessionKeyLoginStorageName)
		if sessErr != nil {
			util.Log(ctx).WithError(sessErr).Error("failed to get session")
			http.Redirect(rw, req, "/error", http.StatusSeeOther)
			return nil
		}

		session.Values[SessionKeyLoginEventID] = loginEventID
		err = session.Save(req, rw)
		if err != nil {
			util.Log(ctx).WithError(err).Error("failed to save login event ID to cookie session")
			return err
		}

		gothic.BeginAuthHandler(rw, req)
		return nil
	}

	internalRedirectLinkToSignIn := "/s/login?login_challenge=" + url.QueryEscape(loginEvt.LoginChallengeID)
	req.PostForm = url.Values{}
	req.PostForm.Set("login_event_id", loginEventID)
	if err = h.SubmitLoginEndpoint(rw, req); err != nil {
		util.Log(ctx).WithError(err).Warn("login submission failed - redirecting to login page")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return nil
	}
	return nil
}
