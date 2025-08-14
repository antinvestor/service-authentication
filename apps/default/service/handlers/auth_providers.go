package handlers

import (
	"context"
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

func (h *AuthServer) setupAuthProviders(ctx context.Context, cfg *config.AuthenticationConfig) {

	sessionStore := sessions.NewCookieStore([]byte(cfg.AuthProviderSessionSecurityKey))
	sessionStore.Options.Path = "/"
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = true

	gothic.Store = sessionStore

	var providers []goth.Provider

	h.loginOptions = map[string]bool{"enableContactLogin": !cfg.AuthProviderContactLoginDisabled}
	h.loginProviderMap = make(map[string]string)

	if cfg.AuthProviderGoogleClientID != "" {
		providers = append(providers, google.New(cfg.AuthProviderGoogleClientID, cfg.AuthProviderGoogleSecret, cfg.AuthProviderGoogleCallbackURL, cfg.AuthProviderGoogleScopes...))
		h.loginOptions["enableGoogleLogin"] = true
		h.loginProviderMap["enableGoogleLogin"] = "Google"
	}

	if cfg.AuthProviderMetaClientID != "" {
		providers = append(providers, facebook.New(cfg.AuthProviderMetaClientID, cfg.AuthProviderMetaSecret, cfg.AuthProviderMetaCallbackURL, cfg.AuthProviderMetaScopes...))
		h.loginOptions["enableFacebookLogin"] = true
		h.loginProviderMap["enableFacebookLogin"] = "Facebook"
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
		return  nil, err
	}

	contactDetail := user.Email
	if contactDetail == "" {
		// Check if a phonenumber was used
	}

	existingProfile, err := h.profileCli.GetProfileByContact(ctx, contactDetail)
	if err != nil {
		return nil,  err
	}

	if existingProfile == nil {


		userName := user.Name

		if userName == "" {
			userName = strings.Join([]string{user.FirstName, user.LastName}, " ")
		}
		// don't have this profile in existence so we create it
		existingProfile, err = h.profileCli.CreateProfileByContactAndName(ctx, contactDetail, userName)
		if err != nil {
			return  nil, err
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
		return  nil, nil
	}

	loginEvent, err := h.noteLoginAttempt(ctx, models.LoginSource(user.Provider), existingProfile.GetId(), contactID, "", loginChallenge)
	if err != nil {
		return  nil, err
	}


	return loginEvent, nil
}

func (h *AuthServer) ProviderCallbackEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()
	svc := h.service
	logger := svc.Log(ctx).WithField("endpoint", "ProviderCallbackEndpoint")

	loginChallenge := req.FormValue("login_challenge")
	internalRedirectLinkToSignIn := fmt.Sprintf("/s/login?login_challenge=%s", loginChallenge)

	// try to get the user without re-authenticating
	loginEvt, err := h.providerPostUserLogin(rw, req, loginChallenge)
	if err != nil {

		logger.WithError(err).Error(" user login attempt failed")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)

		return err
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

	loginChallenge := req.FormValue("login_challenge")
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
