package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers/providers"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	loginSessionProviderAuth = "l_provider_sess"
)

func (h *AuthServer) ProviderLoginEndpointV2(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx)

	loginEventID := req.PathValue(pathValueLoginEventID)
	providerName := req.URL.Query().Get("provider")

	log = log.WithFields(map[string]any{
		"login_event_id": loginEventID,
		"provider":       providerName,
	})

	if providerName == "" {
		log.Warn("provider login attempt with empty provider name")
		return fmt.Errorf("provider name is required")
	}

	provider, ok := h.loginAuthProviders[providerName]
	if !ok {
		log.WithField("available_providers", loginAuthProviderNames(h.loginAuthProviders)).
			Warn("provider login attempt with unknown provider")
		return fmt.Errorf("unknown login provider: %s", providerName)
	}

	pkce, err := providers.NewPKCE()
	if err != nil {
		log.WithError(err).Error("failed to generate PKCE challenge")
		return fmt.Errorf("failed to generate PKCE: %w", err)
	}

	authState := &providers.AuthState{
		Provider:     providerName,
		State:        util.RandomAlphaNumericString(32),
		PKCEVerifier: pkce.Verifier,
		LoginEventID: loginEventID,
		ExpiresAt:    time.Now().Add(5 * time.Minute),
	}

	encoded, err := h.loginCookieCodec[0].Encode(loginSessionProviderAuth, authState)
	if err != nil {
		log.WithError(err).Error("failed to encode auth state cookie")
		return fmt.Errorf("failed to encode auth state: %w", err)
	}

	providers.SetAuthStateCookie(rw, encoded)

	authURL := provider.AuthCodeURL(authState.State, pkce.Challenge)

	log.WithFields(map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
	}).Info("redirecting user to external provider for authentication")

	http.Redirect(rw, req, authURL, http.StatusSeeOther)
	return nil
}

func (h *AuthServer) ProviderCallbackEndpointV2(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx)

	// Check for provider-side errors first (all OAuth2 providers use this pattern)
	if errParam := req.URL.Query().Get("error"); errParam != "" {
		errDesc := req.URL.Query().Get("error_description")
		log.WithFields(map[string]any{
			"provider_error":       errParam,
			"provider_error_desc":  errDesc,
		}).Error("external provider returned an error during authentication")
		return fmt.Errorf("provider authentication error: %s - %s", errParam, errDesc)
	}

	// Step 1: Retrieve and decode auth state from cookie
	cookie, err := req.Cookie(providers.AuthStateCookie)
	if err != nil {
		log.WithError(err).Error("auth state cookie not found - user may have cookies disabled or session expired")
		return fmt.Errorf("missing auth state cookie: %w", err)
	}
	providers.ClearAuthStateCookie(rw)

	var authState *providers.AuthState
	for _, cookieCodec := range h.loginCookieCodec {
		decodeErr := cookieCodec.Decode(loginSessionProviderAuth, cookie.Value, &authState)
		if decodeErr == nil {
			break
		}
	}

	if authState == nil {
		log.Error("failed to decode auth state cookie - all codecs failed")
		return fmt.Errorf("failed to decode authentication state")
	}

	log = log.WithFields(map[string]any{
		"provider":       authState.Provider,
		"login_event_id": authState.LoginEventID,
	})

	// Step 2: Check auth state expiry
	if time.Now().After(authState.ExpiresAt) {
		log.WithField("expired_at", authState.ExpiresAt).
			Warn("auth state has expired - user took too long at the provider")
		return fmt.Errorf("authentication session expired, please try again")
	}

	// Step 3: Validate OAuth2 state parameter against stored state
	callbackState := req.URL.Query().Get("state")
	if callbackState != authState.State {
		log.WithFields(map[string]any{
			"expected_state_prefix": authState.State[:min(8, len(authState.State))],
			"received_state_prefix": callbackState[:min(8, len(callbackState))],
		}).Error("OAuth2 state parameter mismatch - possible CSRF attack")
		return fmt.Errorf("state parameter mismatch")
	}

	// Step 4: Look up provider using the trusted value from the auth state cookie
	provider, ok := h.loginAuthProviders[authState.Provider]
	if !ok {
		log.Error("provider from auth state not found in registered providers")
		return fmt.Errorf("provider %s is no longer available", authState.Provider)
	}

	// Step 5: Exchange authorization code for user info
	code := req.URL.Query().Get("code")
	if code == "" {
		log.Error("provider callback missing authorization code")
		return fmt.Errorf("missing authorization code from provider")
	}

	log.Debug("exchanging authorization code with external provider")

	user, err := provider.CompleteLogin(ctx, code, authState.PKCEVerifier)
	if err != nil {
		log.WithError(err).Error("failed to complete login with external provider - token exchange or user info retrieval failed")
		return fmt.Errorf("provider login completion failed: %w", err)
	}

	log.WithField("has_contact", user.Contact != "").
		Debug("external provider authentication successful")

	// Step 6: Retrieve login event from cache
	loginEvt, err := h.getLoginEventFromCache(ctx, authState.LoginEventID)
	if err != nil {
		log.WithError(err).Error("login event not found in cache after provider callback - session may have expired")
		return fmt.Errorf("login session not found: %w", err)
	}

	log.WithFields(map[string]any{
		"client_id":    loginEvt.ClientID,
		"duration_ms":  time.Since(start).Milliseconds(),
	}).Info("provider callback processed, completing user login")

	// Step 7: Complete the login flow
	return h.postUserLogin(ctx, rw, req, loginEvt, user, provider.Name())
}

func (h *AuthServer) postUserLogin(
	ctx context.Context,
	rw http.ResponseWriter,
	req *http.Request,
	loginEvt *models.LoginEvent,
	loggedInUser *providers.AuthenticatedUser,
	provider string,
) error {
	start := time.Now()
	log := util.Log(ctx).WithFields(map[string]any{
		"provider":       provider,
		"login_event_id": loginEvt.GetID(),
	})

	contactDetail := loggedInUser.Contact
	if contactDetail == "" {
		log.Error("external provider did not return a contact (email/phone) for the user")
		return fmt.Errorf("no contact detail provided by provider %s", provider)
	}

	internalRedirectLinkToSignIn := "/s/login?login_challenge=" + url.QueryEscape(loginEvt.LoginChallengeID)

	// Step 1: Look up existing profile by contact
	log.Debug("looking up user profile by contact")

	result, err := h.profileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{Contact: contactDetail}))
	if err != nil {
		if !frame.ErrorIsNotFound(err) {
			log.WithError(err).Error("profile service lookup failed")
			return fmt.Errorf("profile lookup failed: %w", err)
		}
		log.Debug("no existing profile found for contact - will create new profile")
	}

	var existingProfile *profilev1.ProfileObject
	if result != nil {
		existingProfile = result.Msg.GetData()
	}

	// Step 2: Create profile if not found
	if existingProfile == nil {
		userName := loggedInUser.Name
		if userName == "" {
			userName = strings.TrimSpace(strings.Join([]string{loggedInUser.FirstName, loggedInUser.LastName}, " "))
		}

		log.WithField("user_name", userName).Debug("creating new profile for provider login")

		properties, _ := structpb.NewStruct(map[string]any{
			KeyProfileName: userName,
		})

		createResult, createErr := h.profileCli.Create(ctx, connect.NewRequest(&profilev1.CreateRequest{
			Type:       profilev1.ProfileType_PERSON,
			Contact:    contactDetail,
			Properties: properties,
		}))
		if createErr != nil {
			log.WithError(createErr).Error("failed to create new profile via profile service")
			return fmt.Errorf("profile creation failed: %w", createErr)
		}
		existingProfile = createResult.Msg.GetData()
		log.WithField("profile_id", existingProfile.GetId()).Info("new profile created for provider login")
	} else {
		log.WithField("profile_id", existingProfile.GetId()).Debug("existing profile found for contact")
	}

	// Step 3: Find contact ID within the profile
	contactID := ""
	profileContacts := existingProfile.GetContacts()

	for _, profileContact := range profileContacts {
		if strings.EqualFold(contactDetail, profileContact.GetDetail()) {
			contactID = profileContact.GetId()
			break
		}
	}

	if contactID == "" {
		log.WithField("profile_id", existingProfile.GetId()).
			Error("contact not found within profile - contact/profile linkage is broken")
		http.Redirect(rw, req, internalRedirectLinkToSignIn, http.StatusSeeOther)
		return nil
	}

	// Step 4: Store login attempt
	log.Debug("storing login attempt")

	loginEvent, err := h.storeLoginAttempt(
		ctx,
		loginEvt,
		models.LoginSource(provider),
		existingProfile.GetId(),
		contactID,
		"",
		loggedInUser.Raw,
	)
	if err != nil {
		log.WithError(err).Error("failed to store login attempt in database")
		return fmt.Errorf("login attempt storage failed: %w", err)
	}

	// Step 5: Accept the Hydra login request to complete the OAuth2 flow
	log.Debug("accepting Hydra login request")

	params := &hydra.AcceptLoginRequestParams{
		LoginChallenge:   loginEvt.LoginChallengeID,
		SubjectID:        existingProfile.GetId(),
		SessionID:        loginEvent.GetID(),
		ExtendSession:    true,
		Remember:         true,
		RememberDuration: h.config.SessionRememberDuration,
	}

	loginContext := map[string]any{
		"login_event_id": loginEvent.GetID(),
	}

	redirectURL, err := h.defaultHydraCli.AcceptLoginRequest(ctx, params, loginContext, provider, contactID)
	if err != nil {
		log.WithError(err).Error("hydra accept login request failed after provider authentication")
		return fmt.Errorf("failed to complete OAuth2 login: %w", err)
	}

	log.WithFields(map[string]any{
		"profile_id":  existingProfile.GetId(),
		"duration_ms": time.Since(start).Milliseconds(),
	}).Info("provider login completed successfully")

	http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
	return nil
}

// loginAuthProviderNames returns registered provider names for diagnostic logging.
func loginAuthProviderNames(providerMap map[string]providers.AuthProvider) []string {
	names := make([]string, 0, len(providerMap))
	for name := range providerMap {
		names = append(names, name)
	}
	return names
}
