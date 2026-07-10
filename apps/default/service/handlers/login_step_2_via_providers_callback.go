// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers/providers"
	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

func (h *AuthServer) ProviderCallbackEndpointV2(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	start := time.Now()
	log := util.Log(ctx)

	// Check for provider-side errors first (all OAuth2 providers use this pattern)
	if errParam := req.URL.Query().Get("error"); errParam != "" {
		errDesc := req.URL.Query().Get("error_description")
		log.WithFields(map[string]any{
			"provider_error":      errParam,
			"provider_error_desc": errDesc,
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

	var authState providers.AuthState
	if decodeErr := h.cookiesCodec.Decode(loginSessionProviderAuth, cookie.Value, &authState); decodeErr != nil {
		log.WithError(decodeErr).Error("failed to decode auth state cookie")
		return fmt.Errorf("failed to decode authentication state: %w", decodeErr)
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

	user, err := provider.CompleteLogin(ctx, code, authState.PKCEVerifier, authState.Nonce)
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

	// Enrich login event with partition/tenant info if not already set.
	// The normal contact login flow does this in LoginEndpointShow, but
	// the social login redirect skips that step.
	if loginEvt.TenantID == "" || loginEvt.PartitionID == "" {
		h.updateTenancyForLoginEvent(ctx, authState.LoginEventID)

		loginEvt, err = h.getLoginEventFromCache(ctx, authState.LoginEventID)
		if err != nil {
			log.WithError(err).Error("failed to reload login event after tenancy enrichment")
			return fmt.Errorf("login session not found: %w", err)
		}

		if loginEvt.TenantID == "" || loginEvt.PartitionID == "" {
			log.WithField("client_id", loginEvt.ClientID).
				Error("login event still missing tenancy info after enrichment")
			return fmt.Errorf("unable to resolve tenancy for login session")
		}
	}

	// Keep service-bot JWT tenancy for outbound profile/device S2S calls.
	// Setting login-event tenancy here rewrites Plane-1 checks onto the
	// product partition and fails when the bot only has service on root.
	ctx = serviceBotContext(ctx)
	log.WithFields(map[string]any{
		"client_id":    loginEvt.ClientID,
		"tenant_id":    loginEvt.TenantID,
		"partition_id": loginEvt.PartitionID,
		"duration_ms":  time.Since(start).Milliseconds(),
	}).Debug("provider callback processed, completing user login")

	// Step 7: Complete the login flow
	return h.postUserLogin(ctx, rw, req, loginEvt, user, provider.Name())
}

// postUserLogin completes a provider-based login by driving the shared
// profile-resolution + Hydra-acceptance flow, then performs a top-level
// redirect to the URL Hydra returned. The Set-Login: logged-in header is
// emitted before the redirect so Chrome's Login Status API knows this IdP is
// in the logged-in state.
func (h *AuthServer) postUserLogin(
	ctx context.Context,
	rw http.ResponseWriter,
	req *http.Request,
	loginEvt *models.LoginEvent,
	loggedInUser *providers.AuthenticatedUser,
	provider string,
) error {
	redirectURL, err := h.completeProviderLogin(ctx, req, loginEvt, loggedInUser, provider)
	if err != nil {
		return err
	}
	setLoginStatusLoggedIn(rw)
	http.Redirect(rw, req, redirectURL, http.StatusSeeOther)
	return nil
}

// completeProviderLogin runs the shared "authenticated provider user →
// Hydra-accepted login session" flow. It is reused by both the OAuth2 code
// callback and the Google FedCM completion endpoint so the security and
// data-integrity properties stay identical across paths.
//
// On success it returns the URL the browser should navigate to (the value
// Hydra hands back from AcceptLoginRequest) without writing to any response
// — leaving the caller free to do an http.Redirect (server-driven) or to
// encode it into a JSON body for a fetch-driven client.
func (h *AuthServer) completeProviderLogin(
	ctx context.Context,
	req *http.Request,
	loginEvt *models.LoginEvent,
	loggedInUser *providers.AuthenticatedUser,
	provider string,
) (string, error) {
	start := time.Now()
	log := util.Log(ctx).WithFields(map[string]any{
		"provider":       provider,
		"login_event_id": loginEvt.GetID(),
	})

	// Identity S2S (profile) must run with the service bot's JWT home tenancy.
	// User-partition secondary tenancy is re-applied later only if needed for
	// access provisioning (consent / ensureLoginEventTenancyAccess).
	ctx = serviceBotContext(ctx)

	contactDetail := loggedInUser.Contact
	if contactDetail == "" {
		log.Error("external provider did not return a contact (email/phone) for the user")
		return "", fmt.Errorf("no contact detail provided by provider %s", provider)
	}

	// Step 1: Look up existing profile by contact
	log.Debug("looking up user profile by contact")

	result, err := h.profileCli.GetByContact(ctx, connect.NewRequest(&profilev1.GetByContactRequest{Contact: contactDetail}))
	if err != nil {
		if !frame.ErrorIsNotFound(err) {
			log.WithError(err).Error("profile service lookup failed")
			return "", fmt.Errorf("profile lookup failed: %w", err)
		}
		log.Debug("no existing profile found for contact - will create new profile")
	}

	var existingProfile *profilev1.ProfileObject
	if result != nil {
		existingProfile = result.Msg.GetData()
	}

	if existingProfile != nil && existingProfile.GetType() == profilev1.ProfileType_BOT {
		log.WithField("profile_id", existingProfile.GetId()).Warn("bot profile attempted UI login via provider")
		return "", fmt.Errorf("bot accounts cannot log in through the web interface")
	}

	// Step 2: Create profile if not found or if returned profile has empty ID
	if existingProfile == nil || existingProfile.GetId() == "" {
		if existingProfile != nil && existingProfile.GetId() == "" {
			log.Warn("profile service returned profile with empty ID - will create new profile")
			existingProfile = nil // Reset to trigger profile creation
		}
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
			return "", fmt.Errorf("profile creation failed: %w", createErr)
		}
		existingProfile = createResult.Msg.GetData()
		if existingProfile == nil {
			log.Error("profile service returned nil profile after creation")
			return "", fmt.Errorf("profile creation returned invalid response")
		}
		if existingProfile.GetId() == "" {
			log.Error("profile service returned profile with empty ID")
			return "", fmt.Errorf("created profile has empty ID")
		}
		log.WithField("profile_id", existingProfile.GetId()).Info("new profile created for provider login")
	} else {
		log.WithField("profile_id", existingProfile.GetId()).Debug("existing profile found for contact")
	}

	// Step 2.5: Asynchronously import the provider-supplied avatar if any.
	// The consumer skips profiles that already carry an avatar_file_id, so
	// this is safe to emit on every provider login.
	h.maybeEmitAvatarSync(ctx, existingProfile.GetId(), provider, loggedInUser.AvatarURL)

	// Step 3: Find contact ID within the profile
	contactID := ""
	profileContacts := existingProfile.GetContacts()

	for _, profileContact := range profileContacts {
		if strings.EqualFold(strings.TrimSpace(contactDetail), profileContact.GetDetail()) {
			contactID = profileContact.GetId()
			break
		}
	}

	if contactID == "" {
		log.WithField("profile_id", existingProfile.GetId()).
			Error("contact not found within profile - contact/profile linkage is broken")
		return "", fmt.Errorf("contact %q not linked to profile %s", contactDetail, existingProfile.GetId())
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
		return "", fmt.Errorf("login attempt storage failed: %w", err)
	}

	// Step 5: Validate profile ID before accepting login
	profileID := existingProfile.GetId()
	if profileID == "" {
		log.Error("profile ID is empty - cannot complete provider login")
		return "", fmt.Errorf("resolved profile has empty ID")
	}

	// Access provisioning may need the OAuth client partition; hydrate secondary
	// tenancy only for this step (Plane-1 still falls back via Hydra metadata).
	accessCtx := withUserLoginTenancy(ctx, loginEvent)
	loginEvent, err = h.ensureLoginEventTenancyAccess(accessCtx, loginEvent, loginEvt.ClientID, profileID)
	if err != nil {
		log.WithError(err).Error("failed to ensure tenancy access for provider login")
		return "", fmt.Errorf("provider login tenancy access failed: %w", err)
	}

	// Step 6: Accept the Hydra login request to complete the OAuth2 flow
	log.Debug("accepting Hydra login request")

	params := &hydra.AcceptLoginRequestParams{
		LoginChallenge:   loginEvt.LoginChallengeID,
		SubjectID:        profileID,
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
		return "", fmt.Errorf("failed to complete OAuth2 login: %w", err)
	}

	log.WithFields(map[string]any{
		"profile_id":  profileID,
		"duration_ms": time.Since(start).Milliseconds(),
	}).Info("provider login completed successfully")

	h.emitLoginCompleted(ctx, req, profileID, provider, loginEvt.ClientID)

	return redirectURL, nil
}
