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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pitabwire/util"

	"github.com/antinvestor/service-authentication/apps/default/service/handlers/providers"
)

// fedcmGoogleCompleteRequest is the JSON body posted by the /s/login page when
// FedCM with Google as the IdP succeeds. The id_token is the JWT Chrome hands
// back from navigator.credentials.get({identity: …}); loginEventId binds the
// completion to the active Hydra login_challenge so attackers can't smuggle
// a token across sessions.
type fedcmGoogleCompleteRequest struct {
	LoginEventID string `json:"login_event_id"`
	IDToken      string `json:"id_token"`
}

// fedcmGoogleCompleteResponse mirrors the shape of /s/login/{id}/fedcm-complete
// so the frontend can dispatch on a single redirect_url field regardless of
// which FedCM provider succeeded.
type fedcmGoogleCompleteResponse struct {
	RedirectURL string `json:"redirect_url"`
}

// Bound the JSON request body to a sensible upper limit. Google id_tokens are
// typically ~1KB; we leave generous headroom for future claim additions but
// refuse anything that smells like a memory-exhaustion probe.
const fedcmGoogleCompleteMaxBody = 8 * 1024

// FedCMGoogleCompleteEndpoint serves POST /s/social/google/fedcm-complete.
//
// It accepts a Google-signed id_token produced by the browser's FedCM flow on
// the /s/login page, validates it against every safety property the OAuth
// code-callback path enforces (iss, aud, exp, signature, nonce, email
// verification), and then drives the same Hydra AcceptLoginRequest +
// profile-resolution flow used by the redirect-based provider callback.
//
// The endpoint is intentionally *not* covered by the CSRF middleware: it is a
// JSON fetch from same-origin JavaScript, so we gate it on:
//  1. Sec-Fetch-Site: same-origin (browsers stamp this on fetches; bots
//     emulating it without same-origin cookies cannot impersonate a user)
//  2. The id_token's signature, aud, iss and nonce binding to the server-issued
//     LoginEvent.fedcm_nonce — only a Google-signed token with the nonce we
//     just minted will pass
//  3. Hydra's single-use login_challenge — even a valid replay can only
//     complete the OAuth flow once
//
// On any verification failure the response body is a generic JSON error and
// the response status reflects the category (400 for malformed input, 401 for
// failed token verification, 5xx for internal errors). Detailed reasons stay
// in server logs so attackers can't enumerate failure modes.
func (h *AuthServer) FedCMGoogleCompleteEndpoint(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	log := util.Log(ctx)
	start := time.Now()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	// Step 1: Reject any cross-site fetch. Sec-Fetch-Site is browser-stamped
	// and cannot be forged by JavaScript in another origin's context.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		log.WithField("sec_fetch_site", site).Warn("rejected cross-site Google FedCM completion")
		return writeFedCMError(w, http.StatusForbidden, "invalid_request")
	}

	// Step 2: Decode + bound the body before doing any expensive work.
	var body fedcmGoogleCompleteRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, fedcmGoogleCompleteMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		log.WithError(err).Debug("malformed Google FedCM completion body")
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}
	if body.LoginEventID == "" || body.IDToken == "" {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}

	// Step 3: Rate-limit by IP. Same limiter as the contact-verification flow
	// to share the per-IP budget across all login mechanisms.
	if result := h.CheckLoginRateLimit(ctx, util.GetIP(r)); !result.Allowed {
		return writeFedCMError(w, http.StatusTooManyRequests, "rate_limited")
	}

	log = log.WithField("login_event_id", body.LoginEventID)

	// Step 4: Look up the LoginEvent + pull the expected nonce. If either is
	// missing we treat the request as forged/expired and refuse — without a
	// server-bound nonce we cannot prove the id_token belongs to this login.
	loginEvt, err := h.getLoginEventFromCache(ctx, body.LoginEventID)
	if err != nil || loginEvt == nil {
		log.WithError(err).Warn("login event not found for Google FedCM completion")
		return writeFedCMError(w, http.StatusUnauthorized, "invalid_request")
	}

	expectedNonce, ok := loginEventStringProperty(loginEvt.Properties, loginEventPropertyFedCMNonce)
	if !ok || expectedNonce == "" {
		log.Warn("login event missing FedCM nonce — refusing Google FedCM completion")
		return writeFedCMError(w, http.StatusUnauthorized, "invalid_request")
	}

	// Step 5: Resolve the Google provider. We require it to be configured;
	// otherwise this endpoint should not have been reached and we refuse
	// rather than degrading to a generic OAuth fallback the caller didn't
	// ask for.
	googleProvider, perr := h.resolveGoogleFedCMProvider()
	if perr != nil {
		log.WithError(perr).Error("Google provider unavailable for FedCM completion")
		return writeFedCMError(w, http.StatusServiceUnavailable, "provider_unavailable")
	}

	// Step 6: Verify the id_token. VerifyIDToken validates signature, iss,
	// aud, exp, email_verified and the nonce against the value we stored
	// server-side when the page was rendered.
	user, verifyErr := googleProvider.VerifyIDToken(ctx, body.IDToken, expectedNonce)
	if verifyErr != nil {
		log.WithError(verifyErr).Warn("Google FedCM id_token verification failed")
		h.emitAnalyticsEvent(ctx, r, "", evtFedCMGoogleFailed, map[string]any{
			"login_event_id": body.LoginEventID,
			"client_id":      loginEvt.ClientID,
			"reason":         "id_token_verification",
		})
		return writeFedCMError(w, http.StatusUnauthorized, "invalid_token")
	}

	// Step 7: Enrich tenancy on the LoginEvent if the redirect-based flow
	// hasn't already done so. The contact-login path runs this synchronously
	// in LoginEndpointShow; the social-redirect path runs it in the callback;
	// we mirror the same guard here so all three converge to the same
	// tenancy-populated LoginEvent state.
	if loginEvt.TenantID == "" || loginEvt.PartitionID == "" {
		h.updateTenancyForLoginEvent(ctx, body.LoginEventID)

		loginEvt, err = h.getLoginEventFromCache(ctx, body.LoginEventID)
		if err != nil || loginEvt == nil {
			log.WithError(err).Error("failed to reload login event after tenancy enrichment")
			return writeFedCMError(w, http.StatusInternalServerError, "server_error")
		}
		if loginEvt.TenantID == "" || loginEvt.PartitionID == "" {
			log.WithField("client_id", loginEvt.ClientID).Error("login event still missing tenancy info after enrichment")
			return writeFedCMError(w, http.StatusInternalServerError, "tenancy_resolution_failed")
		}
	}

	// Service-bot context for profile S2S (see serviceBotContext docs).
	ctx = serviceBotContext(ctx)

	// Step 8: Run the shared profile-resolution + Hydra-acceptance path.
	redirectURL, runErr := h.completeProviderLogin(ctx, r, loginEvt, user, googleProvider.Name())
	if runErr != nil {
		log.WithError(runErr).Error("Google FedCM provider login completion failed")
		h.emitAnalyticsEvent(ctx, r, "", evtFedCMGoogleFailed, map[string]any{
			"login_event_id": body.LoginEventID,
			"client_id":      loginEvt.ClientID,
			"reason":         "post_auth_failure",
		})
		return writeFedCMError(w, http.StatusInternalServerError, "completion_failed")
	}

	h.emitAnalyticsEvent(ctx, r, "", evtFedCMGoogleSuccess, map[string]any{
		"login_event_id": body.LoginEventID,
		"client_id":      loginEvt.ClientID,
	})

	log.WithFields(map[string]any{
		"profile_present": user.Contact != "",
		"duration_ms":     time.Since(start).Milliseconds(),
	}).Info("Google FedCM login completed successfully")

	// Note on Set-Login: this response is a fetch, not a top-level navigation,
	// so the browser ignores Set-Login here. The subsequent top-level
	// navigation to the Hydra redirect URL (which routes back through
	// /s/consent) is where we emit it.
	return json.NewEncoder(w).Encode(fedcmGoogleCompleteResponse{RedirectURL: redirectURL})
}

// errGoogleFedCMNotConfigured is returned when the Google provider has not
// been initialised — typically because AUTH_PROVIDER_GOOGLE_CLIENT_ID is
// empty in the deployment.
var errGoogleFedCMNotConfigured = errors.New("google provider is not configured")

// resolveGoogleFedCMProvider narrows the auth-provider registry down to the
// concrete Google implementation. We need the concrete type so the FedCM
// endpoint can call VerifyIDToken — which is intentionally not on the generic
// AuthProvider interface (other providers don't issue id_tokens via FedCM
// today, and adding the method to the interface would force them all to
// stub it).
func (h *AuthServer) resolveGoogleFedCMProvider() (*providers.GoogleOIDCProvider, error) {
	provider, ok := h.loginAuthProviders["google"]
	if !ok {
		return nil, errGoogleFedCMNotConfigured
	}
	google, ok := provider.(*providers.GoogleOIDCProvider)
	if !ok {
		return nil, fmt.Errorf("unexpected concrete type %T for google provider", provider)
	}
	if google.ClientID() == "" {
		return nil, errGoogleFedCMNotConfigured
	}
	return google, nil
}

// loginEventStringProperty extracts a string-typed property from the LoginEvent
// properties map, returning ("", false) when the property is missing or holds
// a non-string value. The cache round-trips Properties as map[string]any so
// callers need a typed accessor to avoid scattered type assertions.
func loginEventStringProperty(props map[string]any, key string) (string, bool) {
	if props == nil {
		return "", false
	}
	v, ok := props[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
