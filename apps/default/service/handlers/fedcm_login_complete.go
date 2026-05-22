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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/pitabwire/util"

	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
)

type fedcmCompleteLoginRequest struct {
	IDToken string `json:"id_token"`
}

type fedcmCompleteLoginResponse struct {
	RedirectURL string `json:"redirect_url"`
}

// FedCMCompleteLogin accepts a FedCM id_token produced on the /s/login page's
// probe and, if valid and matching the active login_challenge, accepts the
// challenge against Hydra and returns the redirect URL the page should follow.
func (h *AuthServer) FedCMCompleteLogin(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	log := util.Log(ctx)

	loginEventID := r.PathValue("loginEventId")
	if loginEventID == "" {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}

	var body fedcmCompleteLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}
	if body.IDToken == "" {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}

	ev, err := h.getLoginEventFromCache(ctx, loginEventID)
	if err != nil || ev == nil {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}

	// Confirm the id_token came from our own FedCM path. The freshness cache
	// was written by /fedcm/id-assertion; without this check we'd accept any
	// token the browser can present.
	if !h.fedcmIDTokenIsFresh(ctx, body.IDToken) {
		log.Warn("fedcm-complete: id_token not found in freshness cache")
		return writeFedCMError(w, http.StatusUnauthorized, "invalid_token")
	}

	// Extract the subject without re-verifying Hydra's JWT signature; the
	// freshness cache already binds the token to our own recent issuance.
	subject, claimErr := readIDTokenSubject(body.IDToken)
	if claimErr != nil {
		return writeFedCMError(w, http.StatusUnauthorized, "invalid_token")
	}

	params := &hydra.AcceptLoginRequestParams{
		LoginChallenge:   ev.LoginChallengeID,
		SubjectID:        subject,
		Remember:         h.config.SessionRememberDuration > 0,
		RememberDuration: h.config.SessionRememberDuration,
	}

	redirectURL, err := h.defaultHydraCli.AcceptLoginRequest(ctx, params, nil, "fedcm", "fedcm")
	if err != nil {
		log.WithError(err).Error("fedcm-complete: AcceptLoginRequest failed")
		h.emitAnalyticsEvent(ctx, r, subject, evtFedCMSelfFailed, map[string]any{
			"login_event_id": loginEventID,
			"client_id":      ev.ClientID,
			"reason":         "accept_login_failed",
		})
		return writeFedCMError(w, http.StatusInternalServerError, "server_error")
	}

	h.emitLoginCompleted(ctx, r, subject, "self_fedcm", ev.ClientID)
	h.emitAnalyticsEvent(ctx, r, subject, evtFedCMSelfSuccess, map[string]any{
		"login_event_id": loginEventID,
		"client_id":      ev.ClientID,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(fedcmCompleteLoginResponse{RedirectURL: redirectURL})
}

// fedcmIDTokenIsFresh returns true if id_token has an active entry in the
// fedcm_exchange cache. Does NOT delete the entry — deletion happens on
// /fedcm/token-exchange.
func (h *AuthServer) fedcmIDTokenIsFresh(ctx context.Context, idToken string) bool {
	if h.cacheMan == nil || idToken == "" {
		return false
	}
	sum := sha256.Sum256([]byte(idToken))
	key := "fedcm:exchange:" + hex.EncodeToString(sum[:])
	c, err := h.fedcmExchangeCache()
	if err != nil {
		return false
	}
	_, ok, err := c.Get(ctx, key)
	if err != nil {
		return false
	}
	return ok
}

// readIDTokenSubject decodes the middle segment of a JWT and returns its
// `sub` claim. It does NOT verify the signature; callers must have already
// confirmed the token's provenance through another mechanism.
func readIDTokenSubject(idToken string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("id_token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", fmt.Errorf("unmarshal JWT claims: %w", err)
	}
	if claims.Sub == "" {
		return "", fmt.Errorf("JWT missing sub claim")
	}
	return claims.Sub, nil
}
