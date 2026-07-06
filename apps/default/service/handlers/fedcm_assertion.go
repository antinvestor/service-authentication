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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pitabwire/frame/v2/cache"
	"github.com/pitabwire/util"

	"github.com/antinvestor/service-authentication/apps/default/service/fedcm"
)

type fedcmAssertionRequest struct {
	ClientID            string `json:"client_id"`
	Nonce               string `json:"nonce"`
	AccountID           string `json:"account_id"`
	DisclosureTextShown bool   `json:"disclosure_text_shown"`
	DisclosureShownFor  string `json:"disclosure_shown_for"`
}

// FedCMIdAssertionEndpoint serves POST /fedcm/id-assertion.
//
// It runs the headless Hydra flow for the RP identified by client_id against
// the profile selected in the browser's idp_session, returns {token: id_token},
// and stashes access/refresh tokens in a one-shot cache entry for the
// follow-up /fedcm/token-exchange call.
func (h *AuthServer) FedCMIdAssertionEndpoint(w http.ResponseWriter, r *http.Request) error {
	setFedCMCORSHeaders(w, r)

	if r.Header.Get("Sec-Fetch-Dest") != "webidentity" {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}

	ctx := r.Context()
	log := util.Log(ctx)

	var body fedcmAssertionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}
	if body.ClientID == "" || body.Nonce == "" || body.AccountID == "" {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}
	if len(body.Nonce) > 128 {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}

	// Resolve RP's OAuth2 client for origin validation + scopes + secret.
	hydraCli, err := h.defaultHydraCli.GetOAuth2Client(ctx, body.ClientID)
	if err != nil {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}
	ok, err := fedcm.OriginMatchesRedirectURIs(origin, hydraCli.GetRedirectUris())
	if err != nil || !ok {
		return writeFedCMError(w, http.StatusForbidden, "invalid_request")
	}

	if h.fedcmRevocation != nil {
		revoked, rerr := h.fedcmRevocation.IsRevoked(ctx, body.AccountID, body.ClientID)
		if rerr != nil {
			return writeFedCMError(w, http.StatusInternalServerError, "server_error")
		}
		if revoked {
			return writeFedCMError(w, http.StatusForbidden, "access_denied")
		}
	}

	session, err := h.fedcmSession.Read(r)
	if err != nil {
		return writeFedCMError(w, http.StatusInternalServerError, "server_error")
	}
	entry, found := session.Find(body.AccountID)
	if !found {
		return writeFedCMError(w, http.StatusUnauthorized, "not_signed_in")
	}

	// Resolve partition (tenancy context) via the same path the consent
	// handler uses.
	partition, perr := h.resolvePartitionByClientID(ctx, body.ClientID)
	if perr != nil || partition == nil {
		return writeFedCMError(w, http.StatusInternalServerError, "server_error")
	}

	// Resolve (or create) the tenancy access record for this profile+partition.
	// The webhook requires a non-empty access_id; without it the token enrichment
	// will be rejected. We use the same method the consent handler uses so the
	// access record is consistent across both flows.
	accessObj, aerr := h.getOrCreateTenancyAccessByPartitionID(ctx, partition, entry.ProfileID)
	accessID := ""
	if aerr != nil {
		log.WithError(aerr).Warn("fedcm: access record lookup failed; access_id will be empty")
	} else if accessObj != nil {
		accessID = accessObj.GetId()
	}

	// Fetch roles from the access record using partition default role,
	// matching the behaviour of the normal consent handler.
	defaultRole := partitionDefaultRole(partition)
	roles := h.fetchAccessRoleNames(ctx, accessID, defaultRole)
	if len(roles) == 0 {
		roles = []string{"user"}
	}

	claims := map[string]any{
		"tenant_id":         partition.GetTenantId(),
		"partition_id":      partition.GetId(),
		"profile_id":        entry.ProfileID,
		"device_id":         entry.DeviceID,
		"login_event_id":    entry.LoginEventID,
		"session_id":        entry.LoginEventID,
		"oauth2_session_id": "",
		"access_id":         accessID,
		"contact_id":        "",
		"roles":             roles,
	}

	scopes := []string{"openid", "profile", "email"}
	if raw := strings.TrimSpace(hydraCli.GetScope()); raw != "" {
		scopes = strings.Fields(raw)
	}

	clientSecret := hydraCli.GetClientSecret()

	amr := []string{"fedcm"}
	if entry.AuthMethod != "" {
		amr = []string{entry.AuthMethod}
	}

	result, err := h.fedcmDriver.Run(ctx, fedcm.HeadlessRequest{
		ClientID:     body.ClientID,
		ClientSecret: clientSecret,
		SubjectID:    entry.ProfileID,
		Nonce:        body.Nonce,
		Scopes:       scopes,
		Claims:       claims,
		ACR:          "fedcm",
		AMR:          amr,
		DeviceID:     entry.DeviceID,
	})
	if err != nil {
		log.WithError(err).Error("fedcm headless flow failed")
		return writeFedCMError(w, http.StatusUnauthorized, "not_signed_in")
	}

	// Touch session entry to extend sliding TTL.
	entry.LastUsedAt = time.Now()
	session.Upsert(entry)
	session.LastActive = time.Now()
	if werr := h.fedcmSession.Write(w, r, session); werr != nil {
		log.WithError(werr).Warn("rewrite idp_session after id-assertion")
	}

	// Stash access/refresh tokens for the follow-up /fedcm/token-exchange call.
	h.stashFedCMExchange(ctx, result.IDToken, body.ClientID, origin, result)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return json.NewEncoder(w).Encode(map[string]string{"token": result.IDToken})
}

func (h *AuthServer) stashFedCMExchange(ctx context.Context, idToken, clientID, origin string, r *fedcm.HeadlessResult) {
	if h.cacheMan == nil || idToken == "" {
		return
	}
	log := util.Log(ctx)

	sum := sha256.Sum256([]byte(idToken))
	key := "fedcm:exchange:" + hex.EncodeToString(sum[:])

	payload, merr := json.Marshal(map[string]any{
		"access_token":  r.AccessToken,
		"refresh_token": r.RefreshToken,
		"expires_in":    r.ExpiresIn,
		"client_id":     clientID,
		"origin":        origin,
	})
	if merr != nil {
		log.WithError(merr).Warn("fedcm exchange marshal failed")
		return
	}

	cacheObj, cerr := h.fedcmExchangeCache()
	if cerr != nil {
		log.WithError(cerr).Warn("fedcm exchange cache unavailable")
		return
	}
	if err := cacheObj.Set(ctx, key, string(payload), 60*time.Second); err != nil {
		log.WithError(err).Warn("fedcm exchange cache set failed")
	}
}

// fedcmExchangeCache returns a lazily-initialised cache for stashing post-
// id-assertion token payloads. Mirrors the pattern used by the revocation KV
// in fedcm_wiring.go (GetRawCache + NewGenericCache).
func (h *AuthServer) fedcmExchangeCache() (cache.Cache[string, string], error) {
	cacheName := "defaultCache"
	if h.config != nil && strings.TrimSpace(h.config.CacheName) != "" {
		cacheName = h.config.CacheName
	}
	rCache, ok := h.cacheMan.GetRawCache(cacheName)
	if !ok {
		return nil, errFedCMCacheUnavailable
	}
	return cache.NewGenericCache[string, string](rCache, func(key string) string {
		return key
	}), nil
}

// errFedCMCacheUnavailable is returned when the underlying cache backend is
// not yet available, allowing the caller to log and skip non-critical stash ops.
var errFedCMCacheUnavailable = fmt.Errorf("fedcm exchange cache backend unavailable")
