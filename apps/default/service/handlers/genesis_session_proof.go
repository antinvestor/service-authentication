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
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/sessionproof"
	"github.com/pitabwire/frame/v2/cache"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/frame/v2/security/interceptors/httptor"
	"github.com/pitabwire/util"
)

// Paths of the genesis session proof (GFOS §8.2, P26; platform change K9).
const (
	GenesisSessionProofPath       = "/s/genesis/session-proof"
	GenesisSessionProofVerifyPath = "/s/genesis/session-proof/verify"
	GenesisSessionProofKeysPath   = "/.well-known/genesis-session-proof-keys.json"
)

// maxProofRequestBytes bounds the JSON bodies of both endpoints.
const maxProofRequestBytes = 4 << 10

// pubkeyHashPattern is the §8.2 pubkey_hash: a 32-byte lowercase hex digest.
// On EVM that is keccak256(device address); this service binds it without
// interpreting it.
var pubkeyHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// nonceTTLMargin keeps a spent nonce on record past the token's own lifetime
// so a replay cannot wait out the record.
const nonceTTLMargin = time.Hour

type genesisProofIssueRequest struct {
	PubkeyHash  string `json:"pubkey_hash"`
	DeviceKeyID string `json:"device_key_id"`
	// DeviceID is optional and, when present, must equal the session's device.
	DeviceID string `json:"device_id"`
}

type genesisProofIssueResponse struct {
	Token       string `json:"token"`
	KeyID       string `json:"key_id"`
	Algorithm   string `json:"algorithm"`
	Nonce       string `json:"nonce"`
	IssuedAt    string `json:"issued_at"`
	ExpiresAt   string `json:"expires_at"`
	BindingHash string `json:"binding_hash"`
	Audience    string `json:"audience"`
}

type genesisProofVerifyRequest struct {
	Token       string `json:"token"`
	ProfileID   string `json:"profile_id"`
	DeviceID    string `json:"device_id"`
	PubkeyHash  string `json:"pubkey_hash"`
	DeviceKeyID string `json:"device_key_id"`
	// Consume spends the nonce. A consumer that is about to act on the proof
	// sets it; a consumer that is only inspecting does not.
	Consume bool `json:"consume"`
}

type genesisProofVerifyResponse struct {
	Valid       bool                 `json:"valid"`
	Reason      string               `json:"reason,omitempty"`
	Claims      *sessionproof.Claims `json:"claims,omitempty"`
	BindingHash string               `json:"binding_hash,omitempty"`
}

// GenesisSessionProofIssueEndpoint mints a session proof for the caller's own
// live session on the caller's own device (P26). Every bound identity comes
// from the verified token and the login event behind it; the body carries
// only the device key being registered.
func (h *AuthServer) GenesisSessionProofIssueEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	if h.sessionProofIssuer == nil {
		return writeProofError(rw, http.StatusServiceUnavailable, "genesis session proofs are not configured")
	}

	var body genesisProofIssueRequest
	if err := decodeProofBody(req, &body); err != nil {
		return writeProofError(rw, http.StatusBadRequest, err.Error())
	}
	body.PubkeyHash = strings.ToLower(strings.TrimSpace(body.PubkeyHash))
	if !pubkeyHashPattern.MatchString(body.PubkeyHash) {
		return writeProofError(rw, http.StatusBadRequest, "pubkey_hash must be a 32-byte lowercase hex digest")
	}

	claims := security.ClaimsFromContext(ctx)
	if claims == nil {
		return writeProofError(rw, http.StatusUnauthorized, "an authenticated session is required")
	}
	if saID, _ := claims.Ext["service_account_id"].(string); strings.TrimSpace(saID) != "" {
		// A machine never holds a session on a device; P26 is about a person.
		return writeProofError(rw, http.StatusForbidden, "a service account cannot hold a genesis session")
	}
	profileID, deviceID, sessionID := claims.GetProfileID(), claims.GetDeviceID(), claims.GetSessionID()
	if profileID == "" || deviceID == "" || sessionID == "" {
		return writeProofError(rw, http.StatusForbidden, "the session must identify a profile, a device and a login event")
	}
	if want := strings.TrimSpace(body.DeviceID); want != "" && want != deviceID {
		return writeProofError(rw, http.StatusForbidden, "device_id does not match the session device")
	}
	if err := h.assertLiveSession(ctx, sessionID, profileID, deviceID); err != nil {
		util.Log(ctx).WithError(err).WithField("session_id", sessionID).
			Warn("genesis session proof refused: no live session on this device")
		return writeProofError(rw, http.StatusForbidden, "no live authenticated session for this profile on this device")
	}

	issued, err := h.sessionProofIssuer.Issue(sessionproof.IssueRequest{
		ProfileID: profileID, DeviceID: deviceID, PubkeyHash: body.PubkeyHash,
		DeviceKeyID: strings.TrimSpace(body.DeviceKeyID), SessionID: sessionID,
		TenantID: claims.GetTenantID(), PartitionID: claims.GetPartitionID(),
	})
	if err != nil {
		return err
	}
	util.Log(ctx).WithFields(map[string]any{
		"profile_id": profileID, "device_id": deviceID, "key_id": issued.Claims.KeyID,
	}).Info("issued genesis session proof")

	return writeProofJSON(rw, http.StatusOK, genesisProofIssueResponse{
		Token: issued.Token, KeyID: issued.Claims.KeyID, Algorithm: issued.Claims.Algorithm,
		Nonce: issued.Claims.Nonce, IssuedAt: issued.Claims.IssuedAt, ExpiresAt: issued.Claims.ExpiresAt,
		BindingHash: issued.BindingHash, Audience: issued.Claims.Audience,
	})
}

// GenesisSessionProofVerifyEndpoint checks a proof for a consumer that would
// rather not carry a verifier, and spends its nonce when asked. Verification
// itself needs nothing from this service: the published keys are enough.
func (h *AuthServer) GenesisSessionProofVerifyEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	if h.sessionProofVerifier == nil {
		return writeProofError(rw, http.StatusServiceUnavailable, "genesis session proofs are not configured")
	}
	var body genesisProofVerifyRequest
	if err := decodeProofBody(req, &body); err != nil {
		return writeProofError(rw, http.StatusBadRequest, err.Error())
	}
	if security.ClaimsFromContext(ctx) == nil {
		return writeProofError(rw, http.StatusUnauthorized, "an authenticated caller is required")
	}

	claims, err := h.sessionProofVerifier.Verify(body.Token, sessionproof.Expectation{
		ProfileID: strings.TrimSpace(body.ProfileID), DeviceID: strings.TrimSpace(body.DeviceID),
		PubkeyHash: strings.TrimSpace(body.PubkeyHash), DeviceKeyID: strings.TrimSpace(body.DeviceKeyID),
	})
	if err != nil {
		return writeProofJSON(rw, http.StatusOK, genesisProofVerifyResponse{Valid: false, Reason: err.Error()})
	}
	if body.Consume {
		fresh, cerr := h.consumeProofNonce(ctx, claims)
		if cerr != nil {
			return cerr
		}
		if !fresh {
			return writeProofJSON(rw, http.StatusOK, genesisProofVerifyResponse{
				Valid: false, Reason: sessionproof.ErrReplay.Error(),
			})
		}
	}
	digest := sessionproof.BindingHash(claims)
	return writeProofJSON(rw, http.StatusOK, genesisProofVerifyResponse{
		Valid: true, Claims: claims, BindingHash: hex.EncodeToString(digest[:]),
	})
}

// GenesisSessionProofKeysEndpoint publishes the verifying keys so a consumer
// checks a proof offline, exactly as it does for the audit chain.
func (h *AuthServer) GenesisSessionProofKeysEndpoint(rw http.ResponseWriter, _ *http.Request) error {
	if h.sessionProofKeys.Keys == nil {
		return writeProofError(rw, http.StatusServiceUnavailable, "genesis session proofs are not configured")
	}
	rw.Header().Set("Cache-Control", "public, max-age=300")
	return writeProofJSON(rw, http.StatusOK, h.sessionProofKeys)
}

// sessionLookup is the narrow read the liveness check needs; the login event
// repository satisfies it.
type sessionLookup interface {
	GetByID(ctx context.Context, id string) (*models.LoginEvent, error)
}

// liveSessions resolves the lookup, preferring an explicitly injected one.
func (h *AuthServer) liveSessions() sessionLookup {
	if h.sessionLookup != nil {
		return h.sessionLookup
	}
	if h.loginEventRepo == nil {
		return nil
	}
	return h.loginEventRepo
}

// assertLiveSession requires the login event the token names to still be the
// one for this profile on this device. A device row on its own is never
// enough (P26); the person must have authenticated in this session.
func (h *AuthServer) assertLiveSession(ctx context.Context, sessionID, profileID, deviceID string) error {
	lookup := h.liveSessions()
	if lookup == nil {
		return errors.New("login events are unavailable")
	}
	event, err := lookup.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if event == nil {
		return errors.New("login event not found")
	}
	if event.ProfileID != profileID {
		return errors.New("login event belongs to another profile")
	}
	if event.DeviceID != deviceID {
		return errors.New("login event belongs to another device")
	}
	return nil
}

// consumeProofNonce records the nonce and reports whether it was fresh.
func (h *AuthServer) consumeProofNonce(ctx context.Context, claims *sessionproof.Claims) (bool, error) {
	kv := h.sessionProofNonces()
	if kv == nil {
		// No store, no single-use guarantee: refuse rather than pretend.
		return false, errors.New("nonce store is unavailable")
	}
	key := "genesis_session_proof:nonce:" + claims.Nonce
	if _, found, err := kv.Get(ctx, key); err != nil {
		return false, err
	} else if found {
		return false, nil
	}
	ttl := nonceTTLMargin
	if expiresAt, err := time.Parse(sessionproof.TimeLayout, claims.ExpiresAt); err == nil {
		ttl = time.Until(expiresAt) + nonceTTLMargin
	}
	if err := kv.Set(ctx, key, claims.ProfileID, ttl); err != nil {
		return false, err
	}
	return true, nil
}

// sessionProofNonces lazily resolves the shared cache used for spent nonces.
func (h *AuthServer) sessionProofNonces() cache.Cache[string, string] {
	if h.proofNonceCache != nil {
		return h.proofNonceCache
	}
	if h.cacheMan == nil {
		return nil
	}
	raw, ok := h.cacheMan.GetRawCache(h.config.CacheName)
	if !ok {
		return nil
	}
	h.proofNonceCache = cache.NewGenericCache[string, string](raw, func(key string) string { return key })
	return h.proofNonceCache
}

func decodeProofBody(req *http.Request, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, req.Body, maxProofRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errors.New("request body must be a JSON object of the documented shape")
	}
	return nil
}

func writeProofJSON(rw http.ResponseWriter, status int, payload any) error {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	return json.NewEncoder(rw).Encode(payload)
}

func writeProofError(rw http.ResponseWriter, status int, reason string) error {
	return writeProofJSON(rw, status, map[string]string{"error": reason})
}

// setupGenesisSessionProof loads the signing key and builds the issuer, the
// verifier and the published key set. With no key reference configured the
// feature stays off and the endpoints answer 503; with a broken one the
// caller fails the process.
func (h *AuthServer) setupGenesisSessionProof(cfg *aconfig.AuthenticationConfig) error {
	if cfg == nil || strings.TrimSpace(cfg.GenesisProofSigningKeyRef) == "" {
		return nil
	}
	private, err := sessionproof.LoadPrivateKey(
		cfg.GenesisProofSigningKeyRef, cfg.GenesisProofSigningKeyID, cfg.GenesisProofSigningKeyMountDir)
	if err != nil {
		return err
	}
	issuer, err := sessionproof.NewIssuer(cfg.GenesisProofSigningKeyID, private, cfg.GenesisProofTTL, cfg.GenesisProofAudience)
	if err != nil {
		return err
	}
	retired, err := sessionproof.ParseRetiredKeys(cfg.GenesisProofRetiredKeys, time.Now().UTC())
	if err != nil {
		return err
	}
	keys := sessionproof.KeySet{Keys: append([]sessionproof.PublicKey{{
		KeyID: issuer.KeyID(), Algorithm: sessionproof.Algorithm,
		PublicKey: hex.EncodeToString(issuer.PublicKey()), ValidFrom: time.Now().UTC(),
	}}, retired...)}

	h.sessionProofIssuer = issuer
	h.sessionProofKeys = keys
	h.sessionProofVerifier = sessionproof.NewVerifier(keys.Lookup(), cfg.GenesisProofAudience)
	return nil
}

// registerGenesisSessionProofRoutes mounts the genesis session proof
// endpoints. Issue and verify require a verified bearer token: the proof asserts
// that this person held this session on this device, so it can only be
// minted from inside that session. The key set is public — a consumer
// verifies a proof offline and never needs to call this service.
func (h *AuthServer) registerGenesisSessionProofRoutes(router *http.ServeMux) {
	proofAuthenticated := func(f func(w http.ResponseWriter, r *http.Request) error, path, name string) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := f(w, r); err != nil {
				h.writeAPIError(r.Context(), w, err, name)
			}
		})
		authenticated := httptor.AuthenticationMiddleware(handler, h.securityAuth)
		router.Handle("POST "+path, authenticated)
	}
	proofAuthenticated(h.GenesisSessionProofIssueEndpoint, GenesisSessionProofPath, "GenesisSessionProofIssue")
	proofAuthenticated(h.GenesisSessionProofVerifyEndpoint, GenesisSessionProofVerifyPath, "GenesisSessionProofVerify")
	router.HandleFunc("GET "+GenesisSessionProofKeysPath, func(w http.ResponseWriter, r *http.Request) {
		if err := h.GenesisSessionProofKeysEndpoint(w, r); err != nil {
			h.writeAPIError(r.Context(), w, err, "GenesisSessionProofKeys")
		}
	})
}
