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
	"github.com/pitabwire/frame/v2/security/authorizer"
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

// GenesisProofError is a refusal the caller can act on. Status is the HTTP
// status the REST endpoint answers with; the Connect RPC maps it to a code.
type GenesisProofError struct {
	Status int
	Reason string
}

func (e *GenesisProofError) Error() string { return e.Reason }

func proofRefusal(status int, reason string) error {
	return &GenesisProofError{Status: status, Reason: reason}
}

// GenesisProofIssueInput is what a caller supplies; every bound identity
// comes from the verified token instead.
type GenesisProofIssueInput struct {
	PubkeyHash  string
	DeviceKeyID string
	DeviceID    string
}

// GenesisProofVerifyInput is a proof and what the consumer expects of it.
type GenesisProofVerifyInput struct {
	Token       string
	ProfileID   string
	DeviceID    string
	PubkeyHash  string
	DeviceKeyID string
	Consume     bool
}

// GenesisProofVerdict is the outcome of a verification. A proof that fails
// verification is a verdict, not an error.
type GenesisProofVerdict struct {
	Valid       bool
	Reason      string
	Claims      *sessionproof.Claims
	BindingHash string
}

// IssueGenesisSessionProof mints a session proof for the caller's own live
// session on the caller's own device (P26). Every bound identity comes from
// the verified token and the login event behind it; the input carries only
// the device key being registered. Refusals are *GenesisProofError.
func (h *AuthServer) IssueGenesisSessionProof(ctx context.Context, in GenesisProofIssueInput) (*sessionproof.Issued, error) {
	if h.sessionProofIssuer == nil {
		return nil, proofRefusal(http.StatusServiceUnavailable, "genesis session proofs are not configured")
	}
	pubkeyHash := strings.ToLower(strings.TrimSpace(in.PubkeyHash))
	if !pubkeyHashPattern.MatchString(pubkeyHash) {
		return nil, proofRefusal(http.StatusBadRequest, "pubkey_hash must be a 32-byte lowercase hex digest")
	}

	claims := security.ClaimsFromContext(ctx)
	if claims == nil {
		return nil, proofRefusal(http.StatusUnauthorized, "an authenticated session is required")
	}
	if saID, _ := claims.Ext["service_account_id"].(string); strings.TrimSpace(saID) != "" {
		// A machine never holds a session on a device; P26 is about a person.
		return nil, proofRefusal(http.StatusForbidden, "a service account cannot hold a genesis session")
	}
	profileID, deviceID, sessionID := claims.GetProfileID(), claims.GetDeviceID(), claims.GetSessionID()
	if profileID == "" || deviceID == "" || sessionID == "" {
		return nil, proofRefusal(http.StatusForbidden, "the session must identify a profile, a device and a login event")
	}
	if want := strings.TrimSpace(in.DeviceID); want != "" && want != deviceID {
		return nil, proofRefusal(http.StatusForbidden, "device_id does not match the session device")
	}
	if err := h.assertLiveSession(ctx, sessionID, profileID, deviceID); err != nil {
		util.Log(ctx).WithError(err).WithField("session_id", sessionID).
			Warn("genesis session proof refused: no live session on this device")
		return nil, proofRefusal(http.StatusForbidden, "no live authenticated session for this profile on this device")
	}

	issued, err := h.sessionProofIssuer.Issue(sessionproof.IssueRequest{
		ProfileID: profileID, DeviceID: deviceID, PubkeyHash: pubkeyHash,
		DeviceKeyID: strings.TrimSpace(in.DeviceKeyID), SessionID: sessionID,
		TenantID: claims.GetTenantID(), PartitionID: claims.GetPartitionID(),
	})
	if err != nil {
		return nil, err
	}
	util.Log(ctx).WithFields(map[string]any{
		"profile_id": profileID, "device_id": deviceID, "key_id": issued.Claims.KeyID,
	}).Info("issued genesis session proof")
	return issued, nil
}

// VerifyGenesisSessionProof checks a proof for a consumer that would rather
// not carry a verifier, and spends its nonce when asked. Verification itself
// needs nothing from this service: the published keys are enough.
func (h *AuthServer) VerifyGenesisSessionProof(ctx context.Context, in GenesisProofVerifyInput) (*GenesisProofVerdict, error) {
	if h.sessionProofVerifier == nil {
		return nil, proofRefusal(http.StatusServiceUnavailable, "genesis session proofs are not configured")
	}
	if security.ClaimsFromContext(ctx) == nil {
		return nil, proofRefusal(http.StatusUnauthorized, "an authenticated caller is required")
	}
	if err := h.assertMayVerifyGenesisProof(ctx); err != nil {
		return nil, err
	}

	claims, err := h.sessionProofVerifier.Verify(in.Token, sessionproof.Expectation{
		ProfileID: strings.TrimSpace(in.ProfileID), DeviceID: strings.TrimSpace(in.DeviceID),
		PubkeyHash: strings.TrimSpace(in.PubkeyHash), DeviceKeyID: strings.TrimSpace(in.DeviceKeyID),
	})
	if err != nil {
		return &GenesisProofVerdict{Valid: false, Reason: err.Error()}, nil
	}
	if in.Consume {
		fresh, cerr := h.consumeProofNonce(ctx, claims)
		if cerr != nil {
			return nil, cerr
		}
		if !fresh {
			return &GenesisProofVerdict{Valid: false, Reason: sessionproof.ErrReplay.Error()}, nil
		}
	}
	digest := sessionproof.BindingHash(claims)
	return &GenesisProofVerdict{Valid: true, Claims: claims, BindingHash: hex.EncodeToString(digest[:])}, nil
}

// GenesisSessionProofIssueEndpoint is the REST form of IssueGenesisSessionProof.
func (h *AuthServer) GenesisSessionProofIssueEndpoint(rw http.ResponseWriter, req *http.Request) error {
	var body genesisProofIssueRequest
	if err := decodeProofBody(req, &body); err != nil {
		return writeProofError(rw, http.StatusBadRequest, err.Error())
	}
	issued, err := h.IssueGenesisSessionProof(req.Context(), GenesisProofIssueInput(body))
	if refusal := (*GenesisProofError)(nil); errors.As(err, &refusal) {
		return writeProofError(rw, refusal.Status, refusal.Reason)
	} else if err != nil {
		return err
	}
	return writeProofJSON(rw, http.StatusOK, genesisProofIssueResponse{
		Token: issued.Token, KeyID: issued.Claims.KeyID, Algorithm: issued.Claims.Algorithm,
		Nonce: issued.Claims.Nonce, IssuedAt: issued.Claims.IssuedAt, ExpiresAt: issued.Claims.ExpiresAt,
		BindingHash: issued.BindingHash, Audience: issued.Claims.Audience,
	})
}

// GenesisSessionProofVerifyEndpoint is the REST form of VerifyGenesisSessionProof.
func (h *AuthServer) GenesisSessionProofVerifyEndpoint(rw http.ResponseWriter, req *http.Request) error {
	if h.sessionProofVerifier == nil {
		return writeProofError(rw, http.StatusServiceUnavailable, "genesis session proofs are not configured")
	}
	var body genesisProofVerifyRequest
	if err := decodeProofBody(req, &body); err != nil {
		return writeProofError(rw, http.StatusBadRequest, err.Error())
	}
	verdict, err := h.VerifyGenesisSessionProof(req.Context(), GenesisProofVerifyInput(body))
	if refusal := (*GenesisProofError)(nil); errors.As(err, &refusal) {
		return writeProofError(rw, refusal.Status, refusal.Reason)
	} else if err != nil {
		return err
	}
	return writeProofJSON(rw, http.StatusOK, genesisProofVerifyResponse{
		Valid: verdict.Valid, Reason: verdict.Reason, Claims: verdict.Claims, BindingHash: verdict.BindingHash,
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

// consumeProofNonce spends the nonce and reports whether this call was the
// one that spent it. Increment is atomic in the shared cache, so of any number
// of concurrent spends of one nonce exactly one sees 1 and wins.
func (h *AuthServer) consumeProofNonce(ctx context.Context, claims *sessionproof.Claims) (bool, error) {
	kv := h.sessionProofNonces()
	if kv == nil {
		// No store, no single-use guarantee: refuse rather than pretend.
		return false, errors.New("nonce store is unavailable")
	}
	key := "genesis_session_proof:nonce:" + claims.Nonce
	count, err := kv.Increment(ctx, key, 1)
	if err != nil {
		return false, err
	}
	if count != 1 {
		return false, nil
	}
	ttl := nonceTTLMargin
	if expiresAt, perr := time.Parse(sessionproof.TimeLayout, claims.ExpiresAt); perr == nil {
		ttl = time.Until(expiresAt) + nonceTTLMargin
	}
	if err = kv.Expire(ctx, key, ttl); err != nil {
		// Keep the spent record (a lost TTL only costs space); never report
		// the nonce as fresh to anyone else.
		util.Log(ctx).WithError(err).Warn("genesis session proof nonce spent without expiry")
	}
	return true, nil
}

// sessionProofNonces resolves the shared cache used for spent nonces.
func (h *AuthServer) sessionProofNonces() cache.RawCache {
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
	h.proofNonceCache = raw
	return h.proofNonceCache
}

// genesisVerifyPermission is the only grant that may verify (and so spend) a
// proof. Verify with consume burns a person's proof, so it is limited to the
// consumer that acts on it (settlement's service account), not to anyone
// holding a token.
const (
	genesisVerifyNamespace  = "service_authentication"
	genesisVerifyPermission = "auth_genesis_verify"
)

// assertMayVerifyGenesisProof checks the caller holds auth_genesis_verify.
func (h *AuthServer) assertMayVerifyGenesisProof(ctx context.Context) error {
	if h.authorizer == nil {
		return proofRefusal(http.StatusServiceUnavailable, "authorization is unavailable")
	}
	checker := authorizer.NewFunctionChecker(h.authorizer, genesisVerifyNamespace)
	if err := checker.Check(ctx, genesisVerifyPermission); err != nil {
		util.Log(ctx).WithError(err).Warn("genesis session proof verify refused: caller lacks " + genesisVerifyPermission)
		return proofRefusal(http.StatusForbidden, "caller may not verify genesis session proofs")
	}
	return nil
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
