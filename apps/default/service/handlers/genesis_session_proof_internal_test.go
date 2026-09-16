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
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/sessionproof"
	"github.com/pitabwire/frame/v2/cache"
	"github.com/pitabwire/frame/v2/security"
	"github.com/stretchr/testify/require"
)

// proofTestSeed is a throwaway Ed25519 seed; it never leaves the test.
const proofTestSeed = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"

type stubSessions struct {
	event *models.LoginEvent
	err   error
}

func (s stubSessions) GetByID(_ context.Context, _ string) (*models.LoginEvent, error) {
	return s.event, s.err
}

func liveEvent() *models.LoginEvent {
	event := &models.LoginEvent{ProfileID: "profile-1", DeviceID: "device-1"}
	event.ID = "login-event-1"
	return event
}

func proofServer(t *testing.T, sessions sessionLookup) *AuthServer {
	t.Helper()
	dir := t.TempDir()
	keyPath := dir + "/gsp-k1"
	require.NoError(t, os.WriteFile(keyPath, []byte(proofTestSeed), 0o600))

	cfg := &aconfig.AuthenticationConfig{
		GenesisProofSigningKeyRef: "file://" + keyPath,
		GenesisProofSigningKeyID:  "gsp-k1",
		GenesisProofTTL:           5 * time.Minute,
		GenesisProofAudience:      "stawi-genesis",
	}
	h := &AuthServer{config: cfg, sessionLookup: sessions}
	require.NoError(t, h.setupGenesisSessionProof(cfg))
	h.proofNonceCache = cache.NewGenericCache[string, string](cache.NewInMemoryCache(), func(key string) string { return key })
	return h
}

func personContext(t *testing.T, sessionID string) context.Context {
	t.Helper()
	claims := &security.AuthenticationClaims{
		TenantID: "tenant-1", PartitionID: "partition-1",
		ProfileID: "profile-1", DeviceID: "device-1", SessionID: sessionID,
	}
	return claims.ClaimsToContext(t.Context())
}

func postProof(t *testing.T, ctx context.Context, path string, body any,
	call func(http.ResponseWriter, *http.Request) error) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw))).WithContext(ctx)
	rw := httptest.NewRecorder()
	require.NoError(t, call(rw, req))
	out := map[string]any{}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &out))
	return rw.Code, out
}

// TestGenesisSessionProof_IssuedOnlyInsideALiveSessionOnThatDevice is P26:
// the proof is minted from the session's own identities, and a caller who
// cannot show a live session on that device gets nothing.
func TestGenesisSessionProof_IssuedOnlyInsideALiveSessionOnThatDevice(t *testing.T) {
	pubkeyHash := strings.Repeat("ab", 32)

	t.Run("issued inside the session", func(t *testing.T) {
		h := proofServer(t, stubSessions{event: liveEvent()})
		ctx := personContext(t, "login-event-1")
		status, body := postProof(t, ctx, GenesisSessionProofPath,
			genesisProofIssueRequest{PubkeyHash: pubkeyHash, DeviceKeyID: "devkey-1"},
			h.GenesisSessionProofIssueEndpoint)
		require.Equal(t, http.StatusOK, status, body)

		claims, _, err := sessionproof.Decode(body["token"].(string))
		require.NoError(t, err)
		require.Equal(t, "profile-1", claims.ProfileID)
		require.Equal(t, "device-1", claims.DeviceID)
		require.Equal(t, "login-event-1", claims.SessionID)
		require.Equal(t, pubkeyHash, claims.PubkeyHash)
		digest := sessionproof.BindingHash(claims)
		require.Equal(t, body["binding_hash"], hex.EncodeToString(digest[:]))
	})

	t.Run("no session claims", func(t *testing.T) {
		h := proofServer(t, stubSessions{event: liveEvent()})
		ctx := personContext(t, "")
		status, _ := postProof(t, ctx, GenesisSessionProofPath,
			genesisProofIssueRequest{PubkeyHash: pubkeyHash}, h.GenesisSessionProofIssueEndpoint)
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("session belongs to another device", func(t *testing.T) {
		other := liveEvent()
		other.DeviceID = "device-2"
		h := proofServer(t, stubSessions{event: other})
		ctx := personContext(t, "login-event-1")
		status, _ := postProof(t, ctx, GenesisSessionProofPath,
			genesisProofIssueRequest{PubkeyHash: pubkeyHash}, h.GenesisSessionProofIssueEndpoint)
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("a device row is not a session", func(t *testing.T) {
		h := proofServer(t, stubSessions{err: errors.New("not found")})
		ctx := personContext(t, "login-event-1")
		status, _ := postProof(t, ctx, GenesisSessionProofPath,
			genesisProofIssueRequest{PubkeyHash: pubkeyHash}, h.GenesisSessionProofIssueEndpoint)
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("body device must match the session", func(t *testing.T) {
		h := proofServer(t, stubSessions{event: liveEvent()})
		ctx := personContext(t, "login-event-1")
		status, _ := postProof(t, ctx, GenesisSessionProofPath,
			genesisProofIssueRequest{PubkeyHash: pubkeyHash, DeviceID: "device-2"},
			h.GenesisSessionProofIssueEndpoint)
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("pubkey hash must be a digest", func(t *testing.T) {
		h := proofServer(t, stubSessions{event: liveEvent()})
		ctx := personContext(t, "login-event-1")
		status, _ := postProof(t, ctx, GenesisSessionProofPath,
			genesisProofIssueRequest{PubkeyHash: "not-a-digest"}, h.GenesisSessionProofIssueEndpoint)
		require.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("service accounts never hold a genesis session", func(t *testing.T) {
		h := proofServer(t, stubSessions{event: liveEvent()})
		claims := &security.AuthenticationClaims{
			TenantID: "tenant-1", ProfileID: "profile-1", DeviceID: "device-1", SessionID: "login-event-1",
			Ext: map[string]any{"service_account_id": "sa-1"},
		}
		status, _ := postProof(t, claims.ClaimsToContext(t.Context()), GenesisSessionProofPath,
			genesisProofIssueRequest{PubkeyHash: pubkeyHash}, h.GenesisSessionProofIssueEndpoint)
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("unconfigured service issues nothing", func(t *testing.T) {
		h := &AuthServer{config: &aconfig.AuthenticationConfig{}}
		ctx := personContext(t, "login-event-1")
		status, _ := postProof(t, ctx, GenesisSessionProofPath,
			genesisProofIssueRequest{PubkeyHash: pubkeyHash}, h.GenesisSessionProofIssueEndpoint)
		require.Equal(t, http.StatusServiceUnavailable, status)
	})
}

// TestGenesisSessionProof_VerifyRefusesReplayAndWrongDevice covers the
// consumer-facing endpoint: a proof verifies once, its nonce is then spent,
// and it never verifies for another device.
func TestGenesisSessionProof_VerifyRefusesReplayAndWrongDevice(t *testing.T) {
	h := proofServer(t, stubSessions{event: liveEvent()})
	ctx := personContext(t, "login-event-1")
	pubkeyHash := strings.Repeat("ab", 32)

	status, issued := postProof(t, ctx, GenesisSessionProofPath,
		genesisProofIssueRequest{PubkeyHash: pubkeyHash, DeviceKeyID: "devkey-1"},
		h.GenesisSessionProofIssueEndpoint)
	require.Equal(t, http.StatusOK, status)
	token := issued["token"].(string)

	status, body := postProof(t, ctx, GenesisSessionProofVerifyPath,
		genesisProofVerifyRequest{Token: token, ProfileID: "profile-1", DeviceID: "device-1",
			PubkeyHash: pubkeyHash, DeviceKeyID: "devkey-1", Consume: true},
		h.GenesisSessionProofVerifyEndpoint)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, true, body["valid"], body["reason"])
	require.Equal(t, issued["binding_hash"], body["binding_hash"])

	// Second use of the same nonce is a replay.
	_, replay := postProof(t, ctx, GenesisSessionProofVerifyPath,
		genesisProofVerifyRequest{Token: token, Consume: true}, h.GenesisSessionProofVerifyEndpoint)
	require.Equal(t, false, replay["valid"])
	require.Contains(t, replay["reason"], "nonce")

	// Wrong device, fresh nonce.
	_, second := postProof(t, ctx, GenesisSessionProofPath,
		genesisProofIssueRequest{PubkeyHash: pubkeyHash}, h.GenesisSessionProofIssueEndpoint)
	_, wrongDevice := postProof(t, ctx, GenesisSessionProofVerifyPath,
		genesisProofVerifyRequest{Token: second["token"].(string), DeviceID: "device-2"},
		h.GenesisSessionProofVerifyEndpoint)
	require.Equal(t, false, wrongDevice["valid"])
	require.Contains(t, wrongDevice["reason"], "another device")
}

// TestGenesisSessionProof_KeysArePublished is what lets a consumer verify a
// proof without calling this service at all.
func TestGenesisSessionProof_KeysArePublished(t *testing.T) {
	h := proofServer(t, stubSessions{event: liveEvent()})
	req := httptest.NewRequest(http.MethodGet, GenesisSessionProofKeysPath, nil)
	rw := httptest.NewRecorder()
	require.NoError(t, h.GenesisSessionProofKeysEndpoint(rw, req))
	require.Equal(t, http.StatusOK, rw.Code)
	require.Equal(t, "public, max-age=300", rw.Header().Get("Cache-Control"))

	var set sessionproof.KeySet
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &set))
	require.Len(t, set.Keys, 1)
	require.Equal(t, "gsp-k1", set.Keys[0].KeyID)
	require.Equal(t, sessionproof.Algorithm, set.Keys[0].Algorithm)

	// A proof issued now verifies against the published set alone.
	ctx := personContext(t, "login-event-1")
	_, issued := postProof(t, ctx, GenesisSessionProofPath,
		genesisProofIssueRequest{PubkeyHash: strings.Repeat("ab", 32)}, h.GenesisSessionProofIssueEndpoint)
	offline := sessionproof.NewVerifier(set.Lookup(), "stawi-genesis")
	claims, err := offline.Verify(issued["token"].(string), sessionproof.Expectation{ProfileID: "profile-1"})
	require.NoError(t, err)
	require.Equal(t, "device-1", claims.DeviceID)
}
