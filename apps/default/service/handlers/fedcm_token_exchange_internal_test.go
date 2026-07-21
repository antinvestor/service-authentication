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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/pitabwire/frame/v2/cache"
	"github.com/stretchr/testify/require"
)

func newExchangeTestServer(t *testing.T) *AuthServer {
	t.Helper()
	cacheMan := cache.NewManager()
	cacheMan.AddCache("auth-cache", cache.NewInMemoryCache())
	return &AuthServer{
		config:   &authconfig.AuthenticationConfig{CacheName: "auth-cache"},
		cacheMan: cacheMan,
	}
}

const testRPOrigin = "https://rp.example.com"

func stashExchangeEntry(t *testing.T, h *AuthServer, idToken, clientID string) {
	t.Helper()
	c, err := h.fedcmExchangeCache()
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(idToken))
	key := fedcmExchangePrefix + hex.EncodeToString(sum[:])
	payload, err := json.Marshal(map[string]any{
		"access_token":  "at",
		"refresh_token": "rt",
		"expires_in":    300,
		"client_id":     clientID,
		"origin":        testRPOrigin,
	})
	require.NoError(t, err)
	require.NoError(t, c.Set(context.Background(), key, string(payload), time.Minute))
}

func exchangeRequest(idToken, clientID, origin string) *http.Request {
	body, _ := json.Marshal(fedcmTokenExchangeRequest{IDToken: idToken, ClientID: clientID})
	req := httptest.NewRequest(http.MethodPost, "/fedcm/token-exchange", strings.NewReader(string(body)))
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return req
}

func TestFedCMTokenExchangeOriginMatch(t *testing.T) {
	h := newExchangeTestServer(t)
	stashExchangeEntry(t, h, "id-token-1", "client-a")

	rec := httptest.NewRecorder()
	require.NoError(t, h.FedCMTokenExchangeEndpoint(rec, exchangeRequest("id-token-1", "client-a", testRPOrigin)))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "\"access_token\":\"at\"")
}

func TestFedCMTokenExchangeRejectsMismatchedOrigin(t *testing.T) {
	h := newExchangeTestServer(t)
	stashExchangeEntry(t, h, "id-token-2", "client-a")

	rec := httptest.NewRecorder()
	require.NoError(t, h.FedCMTokenExchangeEndpoint(rec, exchangeRequest("id-token-2", "client-a", "https://evil.example.com")))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestFedCMTokenExchangeRejectsMissingOriginWhenStashed(t *testing.T) {
	// A stashed origin must be presented back. Omitting the Origin header no
	// longer bypasses the binding.
	h := newExchangeTestServer(t)
	stashExchangeEntry(t, h, "id-token-3", "client-a")

	rec := httptest.NewRecorder()
	require.NoError(t, h.FedCMTokenExchangeEndpoint(rec, exchangeRequest("id-token-3", "client-a", "")))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestFedCMTokenExchangeRejectsMismatchedClientID(t *testing.T) {
	h := newExchangeTestServer(t)
	stashExchangeEntry(t, h, "id-token-4", "client-stashed")

	rec := httptest.NewRecorder()
	require.NoError(t, h.FedCMTokenExchangeEndpoint(rec, exchangeRequest("id-token-4", "client-b", testRPOrigin)))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestFedCMTokenExchangeIsOneShot(t *testing.T) {
	h := newExchangeTestServer(t)
	stashExchangeEntry(t, h, "id-token-5", "client-a")

	rec1 := httptest.NewRecorder()
	require.NoError(t, h.FedCMTokenExchangeEndpoint(rec1, exchangeRequest("id-token-5", "client-a", testRPOrigin)))
	require.Equal(t, http.StatusOK, rec1.Code)

	rec2 := httptest.NewRecorder()
	require.NoError(t, h.FedCMTokenExchangeEndpoint(rec2, exchangeRequest("id-token-5", "client-a", testRPOrigin)))
	require.Equal(t, http.StatusUnauthorized, rec2.Code)
}
