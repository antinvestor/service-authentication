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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/nativecredentials"
	"github.com/stretchr/testify/require"
)

func TestAudienceForIssuer(t *testing.T) {
	cfg := nativeClientConfig{GoogleAudience: "g-aud", AppleAudience: "a-aud"}
	cases := []struct {
		issuer string
		want   string
	}{
		{nativecredentials.GoogleIssuer, "g-aud"},
		{nativecredentials.GoogleIssuer + "/", "g-aud"},
		{nativecredentials.GoogleIssuerShort, "g-aud"},
		{" " + nativecredentials.AppleIssuer + " ", "a-aud"},
		{"https://evil.example.com", ""},
		{"", ""},
	}
	for _, tc := range cases {
		require.Equalf(t, tc.want, cfg.audienceForIssuer(tc.issuer), "issuer %q", tc.issuer)
	}
}

func TestAudienceForIssuerUnsetReturnsEmpty(t *testing.T) {
	cfg := nativeClientConfig{}
	require.Empty(t, cfg.audienceForIssuer(nativecredentials.GoogleIssuer))
	require.Empty(t, cfg.audienceForIssuer(nativecredentials.AppleIssuer))
}

func TestNativeClientConfigFromPropertiesUsesServerProviderConfig(t *testing.T) {
	h := &AuthServer{config: &authconfig.AuthenticationConfig{
		AuthProviderGoogleClientID: "server-google-client.apps.googleusercontent.com",
		AuthProviderAppleClientID:  "com.example.server.apple",
	}}

	cfg := h.nativeClientConfigFromProperties("client-123", map[string]any{
		"native_auth_enabled": true,
	})

	require.Equal(t, "client-123", cfg.ClientID)
	require.True(t, cfg.Enabled)
	require.Equal(t, "server-google-client.apps.googleusercontent.com", cfg.GoogleAudience)
	require.Equal(t, "com.example.server.apple", cfg.AppleAudience)
}

func TestNativeClientConfigFromPropertiesRequiresExplicitNativeOptIn(t *testing.T) {
	h := &AuthServer{config: &authconfig.AuthenticationConfig{
		AuthProviderGoogleClientID: "server-google-client.apps.googleusercontent.com",
	}}

	cfg := h.nativeClientConfigFromProperties("client-123", map[string]any{})

	require.False(t, cfg.Enabled)
	require.Equal(t, "server-google-client.apps.googleusercontent.com", cfg.GoogleAudience)
}

func TestBoolProperty(t *testing.T) {
	require.True(t, boolProperty(map[string]any{"k": true}, "k"))
	require.True(t, boolProperty(map[string]any{"k": "true"}, "k"))
	require.True(t, boolProperty(map[string]any{"k": "TRUE"}, "k"))
	require.True(t, boolProperty(map[string]any{"k": "1"}, "k"))
	require.False(t, boolProperty(map[string]any{"k": "false"}, "k"))
	require.False(t, boolProperty(map[string]any{"k": 1}, "k"))
	require.False(t, boolProperty(map[string]any{}, "k"))
}

func TestTokenScopesDefaults(t *testing.T) {
	require.Equal(t, []string{"openid", "profile", "email", "offline_access"}, tokenScopes(""))
	require.Equal(t, []string{"openid", "profile", "email", "offline_access"}, tokenScopes("   "))
	require.Equal(t, []string{"openid", "email"}, tokenScopes("openid email"))
}

func TestClientIPPrefersForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	r.RemoteAddr = "10.0.0.9:5555"
	require.Equal(t, "10.0.0.9", clientIP(r))

	r.Header.Set("X-Real-IP", "203.0.113.7")
	require.Equal(t, "203.0.113.7", clientIP(r))

	r.Header.Set("X-Forwarded-For", "198.51.100.4, 70.41.3.18")
	require.Equal(t, "198.51.100.4", clientIP(r))
}

func TestSameHTTPHost(t *testing.T) {
	require.True(t, sameHTTPHost("https://Accounts.Example.com/oauth2/token", "https://accounts.example.com"))
	require.False(t, sameHTTPHost("https://hydra-internal:4444", "https://accounts.example.com/oauth2/token"))
	require.False(t, sameHTTPHost("", "https://accounts.example.com"))
	require.False(t, sameHTTPHost("https://a.example.com", "::::not-a-url"))
}

func TestHydraUpstreamBaseRejectsSelfReference(t *testing.T) {
	h := &AuthServer{config: &authconfig.AuthenticationConfig{
		FedCMPublicOrigin:            "https://accounts.example.com",
		Oauth2HydraPublicInternalURL: "https://accounts.example.com",
	}}
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	_, err := h.hydraUpstreamBase(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "points back")
}

func TestHydraUpstreamBaseRejectsUnset(t *testing.T) {
	h := &AuthServer{config: &authconfig.AuthenticationConfig{}}
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	_, err := h.hydraUpstreamBase(r)
	require.Error(t, err)
}

func TestHydraUpstreamBaseAllowsDistinctHost(t *testing.T) {
	h := &AuthServer{config: &authconfig.AuthenticationConfig{
		FedCMPublicOrigin:            "https://accounts.example.com",
		Oauth2HydraPublicInternalURL: "https://hydra-internal:4444",
	}}
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	base, err := h.hydraUpstreamBase(r)
	require.NoError(t, err)
	require.Equal(t, "https://hydra-internal:4444", base)
}

func TestOpenIDConfigurationFacadeRewritesTokenEndpoint(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/.well-known/openid-configuration", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://hydra.internal",
			"token_endpoint":         "https://hydra.internal/oauth2/token",
			"authorization_endpoint": "https://hydra.internal/oauth2/auth",
		})
	}))
	defer upstream.Close()

	h := &AuthServer{
		config: &authconfig.AuthenticationConfig{
			FedCMPublicOrigin:            "https://accounts.example.com",
			Oauth2HydraPublicInternalURL: upstream.URL,
		},
		tokenFacadeClient: upstream.Client(),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	require.NoError(t, h.OpenIDConfigurationFacadeEndpoint(rec, req))

	require.Equal(t, http.StatusOK, rec.Code)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	require.Equal(t, "https://accounts.example.com/oauth2/token", doc["token_endpoint"])
	// Unrelated fields are passed through untouched.
	require.Equal(t, "https://hydra.internal/oauth2/auth", doc["authorization_endpoint"])
}

func TestOpenIDConfigurationFacadeFailsOnSelfReference(t *testing.T) {
	h := &AuthServer{config: &authconfig.AuthenticationConfig{
		FedCMPublicOrigin:            "https://accounts.example.com",
		Oauth2HydraPublicInternalURL: "https://accounts.example.com",
	}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	require.NoError(t, h.OpenIDConfigurationFacadeEndpoint(rec, req))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestOAuthTokenFacadeProxiesOrdinaryGrants(t *testing.T) {
	var gotBody string
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/oauth2/token", r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer"}`))
	}))
	defer upstream.Close()

	h := &AuthServer{
		config: &authconfig.AuthenticationConfig{
			FedCMPublicOrigin:            "https://accounts.example.com",
			Oauth2HydraPublicInternalURL: upstream.URL,
		},
		tokenFacadeClient: upstream.Client(),
	}

	form := "grant_type=client_credentials&client_id=svc&client_secret=shh"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic abc")
	rec := httptest.NewRecorder()

	require.NoError(t, h.OAuthTokenFacadeEndpoint(rec, req))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, form, gotBody)
	require.Equal(t, "Basic abc", gotAuth)
	require.Contains(t, rec.Body.String(), "access_token")
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestOAuthTokenFacadeNativeGrantRespectsKillSwitch(t *testing.T) {
	h := &AuthServer{config: &authconfig.AuthenticationConfig{}}
	form := "grant_type=" + nativeTokenExchangeGrant
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	require.NoError(t, h.OAuthTokenFacadeEndpoint(rec, req))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "invalid_grant", body["error"])
}

func TestOAuthTokenFacadeNativeGrantEnabledRequiresLocalClientID(t *testing.T) {
	h := &AuthServer{config: &authconfig.AuthenticationConfig{NativeCredentialExchangeEnabled: true}}
	form := "grant_type=" + nativeTokenExchangeGrant + "&subject_token_type=" + idTokenSubjectTokenType
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	require.NoError(t, h.OAuthTokenFacadeEndpoint(rec, req))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "invalid_request", body["error"])
	require.Equal(t, "client_id is required", body["error_description"])
}

func TestOAuthTokenFacadeRejectsNonPost(t *testing.T) {
	h := &AuthServer{config: &authconfig.AuthenticationConfig{}}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/token", nil)
	rec := httptest.NewRecorder()
	require.NoError(t, h.OAuthTokenFacadeEndpoint(rec, req))
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}
