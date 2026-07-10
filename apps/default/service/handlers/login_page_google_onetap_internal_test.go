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
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/stretchr/testify/require"
)

// renderLoginPage executes the real login template (loaded from tmpl/ at init)
// with the given payload and returns the produced HTML.
func renderLoginPage(t *testing.T, payload map[string]any) string {
	t.Helper()
	require.NotNil(t, loginTmpl, "login template must be loaded")
	var buf bytes.Buffer
	require.NoError(t, loginTmpl.Execute(&buf, payload))
	return buf.String()
}

func baseLoginPayload() map[string]any {
	return map[string]any{
		"t":                  map[string]string{},
		"lang":               "en",
		"error":              "",
		"loginEventId":       "le-123",
		"ClientID":           "antinvestor-client",
		"GoogleClientID":     "web-client.apps.googleusercontent.com",
		"FedCMNonce":         "nonce-xyz",
		"PostHogAPIKey":      "",
		"PostHogHost":        "",
		"enableContactLogin": true,
	}
}

func TestLoginPageWiresGoogleOAuthWhenEnabled(t *testing.T) {
	payload := baseLoginPayload()
	payload["enableGoogleLogin"] = true

	html := renderLoginPage(t, payload)

	// Google OAuth script is loaded; install() binds the button with the
	// Google web client ID (kept for config parity) and login event id.
	require.Contains(t, html, "/static/js/fedcm_google.js?v=2.0.5")
	require.Contains(t, html, "stawiGoogleFedCM.install")
	require.Contains(t, html, "web-client.apps.googleusercontent.com")
	require.Contains(t, html, "loginEventId: \"le-123\"")

	// Form posts to classic OAuth start (JSON redirect handled by JS).
	require.Contains(t, html, "data-fedcm-google")
	require.Contains(t, html, "/s/social/login/le-123?provider=google")

	// First-party FedCM probe still runs first (our IdP, not Google).
	require.Contains(t, html, "stawiFedCM.probeAndComplete")
}

func TestLoginPageOmitsGoogleOAuthWhenDisabled(t *testing.T) {
	payload := baseLoginPayload()
	payload["enableGoogleLogin"] = false

	html := renderLoginPage(t, payload)

	// No Google script, install call, or Google sign-in form when disabled.
	// (Note: the literal "data-fedcm-google" still appears in the tracking-loop
	// JS, so assert on the Google-gated markers instead of that attribute name.)
	require.NotContains(t, html, "fedcm_google.js")
	require.NotContains(t, html, "stawiGoogleFedCM")
	require.NotContains(t, html, "provider=google")
	// First-party FedCM probe is independent of Google and remains.
	require.Contains(t, html, "stawiFedCM.probeAndComplete")
}

func TestLoginPageGoogleInstallClientIDIsGoogleNotHydra(t *testing.T) {
	// Regression guard: install() clientId must be the Google web client ID,
	// never the Hydra ClientID (used only for first-party /fedcm/config.json).
	payload := baseLoginPayload()
	payload["enableGoogleLogin"] = true
	payload["GoogleClientID"] = "GOOGLE-AUD"
	payload["ClientID"] = "HYDRA-CLIENT"

	html := renderLoginPage(t, payload)

	idx := strings.Index(html, "stawiGoogleFedCM.install")
	require.GreaterOrEqual(t, idx, 0, "google install call must be present")
	installBlock := html[idx:]
	require.Contains(t, installBlock, "clientId: \"GOOGLE-AUD\"")
	require.NotContains(t, installBlock, "clientId: \"HYDRA-CLIENT\"")

	// Sanity: the Hydra client id is still used by the first-party probe.
	require.Contains(t, html, "clientId: \"HYDRA-CLIENT\"")
}

func TestSetupLoginOptionsRequiresCompleteGoogleConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.AuthenticationConfig
		enabled bool
	}{
		{
			name: "missing all google settings",
			cfg:  config.AuthenticationConfig{},
		},
		{
			name: "client id only is not enough",
			cfg: config.AuthenticationConfig{
				AuthProviderGoogleClientID: "web-client.apps.googleusercontent.com",
			},
		},
		{
			name: "missing callback url",
			cfg: config.AuthenticationConfig{
				AuthProviderGoogleClientID: "web-client.apps.googleusercontent.com",
				AuthProviderGoogleSecret:   "secret",
			},
		},
		{
			name: "complete google web login config",
			cfg: config.AuthenticationConfig{
				AuthProviderGoogleClientID:    "web-client.apps.googleusercontent.com",
				AuthProviderGoogleSecret:      "secret",
				AuthProviderGoogleCallbackURL: "https://accounts.stawi.org/s/social/callback",
			},
			enabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &AuthServer{}
			h.setupLoginOptions(&tt.cfg)

			require.Equal(t, tt.enabled, h.loginOptions["enableGoogleLogin"] == true)
		})
	}
}

func TestGoogleScriptIsOAuthOnlyNoFedCM(t *testing.T) {
	path := filepath.Join("..", "..", "static", "js", "fedcm_google.js")
	source, err := os.ReadFile(path)
	require.NoError(t, err)

	js := string(source)
	// Pure OAuth: no Google FedCM runtime (strip comments before negative asserts).
	codeOnly := stripJSComments(js)
	require.NotContains(t, codeOnly, "navigator.credentials.get")
	require.NotContains(t, codeOnly, "IdentityCredential")
	require.NotContains(t, codeOnly, "auto_prompt")
	require.NotContains(t, codeOnly, "gsi/fedcm.json")
	require.NotContains(t, codeOnly, "fedcm-complete")
	// Click path: JSON OAuth start with complete authorize URL validation.
	require.Contains(t, js, "startGoogleOAuth")
	require.Contains(t, js, `path: "oauth_only"`)
	require.Contains(t, js, `Accept: "application/json"`)
	require.Contains(t, js, "isCompleteGoogleAuthorizeURL")
	require.Contains(t, codeOnly, "response_type")
	require.NotContains(t, codeOnly, "btn.click()")
	require.NotContains(t, codeOnly, "fedcm_google_auto_escalate")
}

// stripJSComments removes // line comments so negative assertions do not
// match explanatory prose in the file header.
func stripJSComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
