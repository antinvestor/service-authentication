package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/stretchr/testify/require"
)

func TestWellKnownWebIdentity_ReturnsProviderURL(t *testing.T) {
	h := handlers.NewFedCMWellKnownHandler("https://auth.example.com", "", "")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/web-identity", nil)
	require.NoError(t, h.WellKnownWebIdentity(rec, req))

	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var out struct {
		ProviderURLs []string `json:"provider_urls"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, []string{"https://auth.example.com/fedcm/config.json"}, out.ProviderURLs)
}

func TestFedCMConfig_ReturnsAllRequiredEndpoints(t *testing.T) {
	h := handlers.NewFedCMWellKnownHandler("https://auth.example.com", "#ffffff", "https://auth.example.com/icon.png")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/fedcm/config.json", nil)
	require.NoError(t, h.FedCMConfig(rec, req))

	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &cfg))
	require.Equal(t, "https://auth.example.com/fedcm/accounts", cfg["accounts_endpoint"])
	require.Equal(t, "https://auth.example.com/fedcm/client_metadata", cfg["client_metadata_endpoint"])
	require.Equal(t, "https://auth.example.com/fedcm/id-assertion", cfg["id_assertion_endpoint"])
	require.Equal(t, "https://auth.example.com/fedcm/disconnect", cfg["disconnect_endpoint"])
	require.Equal(t, "https://auth.example.com/s/fedcm/login", cfg["login_url"])

	branding, ok := cfg["branding"].(map[string]any)
	require.True(t, ok, "branding object must be present")
	require.Equal(t, "#ffffff", branding["background_colour"], "FedCM spec uses US spelling")
	icons, ok := branding["icons"].([]any)
	require.True(t, ok, "branding.icons must be an array")
	require.Len(t, icons, 1)
}

// Relying parties on other origins (e.g. stawi.trade) probe the discovery
// documents with a plain cross-origin fetch, so they must carry permissive
// CORS headers; the credentialed FedCM endpoints are covered elsewhere.
func TestFedCMDiscovery_AllowsCrossOriginReads(t *testing.T) {
	h := handlers.NewFedCMWellKnownHandler("https://auth.example.com", "", "")

	for name, call := range map[string]func(http.ResponseWriter, *http.Request) error{
		"web-identity": h.WellKnownWebIdentity,
		"config.json":  h.FedCMConfig,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Origin", "https://stawi.trade")
			require.NoError(t, call(rec, req))
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
			require.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"), "public documents must not be credentialed")
		})
	}
}

func TestFedCMDiscovery_Preflight(t *testing.T) {
	h := handlers.NewFedCMWellKnownHandler("https://auth.example.com", "", "")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/fedcm/config.json", nil)
	req.Header.Set("Origin", "https://stawi.trade")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	require.NoError(t, h.DiscoveryPreflight(rec, req))

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	require.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), http.MethodGet)
	require.NotEmpty(t, rec.Header().Get("Access-Control-Max-Age"))
}
