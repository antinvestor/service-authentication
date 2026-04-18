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
	h := handlers.NewFedCMWellKnownHandler("https://auth.example.com")

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
	h := handlers.NewFedCMWellKnownHandler("https://auth.example.com")

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
}
