package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/tests"
	handlers2 "github.com/gorilla/handlers"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// Test timeout constants
const (
	HandlerTestTimeout      = 60 * time.Second // Overall test timeout
	HandlerOperationTimeout = 15 * time.Second // Individual operation timeout
)

type HandlersTestSuite struct {
	tests.BaseTestSuite
}

func (suite *HandlersTestSuite) TestErrorEndpoint() {
	testCases := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedType   string
	}{
		{
			name:           "ShowErrorPage",
			endpoint:       "/error",
			expectedStatus: http.StatusInternalServerError,
			expectedType:   "text/html",
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
				defer opCancel()

				client := &http.Client{Timeout: HandlerOperationTimeout}

				req, err := http.NewRequestWithContext(opCtx, "GET", server.URL+tc.endpoint, nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				assert.Equal(t, tc.expectedStatus, resp.StatusCode)
				assert.Contains(t, resp.Header.Get("Content-Type"), tc.expectedType)

				body := make([]byte, 1024)
				n, _ := resp.Body.Read(body)
				bodyStr := string(body[:n])
				assert.Contains(t, bodyStr, "<title>Error | Authentication</title>")
			})
		}
	})
}

func (suite *HandlersTestSuite) TestTokenEnrichmentEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
		defer opCancel()

		client := &http.Client{Timeout: HandlerOperationTimeout}

		webhookReq := map[string]any{
			"token": "test-token",
		}
		jsonData, err := json.Marshal(webhookReq)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(opCtx, "POST", server.URL+"/webhook/token", bytes.NewBuffer(jsonData))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500, "Should return valid HTTP status")
	})
}

func (suite *HandlersTestSuite) TestTokenEnrichmentWithSystemInternal() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
		defer opCancel()

		client := &http.Client{Timeout: HandlerOperationTimeout}

		webhookReq := map[string]any{
			"granted_scopes": []string{"openid", "offline", "system_int"},
			"client_id":      "test-system-client",
			"grant_type":     "client_credentials",
			"session": map[string]any{
				"access_token": map[string]any{
					"tenant_id":    "tenant-sa-1",
					"partition_id": "part-sa-1",
					"roles":        []string{"system_internal"},
					"profile_id":   "service-bot-profile-1",
				},
			},
		}
		jsonData, err := json.Marshal(webhookReq)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(opCtx, "POST", server.URL+"/webhook/enrich/access-token", bytes.NewBuffer(jsonData))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		assert.Equal(t, http.StatusOK, resp.StatusCode, "system_internal token enrichment should succeed")

		var response map[string]any
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		session, ok := response["session"].(map[string]any)
		require.True(t, ok, "response should have session key")

		accessToken, ok := session["access_token"].(map[string]any)
		require.True(t, ok, "session should have access_token")

		roles, ok := accessToken["roles"].([]any)
		require.True(t, ok, "access_token should have roles")
		assert.Contains(t, roles, "system_internal")

		assert.Equal(t, "service-bot-profile-1", accessToken["profile_id"])
		assert.Equal(t, "tenant-sa-1", accessToken["tenant_id"])
		assert.Equal(t, "part-sa-1", accessToken["partition_id"])
	})
}

func (suite *HandlersTestSuite) TestTokenEnrichmentClientCredentialsNoScopes() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
		defer opCancel()

		client := &http.Client{Timeout: HandlerOperationTimeout}

		webhookReq := map[string]any{
			"client_id":  "test-system-client",
			"grant_type": "client_credentials",
			"session": map[string]any{
				"access_token": map[string]any{
					"tenant_id":    "tenant-1",
					"partition_id": "part-1",
					"roles":        []string{"system_internal"},
				},
			},
		}
		jsonData, err := json.Marshal(webhookReq)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(opCtx, "POST", server.URL+"/webhook/enrich/access-token", bytes.NewBuffer(jsonData))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		assert.Equal(t, http.StatusOK, resp.StatusCode, "client_credentials with session claims should succeed")

		var response map[string]any
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		session, ok := response["session"].(map[string]any)
		require.True(t, ok)

		accessToken, ok := session["access_token"].(map[string]any)
		require.True(t, ok)

		assert.Equal(t, "tenant-1", accessToken["tenant_id"])
		assert.Equal(t, "part-1", accessToken["partition_id"])
	})
}

func (suite *HandlersTestSuite) TestTokenEnrichmentMissingClaims() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
		defer opCancel()

		client := &http.Client{Timeout: HandlerOperationTimeout}

		webhookReq := map[string]any{
			"client_id":      "test-regular-client",
			"grant_type":     "authorization_code",
			"granted_scopes": []string{"openid"},
			"session":        map[string]any{},
		}
		jsonData, err := json.Marshal(webhookReq)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(opCtx, "POST", server.URL+"/webhook/enrich/access-token", bytes.NewBuffer(jsonData))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "missing claims should return 403")
	})
}

func (suite *HandlersTestSuite) TestTokenEnrichmentWithLoginEvent() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
		defer opCancel()

		client := &http.Client{Timeout: HandlerOperationTimeout}

		webhookReq := map[string]any{
			"client_id":      "test-api-client",
			"grant_type":     "refresh_token",
			"granted_scopes": []string{"openid", "offline"},
			"session": map[string]any{
				"access_token": map[string]any{
					"tenant_id":    "tenant-2",
					"partition_id": "part-2",
					"access_id":    "access-2",
					"roles":        []string{"system_external"},
					"session_id":   "evt-test-123",
				},
			},
		}
		jsonData, err := json.Marshal(webhookReq)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(opCtx, "POST", server.URL+"/webhook/enrich/refresh-token", bytes.NewBuffer(jsonData))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		assert.Equal(t, http.StatusOK, resp.StatusCode, "non-user role token refresh should succeed")

		var response map[string]any
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		session, ok := response["session"].(map[string]any)
		require.True(t, ok)

		accessToken, ok := session["access_token"].(map[string]any)
		require.True(t, ok)

		assert.Equal(t, "tenant-2", accessToken["tenant_id"])
		assert.Equal(t, "part-2", accessToken["partition_id"])
	})
}

func (suite *HandlersTestSuite) TestNotFoundEndpoint() {
	testCases := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedType   string
	}{
		{
			name:           "ShowNotFoundPage",
			endpoint:       "/not-found",
			expectedStatus: http.StatusNotFound,
			expectedType:   "text/html",
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
				defer opCancel()

				client := &http.Client{Timeout: HandlerOperationTimeout}

				req, err := http.NewRequestWithContext(opCtx, "GET", server.URL+tc.endpoint, nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				assert.Equal(t, tc.expectedStatus, resp.StatusCode)
				assert.Contains(t, resp.Header.Get("Content-Type"), tc.expectedType)

				body := make([]byte, 1024)
				n, _ := resp.Body.Read(body)
				bodyStr := string(body[:n])
				assert.Contains(t, bodyStr, "Page Not Found")
			})
		}
	})
}

func (suite *HandlersTestSuite) TestProviderEndpoints() {
	testCases := []struct {
		name           string
		endpoint       string
		method         string
		expectedStatus int
	}{
		{
			name:           "ProviderLoginGoogle",
			endpoint:       "/s/social/login/test-login-event-id?provider=google",
			method:         "POST",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "ProviderCallbackGoogle",
			endpoint:       "/s/social/callback",
			method:         "POST",
			expectedStatus: http.StatusInternalServerError,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
				defer opCancel()

				client := &http.Client{Timeout: HandlerOperationTimeout}

				req, err := http.NewRequestWithContext(opCtx, tc.method, server.URL+tc.endpoint, nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				assert.Equal(t, tc.expectedStatus, resp.StatusCode)
			})
		}
	})
}

func TestHandlers(t *testing.T) {
	suite.Run(t, new(HandlersTestSuite))
}
