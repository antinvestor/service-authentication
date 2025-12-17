package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
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

// Global mutex to ensure sequential execution of integration tests
var handlerTestMutex sync.Mutex

// Test timeout constants
const (
	HandlerTestTimeout      = 60 * time.Second // Overall test timeout
	HandlerOperationTimeout = 15 * time.Second // Individual operation timeout
	HandlerCleanupTimeout   = 5 * time.Second  // Cleanup operation timeout
)

type HandlersTestSuite struct {
	tests.BaseTestSuite
}

func (suite *HandlersTestSuite) TestErrorEndpoint() {
	// Test cases
	testCases := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedType   string
		shouldError    bool
	}{
		{
			name:           "ShowErrorPage",
			endpoint:       "/error",
			expectedStatus: http.StatusInternalServerError,
			expectedType:   "text/html",
			shouldError:    false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		handlerTestMutex.Lock()
		defer func() {
			handlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
				defer opCancel()

				// Create HTTP client with timeout
				client := &http.Client{
					Timeout: HandlerOperationTimeout,
				}

				// Test GET request to error endpoint
				req, err := http.NewRequestWithContext(opCtx, "GET", server.URL+tc.endpoint, nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				// Verify response
				assert.Equal(t, tc.expectedStatus, resp.StatusCode)
				assert.Contains(t, resp.Header.Get("Content-Type"), tc.expectedType)

				// Verify error template rendering
				body := make([]byte, 1024)
				n, _ := resp.Body.Read(body)
				bodyStr := string(body[:n])
				assert.Contains(t, bodyStr, "<title>Error</title>")

			})
		}
	})
}

func (suite *HandlersTestSuite) TestCreateAPIKeyEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		handlerTestMutex.Lock()
		defer func() {
			handlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Create operation context with timeout
		opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
		defer opCancel()

		// Create HTTP client with timeout
		client := &http.Client{
			Timeout: HandlerOperationTimeout,
		}

		// Create test API key request
		apiKeyReq := map[string]any{
			"name":     "test-api-key",
			"scope":    "read",
			"audience": []string{"test"},
		}
		jsonData, err := json.Marshal(apiKeyReq)
		require.NoError(t, err)

		// Test PUT request to create API key endpoint (should return 401 without JWT)
		req, err := http.NewRequestWithContext(opCtx, "PUT", server.URL+"/api/key", bytes.NewBuffer(jsonData))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// Verify response (should be 401 Unauthorised when no JWT token is provided)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	})
}

func (suite *HandlersTestSuite) TestListAPIKeyEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		handlerTestMutex.Lock()
		defer func() {
			handlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Create operation context with timeout
		opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
		defer opCancel()

		// Create HTTP client with timeout
		client := &http.Client{
			Timeout: HandlerOperationTimeout,
		}

		// Test GET request to list API keys endpoint (should return 401 without JWT)
		req, err := http.NewRequestWithContext(opCtx, "GET", server.URL+"/api/key", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// Verify response (should be 401 Unauthorised when no JWT token is provided)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	})
}

func (suite *HandlersTestSuite) TestGetAPIKeyEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		handlerTestMutex.Lock()
		defer func() {
			handlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Create operation context with timeout
		opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
		defer opCancel()

		// Create HTTP client with timeout
		client := &http.Client{
			Timeout: HandlerOperationTimeout,
		}

		// Test GET request to get specific API key endpoint (should return 401 without JWT)
		req, err := http.NewRequestWithContext(opCtx, "GET", server.URL+"/api/key/test-key-id", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// Verify response (should be 401 Unauthorised when no JWT token is provided)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	})
}

func (suite *HandlersTestSuite) TestDeleteAPIKeyEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		handlerTestMutex.Lock()
		defer func() {
			handlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Create operation context with timeout
		opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
		defer opCancel()

		// Create HTTP client with timeout
		client := &http.Client{
			Timeout: HandlerOperationTimeout,
		}

		// Test DELETE request to delete API key endpoint (should return 401 without JWT)
		req, err := http.NewRequestWithContext(opCtx, "DELETE", server.URL+"/api/key/test-key-id", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// Verify response (should be 401 Unauthorised when no JWT token is provided)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	})
}

func (suite *HandlersTestSuite) TestTokenEnrichmentEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		handlerTestMutex.Lock()
		defer func() {
			handlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Create operation context with timeout
		opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
		defer opCancel()

		// Create HTTP client with timeout
		client := &http.Client{
			Timeout: HandlerOperationTimeout,
		}

		// Create test webhook request
		webhookReq := map[string]any{
			"token": "test-token",
		}
		jsonData, err := json.Marshal(webhookReq)
		require.NoError(t, err)

		// Test POST request to token enrichment webhook endpoint
		req, err := http.NewRequestWithContext(opCtx, "POST", server.URL+"/webhook/token", bytes.NewBuffer(jsonData))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// Verify response (webhook should process but may return error for invalid token)
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500, "Should return valid HTTP status")

	})
}

func (suite *HandlersTestSuite) TestAPIKeyEndpointErrors() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		handlerTestMutex.Lock()
		defer func() {
			handlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Create operation context with timeout
		opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
		defer opCancel()

		// Create HTTP client with timeout
		client := &http.Client{
			Timeout: HandlerOperationTimeout,
		}

		// Test unauthorised access to API key endpoint (no JWT token)
		// This should return 401 Unauthorised as authentication middleware is working correctly
		req, err := http.NewRequestWithContext(opCtx, "GET", server.URL+"/api/key", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// Verify response (should be 401 Unauthorised for unauthorised access)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	})
}

func (suite *HandlersTestSuite) TestNotFoundEndpoint() {
	// Test cases
	testCases := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedType   string
		shouldError    bool
	}{
		{
			name:           "ShowNotFoundPage",
			endpoint:       "/not-found",
			expectedStatus: http.StatusNotFound,
			expectedType:   "text/html",
			shouldError:    false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		handlerTestMutex.Lock()
		defer func() {
			handlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
				defer opCancel()

				// Create HTTP client with timeout
				client := &http.Client{
					Timeout: HandlerOperationTimeout,
				}

				// Test GET request to not found endpoint
				req, err := http.NewRequestWithContext(opCtx, "GET", server.URL+tc.endpoint, nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				// Verify response
				assert.Equal(t, tc.expectedStatus, resp.StatusCode)
				assert.Contains(t, resp.Header.Get("Content-Type"), tc.expectedType)

				// Verify not found template rendering
				body := make([]byte, 1024)
				n, _ := resp.Body.Read(body)
				bodyStr := string(body[:n])
				assert.Contains(t, bodyStr, "Page Not Found")

			})
		}
	})
}

func (suite *HandlersTestSuite) TestProviderEndpoints() {
	// Test cases for provider login endpoints
	testCases := []struct {
		name           string
		endpoint       string
		method         string
		expectedStatus int
		shouldError    bool
	}{
		{
			name:           "ProviderLoginGoogle",
			endpoint:       "/s/social/login/test-login-event-id/google",
			method:         "POST",
			expectedStatus: http.StatusBadRequest, // Expected when login event not found
			shouldError:    true,
		},
		{
			name:           "ProviderCallbackGoogle",
			endpoint:       "/social/callback/google",
			method:         "POST",
			expectedStatus: http.StatusInternalServerError, // Expected without proper OAuth setup
			shouldError:    true,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		handlerTestMutex.Lock()
		defer func() {
			handlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), HandlerTestTimeout)
		defer testCancel()

		ctx, authServer, _ := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx, HandlerOperationTimeout)
				defer opCancel()

				// Create HTTP client with timeout
				client := &http.Client{
					Timeout: HandlerOperationTimeout,
				}

				// Test request to provider endpoint
				req, err := http.NewRequestWithContext(opCtx, tc.method, server.URL+tc.endpoint, nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				// Verify response (should be error due to missing OAuth setup)
				assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			})
		}
	})
}

func TestHandlers(t *testing.T) {
	suite.Run(t, new(HandlersTestSuite))
}
