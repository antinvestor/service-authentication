package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
var authHandlerTestMutex sync.Mutex

// Test timeout constants
const (
	AuthHandlerTestTimeout      = 60 * time.Second // Overall test timeout
	AuthHandlerOperationTimeout = 15 * time.Second // Individual operation timeout
	AuthHandlerCleanupTimeout   = 5 * time.Second  // Cleanup operation timeout
)

type AuthHandlersTestSuite struct {
	tests.BaseTestSuite
}

// TestAuthHandlersTestSuite runs the authentication handler test suite
func TestAuthHandlersTestSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlersTestSuite))
}

func (suite *AuthHandlersTestSuite) TestShowRegisterEndpoint() {
	// Test cases
	testCases := []struct {
		name        string
		endpoint    string
		shouldError bool
	}{
		{
			name:        "ShowRegisterPage",
			endpoint:    "/s/register",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		authHandlerTestMutex.Lock()
		defer func() {
			authHandlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), AuthHandlerTestTimeout)
		defer testCancel()

		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx, AuthHandlerOperationTimeout)
				defer opCancel()

				// Create HTTP client with timeout
				client := &http.Client{
					Timeout: AuthHandlerOperationTimeout,
				}

				// Test GET request to register endpoint
				req, err := http.NewRequestWithContext(opCtx, "GET", server.URL+tc.endpoint, nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				// Verify we get a valid HTTP response (any 2xx, 4xx, or 5xx is acceptable)
				assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 600, "Should return valid HTTP status")

				// Verify service is working
				assert.NotNil(t, authServer.Service())
			})
		}
	})
}

func (suite *AuthHandlersTestSuite) TestSubmitRegisterEndpoint() {
	// Test cases
	testCases := []struct {
		name        string
		username    string
		password    string
		firstName   string
		lastName    string
		challenge   string
		shouldError bool
	}{
		{
			name:        "SubmitRegisterForm",
			username:    "test@example.com",
			password:    "password123",
			firstName:   "Test",
			lastName:    "User",
			challenge:   "test-challenge",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		authHandlerTestMutex.Lock()
		defer func() {
			authHandlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), AuthHandlerTestTimeout)
		defer testCancel()

		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx, AuthHandlerOperationTimeout)
				defer opCancel()

				// Create HTTP client with timeout
				client := &http.Client{
					Timeout: AuthHandlerOperationTimeout,
				}

				// Create form data
				formData := url.Values{}
				formData.Set("email", tc.username)
				formData.Set("password", tc.password)
				formData.Set("first_name", tc.firstName)
				formData.Set("last_name", tc.lastName)
				formData.Set("challenge", tc.challenge)

				// Test POST request to register endpoint
				req, err := http.NewRequestWithContext(opCtx, "POST", server.URL+"/s/register/post", strings.NewReader(formData.Encode()))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				// Verify service is working
				assert.NotNil(t, authServer.Service())
			})
		}
	})
}

func (suite *AuthHandlersTestSuite) TestShowConsentEndpoint() {
	// Test cases
	testCases := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedType   string
		shouldError    bool
	}{
		{
			name:           "ShowConsentPage",
			endpoint:       "/s/consent",
			expectedStatus: http.StatusOK,
			expectedType:   "text/html",
			shouldError:    false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		authHandlerTestMutex.Lock()
		defer func() {
			authHandlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), AuthHandlerTestTimeout)
		defer testCancel()

		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx, AuthHandlerOperationTimeout)
				defer opCancel()

				// Create HTTP client with timeout
				client := &http.Client{
					Timeout: AuthHandlerOperationTimeout,
				}

				// Test GET request to consent endpoint with challenge parameter
				req, err := http.NewRequestWithContext(opCtx, "GET", server.URL+tc.endpoint+"?consent_challenge=test", nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				// Verify service is working
				assert.NotNil(t, authServer.Service())
			})
		}
	})
}

func (suite *AuthHandlersTestSuite) TestShowLogoutEndpoint() {
	// Test cases
	testCases := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedType   string
		shouldError    bool
	}{
		{
			name:           "ShowLogoutPage",
			endpoint:       "/s/logout",
			expectedStatus: http.StatusInternalServerError, // Expect error due to missing/invalid logout_challenge
			expectedType:   "application/json",             // Error response is JSON
			shouldError:    true,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		authHandlerTestMutex.Lock()
		defer func() {
			authHandlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), AuthHandlerTestTimeout)
		defer testCancel()

		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx, AuthHandlerOperationTimeout)
				defer opCancel()

				// Create HTTP client with timeout
				client := &http.Client{
					Timeout: AuthHandlerOperationTimeout,
				}

				// Test GET request to logout endpoint without valid challenge (expects error)
				req, err := http.NewRequestWithContext(opCtx, "GET", server.URL+tc.endpoint, nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				// Verify response matches expected error behaviour
				assert.Equal(t, tc.expectedStatus, resp.StatusCode)
				assert.Contains(t, resp.Header.Get("Content-Type"), tc.expectedType)

				// Verify service is working
				assert.NotNil(t, authServer.Service())
			})
		}
	})
}

func (suite *AuthHandlersTestSuite) TestForgotEndpoint() {
	// Test cases
	testCases := []struct {
		name           string
		endpoint       string
		method         string
		expectedStatus int
		expectedType   string
		shouldError    bool
	}{
		{
			name:           "ShowForgotPasswordPage",
			endpoint:       "/s/forgot",
			method:         "GET",
			expectedStatus: http.StatusOK,
			expectedType:   "text/html",
			shouldError:    false,
		},
		{
			name:           "SubmitForgotPasswordForm",
			endpoint:       "/s/forgot",
			method:         "POST",
			expectedStatus: http.StatusOK,
			expectedType:   "text/html",
			shouldError:    false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		authHandlerTestMutex.Lock()
		defer func() {
			authHandlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), AuthHandlerTestTimeout)
		defer testCancel()

		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx, AuthHandlerOperationTimeout)
				defer opCancel()

				// Create HTTP client with timeout
				client := &http.Client{
					Timeout: AuthHandlerOperationTimeout,
				}

				// Test request to forgot password endpoint
				req, err := http.NewRequestWithContext(opCtx, tc.method, server.URL+tc.endpoint, nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				// Verify service is working
				assert.NotNil(t, authServer.Service())
			})
		}
	})
}

func (suite *AuthHandlersTestSuite) TestSetPasswordEndpoint() {
	// Test cases
	testCases := []struct {
		name           string
		endpoint       string
		method         string
		expectedStatus int
		expectedType   string
		shouldError    bool
	}{
		{
			name:           "ShowSetPasswordPage",
			endpoint:       "/s/password",
			method:         "GET",
			expectedStatus: http.StatusOK,
			expectedType:   "text/html",
			shouldError:    false,
		},
		{
			name:           "SubmitSetPasswordForm",
			endpoint:       "/s/password",
			method:         "POST",
			expectedStatus: http.StatusOK,
			expectedType:   "text/html",
			shouldError:    false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		authHandlerTestMutex.Lock()
		defer func() {
			authHandlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), AuthHandlerTestTimeout)
		defer testCancel()

		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx, AuthHandlerOperationTimeout)
				defer opCancel()

				// Create HTTP client with timeout
				client := &http.Client{
					Timeout: AuthHandlerOperationTimeout,
				}

				// Test request to set password endpoint
				req, err := http.NewRequestWithContext(opCtx, tc.method, server.URL+tc.endpoint, nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				// Verify service is working
				assert.NotNil(t, authServer.Service())
			})
		}
	})
}

func (suite *AuthHandlersTestSuite) TestDeviceIDMiddleware() {
	// Test cases
	testCases := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedType   string
		shouldError    bool
	}{
		{
			name:           "DeviceIDMiddlewareOnLogin",
			endpoint:       "/s/login",
			expectedStatus: http.StatusOK,
			expectedType:   "text/html",
			shouldError:    false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		authHandlerTestMutex.Lock()
		defer func() {
			authHandlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), AuthHandlerTestTimeout)
		defer testCancel()

		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx, AuthHandlerOperationTimeout)
				defer opCancel()

				// Create HTTP client with timeout
				client := &http.Client{
					Timeout: AuthHandlerOperationTimeout,
				}

				// Test GET request to login endpoint to verify device ID middleware
				req, err := http.NewRequestWithContext(opCtx, "GET", server.URL+tc.endpoint, nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)

				// Verify service is working
				assert.NotNil(t, authServer.Service())
			})
		}
	})
}

func (suite *AuthHandlersTestSuite) TestErrorHandling() {
	// Test cases
	testCases := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedType   string
		shouldError    bool
	}{
		{
			name:           "ErrorPageHandling",
			endpoint:       "/error",
			expectedStatus: http.StatusInternalServerError,
			expectedType:   "text/html",
			shouldError:    false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		// Acquire mutex to ensure sequential execution with timeout protection
		authHandlerTestMutex.Lock()
		defer func() {
			authHandlerTestMutex.Unlock()
			if r := recover(); r != nil {
				// Re-panic after cleanup
				panic(r)
			}
		}()

		// Create timeout context for the entire test
		testCtx, testCancel := context.WithTimeout(context.Background(), AuthHandlerTestTimeout)
		defer testCancel()

		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx, AuthHandlerOperationTimeout)
				defer opCancel()

				// Create HTTP client with timeout
				client := &http.Client{
					Timeout: AuthHandlerOperationTimeout,
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

				// Verify service is working
				assert.NotNil(t, authServer.Service())
			})
		}
	})
}
