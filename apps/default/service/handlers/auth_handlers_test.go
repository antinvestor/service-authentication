package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/tests"
	handlers2 "github.com/gorilla/handlers"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AuthHandlersTestSuite struct {
	tests.BaseTestSuite
}

func TestAuthHandlersTestSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlersTestSuite))
}

func (suite *AuthHandlersTestSuite) TestSubmitRegisterEndpoint() {
	testCases := []struct {
		name      string
		username  string
		password  string
		firstName string
		lastName  string
		challenge string
	}{
		{
			name:      "SubmitRegisterForm",
			username:  "test@example.com",
			password:  "password123",
			firstName: "Test",
			lastName:  "User",
			challenge: "test-challenge",
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

				formData := url.Values{}
				formData.Set("contact", tc.username)
				formData.Set("password", tc.password)
				formData.Set("first_name", tc.firstName)
				formData.Set("last_name", tc.lastName)
				formData.Set("challenge", tc.challenge)

				req, err := http.NewRequestWithContext(opCtx, "POST", server.URL+"/s/register/post", strings.NewReader(formData.Encode()))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)
			})
		}
	})
}

func (suite *AuthHandlersTestSuite) TestShowConsentEndpoint() {
	testCases := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedType   string
	}{
		{
			name:           "ShowConsentPage",
			endpoint:       "/s/consent",
			expectedStatus: http.StatusOK,
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

				req, err := http.NewRequestWithContext(opCtx, "GET", server.URL+tc.endpoint+"?consent_challenge=test", nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer util.CloseAndLogOnError(ctx, resp.Body)
			})
		}
	})
}

func (suite *AuthHandlersTestSuite) TestShowLogoutEndpoint() {
	testCases := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedType   string
	}{
		{
			name:           "ShowLogoutPage",
			endpoint:       "/s/logout",
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
			})
		}
	})
}

func (suite *AuthHandlersTestSuite) TestDeviceIDMiddleware() {
	testCases := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedType   string
	}{
		{
			name:           "DeviceIDMiddlewareOnLogin",
			endpoint:       "/s/login",
			expectedStatus: http.StatusOK,
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
			})
		}
	})
}

func (suite *AuthHandlersTestSuite) TestErrorHandling() {
	testCases := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedType   string
	}{
		{
			name:           "ErrorPageHandling",
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
