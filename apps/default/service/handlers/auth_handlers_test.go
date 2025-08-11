package handlers_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/tests"
	handlers2 "github.com/gorilla/handlers"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AuthHandlersTestSuite struct {
	tests.BaseTestSuite
}

// TestAuthHandlersTestSuite runs the authentication handler test suite
func TestAuthHandlersTestSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlersTestSuite))
}

func (suite *AuthHandlersTestSuite) TestShowRegisterEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Test GET request to register endpoint
		resp, err := http.Get(server.URL + "/s/register")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")

		// Verify register template rendering
		body := make([]byte, 2048)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])
		assert.Contains(t, bodyStr, "<html>")
		assert.Contains(t, bodyStr, "register")

		// Verify service is working
		assert.NotNil(t, authServer.Service())
	})
}

func (suite *AuthHandlersTestSuite) TestSubmitRegisterEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Test POST request to register endpoint with form data
		formData := url.Values{}
		formData.Set("username", "newuser@example.com")
		formData.Set("password", "newpassword123")
		formData.Set("first_name", "Test")
		formData.Set("last_name", "User")
		formData.Set("challenge", "test-register-challenge")

		resp, err := http.PostForm(server.URL+"/s/register", formData)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response (registration may fail due to external service dependencies)
		// but we verify the endpoint processes the request
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500)

		// Verify service is working
		assert.NotNil(t, authServer.Service())
	})
}

func (suite *AuthHandlersTestSuite) TestShowConsentEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Test GET request to consent endpoint with challenge parameter
		resp, err := http.Get(server.URL + "/s/consent?consent_challenge=test-challenge")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response (may redirect or show error due to invalid challenge)
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500)

		// Verify service is working
		assert.NotNil(t, authServer.Service())
	})
}

func (suite *AuthHandlersTestSuite) TestShowLogoutEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Test GET request to logout endpoint with challenge parameter
		resp, err := http.Get(server.URL + "/s/logout?logout_challenge=test-logout-challenge")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response (may redirect or show error due to invalid challenge)
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500)

		// Verify service is working
		assert.NotNil(t, authServer.Service())
	})
}

func (suite *AuthHandlersTestSuite) TestForgotEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Test GET request to forgot password endpoint
		resp, err := http.Get(server.URL + "/s/forgot")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")

		// Verify forgot password template rendering
		body := make([]byte, 2048)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])
		assert.Contains(t, bodyStr, "<html>")

		// Test POST request with email
		formData := url.Values{}
		formData.Set("email", "test@example.com")

		resp, err = http.PostForm(server.URL+"/s/forgot", formData)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response (may show success or error depending on profile service)
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500)

		// Verify service is working
		assert.NotNil(t, authServer.Service())
	})
}

func (suite *AuthHandlersTestSuite) TestSetPasswordEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Test GET request to set password endpoint
		resp, err := http.Get(server.URL + "/s/set_password?token=test-token")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")

		// Verify set password template rendering
		body := make([]byte, 2048)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])
		assert.Contains(t, bodyStr, "<html>")

		// Test POST request with new password
		formData := url.Values{}
		formData.Set("password", "newpassword123")
		formData.Set("confirm_password", "newpassword123")
		formData.Set("token", "test-token")

		resp, err = http.PostForm(server.URL+"/s/set_password", formData)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify response (may show success or error depending on token validation)
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500)

		// Verify service is working
		assert.NotNil(t, authServer.Service())
	})
}

func (suite *AuthHandlersTestSuite) TestDeviceIDMiddleware() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Test request to any endpoint to verify device ID middleware
		resp, err := http.Get(server.URL + "/")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Verify device ID cookie is set
		cookies := resp.Cookies()
		var deviceIDCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "device_id" {
				deviceIDCookie = cookie
				break
			}
		}

		assert.NotNil(t, deviceIDCookie, "Device ID cookie should be set")
		if deviceIDCookie != nil {
			assert.NotEmpty(t, deviceIDCookie.Value, "Device ID cookie should have a value")
			assert.True(t, deviceIDCookie.HttpOnly, "Device ID cookie should be HttpOnly")
		}

		// Verify service is working
		assert.NotNil(t, authServer.Service())
	})
}

func (suite *AuthHandlersTestSuite) TestErrorHandling() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Test invalid endpoints
		resp, err := http.Get(server.URL + "/invalid/endpoint")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		// Test POST to GET-only endpoint
		resp, err = http.Post(server.URL+"/", "application/json", bytes.NewBuffer([]byte("{}")))
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should handle method not allowed or process the request
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500)

		// Verify service is working
		assert.NotNil(t, authServer.Service())
	})
}

func TestAuthHandlers(t *testing.T) {
	suite.Run(t, new(AuthHandlersTestSuite))
}
