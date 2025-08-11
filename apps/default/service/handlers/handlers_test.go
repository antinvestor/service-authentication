package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/tests"
	handlers2 "github.com/gorilla/handlers"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// Define the apiKey struct locally for testing since it's not exported
type apiKey struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	ClientID string            `json:"clientId"`
	Scope    string            `json:"scope"`
	Audience []string          `json:"audience"`
	Metadata map[string]string `json:"metadata"`

	Key       string `json:"apiKey"`
	KeySecret string `json:"apiKeySecret"`
}

type HandlersTestSuite struct {
	tests.BaseTestSuite
}

func (suite *HandlersTestSuite) TestIndexEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Test GET request to index endpoint
		resp, err := http.Get(server.URL + "/")
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// Verify response
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")

		// Verify template rendering
		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])
		assert.Contains(t, bodyStr, "<html>")
		assert.Contains(t, bodyStr, "Index")

		// Verify service is working
		assert.NotNil(t, authServer.Service())
	})
}

func (suite *HandlersTestSuite) TestErrorEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Test GET request to error endpoint
		resp, err := http.Get(server.URL + "/s/error")
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// Verify response
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")

		// Verify error template rendering
		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])
		assert.Contains(t, bodyStr, "<html>")
		assert.Contains(t, bodyStr, "Error")

		// Verify service is working
		assert.NotNil(t, authServer.Service())
	})
}

func (suite *HandlersTestSuite) TestCreateAPIKeyEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Create test API key request
		apiKeyReq := apiKey{
			Name:     "Test API Key",
			Scope:    "test_scope",
			Audience: []string{"test_audience"},
			Metadata: map[string]string{"env": "test"},
		}

		reqBody, err := json.Marshal(apiKeyReq)
		require.NoError(t, err)

		// Create authenticated request (this would need proper JWT token in real scenario)
		req, err := http.NewRequest("PUT", server.URL+"/api/key", bytes.NewBuffer(reqBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// We expect authentication failure since we don't have proper JWT setup
		// In full integration test, this would verify successful creation
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Verify service and context are working
		assert.NotNil(t, authServer.Service())
		assert.NotNil(t, ctx)
	})
}

func (suite *HandlersTestSuite) TestListAPIKeyEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create test API key in database first using repository
		profileID := "test-profile-list"
		apiKey := &models.APIKey{
			BaseModel: frame.BaseModel{ID: util.IDString()},
			ProfileID: profileID,
			Name:      "Test List Key",
			Key:       "test-key-123",
			Scope:     `["read", "write"]`,
		}

		// Use API key repository instead of direct DB access
		apiKeyRepo := repository.NewAPIKeyRepository(authServer.Service())
		err := apiKeyRepo.Save(ctx, apiKey)
		require.NoError(t, err)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Create request
		req, err := http.NewRequest("GET", server.URL+"/api/key", nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// Verify response structure (should be unauthorised without proper JWT)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Verify database operation worked using repository
		retrievedKey, err := apiKeyRepo.GetByID(ctx, apiKey.ID)
		require.NoError(t, err)
		require.NotNil(t, retrievedKey, "Should find the API key in database")
		assert.Equal(t, "Test List Key", retrievedKey.Name)
	})
}

func (suite *HandlersTestSuite) TestGetAPIKeyEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create test API key in database first using repository
		profileID := "test-profile-get"
		apiKey := &models.APIKey{
			BaseModel: frame.BaseModel{ID: util.IDString()},
			ProfileID: profileID,
			Name:      "Test Get Key",
			Key:       "test-key-456",
			Scope:     `["read"]`,
		}

		// Use API key repository instead of direct DB access
		apiKeyRepo := repository.NewAPIKeyRepository(authServer.Service())
		err := apiKeyRepo.Save(ctx, apiKey)
		require.NoError(t, err)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Create request
		req, err := http.NewRequest("GET", server.URL+"/api/key/"+apiKey.ID, nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// Verify response (should be unauthorised without proper JWT)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Verify database operation worked using repository
		retrievedKey, err := apiKeyRepo.GetByID(ctx, apiKey.ID)
		require.NoError(t, err)
		require.NotNil(t, retrievedKey, "Should find the API key in database")
	})
}

func (suite *HandlersTestSuite) TestDeleteAPIKeyEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create test API key in database first using repository
		profileID := "test-profile-delete"
		apiKey := &models.APIKey{
			BaseModel: frame.BaseModel{ID: util.IDString()},
			ProfileID: profileID,
			Name:      "Test Delete Key",
			Key:       "test-key-789",
			Scope:     `["delete"]`,
		}

		// Use API key repository instead of direct DB access
		apiKeyRepo := repository.NewAPIKeyRepository(authServer.Service())
		err := apiKeyRepo.Save(ctx, apiKey)
		require.NoError(t, err)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Create request
		req, err := http.NewRequest("DELETE", server.URL+"/api/key/"+apiKey.ID, nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// Verify response (should be unauthorised without proper JWT)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Verify the key still exists in database (since delete was unauthorised) using repository
		existingKey, err := apiKeyRepo.GetByID(ctx, apiKey.ID)
		require.NoError(t, err)
		assert.NotNil(t, existingKey, "API key should still exist since delete was unauthorised")
	})
}

func (suite *HandlersTestSuite) TestTokenEnrichmentEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create test API key for token enrichment using repository
		apiKey := &models.APIKey{
			BaseModel: frame.BaseModel{ID: util.IDString()},
			ProfileID: "test-profile-token",
			Name:      "Test Token Key",
			Key:       "test-token-key",
			Scope:     `["system_external"]`,
		}

		// Use API key repository instead of direct DB access
		apiKeyRepo := repository.NewAPIKeyRepository(authServer.Service())
		err := apiKeyRepo.Save(ctx, apiKey)
		require.NoError(t, err)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Create token enrichment request payload
		tokenPayload := map[string]interface{}{
			"session": map[string]interface{}{
				"access_token": map[string]interface{}{},
				"id_token":     map[string]interface{}{},
			},
			"request": map[string]interface{}{
				"client": map[string]interface{}{
					"client_id": apiKey.Key,
				},
			},
		}

		reqBody, err := json.Marshal(tokenPayload)
		require.NoError(t, err)

		// Test token enrichment endpoint
		req, err := http.NewRequest("POST", server.URL+"/hooks/token/access_token", bytes.NewBuffer(reqBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		// Verify response
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		// Verify token enrichment worked (basic structure check)
		session, ok := response["session"].(map[string]interface{})
		assert.True(t, ok, "Response should contain session")

		accessToken, ok := session["access_token"].(map[string]interface{})
		assert.True(t, ok, "Session should contain access_token")

		// The token enrichment may not work fully without proper API key setup
		// but we verify the endpoint processes the request
		assert.NotNil(t, accessToken, "Access token should be present")
	})
}

func (suite *HandlersTestSuite) TestAPIKeyEndpointErrors() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authServer, ctx := suite.CreateService(t, dep)

		// Create HTTP test server using AuthServer's SetupRouterV1
		handler := handlers2.RecoveryHandler(
			handlers2.PrintRecoveryStack(true))(
			authServer.SetupRouterV1(ctx))
		server := httptest.NewServer(handler)
		defer server.Close()

		// Test unauthorised access
		resp, err := http.Get(server.URL + "/api/key")
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Test invalid API key ID
		req, err := http.NewRequest("GET", server.URL+"/api/key/invalid-id", nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err = client.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(ctx, resp.Body)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Verify service is working
		assert.NotNil(t, authServer.Service())
	})
}

func TestHandlers(t *testing.T) {
	suite.Run(t, new(HandlersTestSuite))
}
