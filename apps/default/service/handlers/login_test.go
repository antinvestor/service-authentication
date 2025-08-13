package handlers_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/tests"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// Global mutex to ensure sequential execution of integration tests
var testMutex sync.Mutex

// Test timeout constants
const (
	TestTimeout          = 60 * time.Second  // Overall test timeout
	OperationTimeout     = 15 * time.Second  // Individual operation timeout
	CleanupTimeout       = 5 * time.Second   // Cleanup operation timeout
)

// LoginTestSuite provides a dedicated test suite for login functionality
type LoginTestSuite struct {
	tests.BaseTestSuite
}

// TestLoginTestSuite runs the login test suite
func TestLoginTestSuite(t *testing.T) {
	suite.Run(t, new(LoginTestSuite))
}

// LoginTestContext holds common test setup for login tests
type LoginTestContext struct {
	AuthServer   *handlers.AuthServer
	Context      context.Context
	Cancel       context.CancelFunc
	OAuth2Client *tests.OAuth2TestClient
	LoginRepo    repository.LoginRepository
}

// SetupLoginTest creates a common test setup for login tests with timeout handling
func (suite *LoginTestSuite) SetupLoginTest(t *testing.T, dep *definition.DependancyOption) *LoginTestContext {
	// Acquire mutex to ensure sequential execution with timeout protection
	testMutex.Lock()
	
	// Create timeout context for the entire test
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	
	authServer, baseCtx := suite.CreateService(t, dep)

	// Create OAuth2 test client with timeout context
	oauth2Client := tests.NewOAuth2TestClient(authServer)
	oauth2Client.SetTestingT(t) // Enable debug logging

	// Set the authentication service URL for OAuth2 client
	testServer := httptest.NewServer(authServer.SetupRouterV1(baseCtx))
	oauth2Client.SetAuthServiceURL(testServer.URL)

	loginRepo := repository.NewLoginRepository(authServer.Service())

	return &LoginTestContext{
		AuthServer:   authServer,
		Context:      ctx,
		Cancel:       cancel,
		OAuth2Client: oauth2Client,
		LoginRepo:    loginRepo,
	}
}

// TeardownLoginTest cleans up test resources with timeout protection
func (suite *LoginTestSuite) TeardownLoginTest(testCtx *LoginTestContext) {
	// Ensure mutex is always released, even on panic
	defer func() {
		testMutex.Unlock()
		if r := recover(); r != nil {
			// Re-panic after cleanup
			panic(r)
		}
	}()

	// Cancel the test context to stop any ongoing operations
	if testCtx.Cancel != nil {
		testCtx.Cancel()
	}

	// Create a separate context for cleanup operations
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), CleanupTimeout)
	defer cleanupCancel()

	if testCtx.OAuth2Client != nil {
		testCtx.OAuth2Client.Cleanup(cleanupCtx)
	}

	// Add a small delay to ensure proper cleanup
	time.Sleep(100 * time.Millisecond)
}

// CreateTestUser creates a test user with login credentials
func (suite *LoginTestSuite) CreateTestUser(ctx context.Context, authServer *handlers.AuthServer, loginRepo repository.LoginRepository, email, password string) error {
	// Use the AuthServer's profile client directly
	profileCli := authServer.ProfileCli()

	// Create the profile using the correct API method
	createdProfile, err := profileCli.CreateProfileByContactAndName(ctx, email, "Test User")
	if err != nil {
		return fmt.Errorf("failed to create test profile: %w", err)
	}

	// Use the actual profile ID from the profile service
	actualProfileID := createdProfile.GetId()
	correctProfileHash := utils.HashStringSecret(actualProfileID)

	// Hash the password properly
	crypt := utils.NewBCrypt()
	hashedPassword, err := crypt.Hash(ctx, []byte(password))
	if err != nil {
		return err
	}

	loginRecord := &models.Login{
		BaseModel:    frame.BaseModel{ID: util.IDString()},
		ProfileHash:  correctProfileHash,
		PasswordHash: hashedPassword,
	}

	return loginRepo.Save(ctx, loginRecord)
}

// TestLoginWithValidCredentials tests successful login with valid user credentials
func (suite *LoginTestSuite) TestLoginWithValidCredentials() {
	// Test cases
	testCases := []struct {
		name        string
		email       string
		password    string
		shouldError bool
	}{
		{
			name:        "ValidCredentialsLogin",
			email:       "valid@example.com",
			password:    "validpassword123",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		testCtx := suite.SetupLoginTest(t, dep)
		defer suite.TeardownLoginTest(testCtx)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
				defer opCancel()

				// Create test user
				err := suite.CreateTestUser(opCtx, testCtx.AuthServer, testCtx.LoginRepo, tc.email, tc.password)
				require.NoError(t, err)

				// Create OAuth2 client for this test using the test case name
				oauth2Client, err := testCtx.OAuth2Client.CreateOAuth2Client(opCtx, tc.name)
				require.NoError(t, err)

				// Initiate OAuth2 flow to get a valid login challenge
				loginChallenge, err := testCtx.OAuth2Client.InitiateLoginFlow(opCtx, oauth2Client)
				require.NoError(t, err)
				assert.NotEmpty(t, loginChallenge, "Should receive a valid login challenge")

				// Perform login with valid credentials
				loginResult, _, err := testCtx.OAuth2Client.PerformLoginWithErrorCapture(opCtx, loginChallenge, tc.email, tc.password)
				require.NoError(t, err)
				assert.True(t, loginResult.Success, "Login should succeed with valid credentials")
				assert.Equal(t, http.StatusSeeOther, loginResult.StatusCode, "Should redirect after successful login")
				assert.NotEmpty(t, loginResult.Location, "Should have redirect location")

				// Verify that we get a consent challenge or authorization code
				var authorizationCode string
				if loginResult.ConsentChallenge != "" {
					// Handle consent flow with timeout
					consentCtx, consentCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
					defer consentCancel()
					
					consentResult, err0 := testCtx.OAuth2Client.PerformConsent(consentCtx, loginResult.ConsentChallenge)
					require.NoError(t, err0)
					assert.True(t, consentResult.Success, "Consent should succeed")
					assert.NotEmpty(t, consentResult.AuthorizationCode, "Should receive authorization code")
					authorizationCode = consentResult.AuthorizationCode
				} else {
					assert.NotEmpty(t, loginResult.AuthorizationCode, "Should receive authorization code directly")
					authorizationCode = loginResult.AuthorizationCode
				}

				// Exchange authorization code for access token with timeout
				tokenCtx, tokenCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
				defer tokenCancel()
				
				tokenResult, err := testCtx.OAuth2Client.ExchangeCodeForToken(tokenCtx, oauth2Client, authorizationCode)
				require.NoError(t, err)
				assert.NotEmpty(t, tokenResult.AccessToken, "Should receive access token")
				assert.NotEmpty(t, tokenResult.TokenType, "Should receive token type")
				assert.Greater(t, tokenResult.ExpiresIn, 0, "Should have valid expiration time")

				// Verify access token can be used for API calls
				t.Logf("SUCCESS: Complete OAuth2 flow completed for test case: %s!", tc.name)
				t.Logf("Access Token: %s", tokenResult.AccessToken[:min(50, len(tokenResult.AccessToken))]+"...")
				t.Logf("Token Type: %s", tokenResult.TokenType)
				t.Logf("Expires In: %d seconds", tokenResult.ExpiresIn)

				// Note: Database verification would require getting the profile ID from the created profile
				// For now, we verify the login flow worked by checking the successful redirect
			})
		}
	})
}

// TestLoginWithInvalidCredentials tests login failure with wrong password for existing user
func (suite *LoginTestSuite) TestLoginWithInvalidCredentials() {
	testCases := []struct {
		name        string
		email       string
		password    string
		wrongPass   string
		shouldError bool
	}{
		{
			name:        "InvalidCredentialsLogin",
			email:       "invalid@example.com",
			password:    "correctpassword123",
			wrongPass:   "wrongpassword456",
			shouldError: true,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		testCtx := suite.SetupLoginTest(t, dep)
		defer suite.TeardownLoginTest(testCtx)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
				defer opCancel()

				// Create test user with correct password
				err := suite.CreateTestUser(opCtx, testCtx.AuthServer, testCtx.LoginRepo, tc.email, tc.password)
				require.NoError(t, err)

				// Create OAuth2 client for this test
				oauth2Client, err := testCtx.OAuth2Client.CreateOAuth2Client(opCtx, tc.name)
				require.NoError(t, err)

				// Initiate OAuth2 flow to get a valid login challenge
				loginChallenge, err := testCtx.OAuth2Client.InitiateLoginFlow(opCtx, oauth2Client)
				require.NoError(t, err)
				assert.NotEmpty(t, loginChallenge, "Should receive a valid login challenge")

				// Perform login with wrong password - should fail
				loginResult, errorMsg, err := testCtx.OAuth2Client.PerformLoginWithErrorCapture(opCtx, loginChallenge, tc.email, tc.wrongPass)
				require.NoError(t, err, "HTTP request should succeed even if login fails")
				assert.False(t, loginResult.Success, "Login should fail with invalid credentials")
				assert.NotEmpty(t, errorMsg, "Should receive error message for invalid credentials")
				t.Logf("Expected error message received: %s", errorMsg)

				// Verify we don't get authorization code on failed login
				assert.Empty(t, loginResult.AuthorizationCode, "Should not receive authorization code on failed login")
				assert.Empty(t, loginResult.ConsentChallenge, "Should not receive consent challenge on failed login")
			})
		}
	})
}

// TestLoginWithInvalidUser tests login failure with non-existent user
func (suite *LoginTestSuite) TestLoginWithInvalidUser() {
	// Test cases
	testCases := []struct {
		name     string
		email    string
		password string
		expected struct {
			success    bool
			statusCode int
			contains   string
		}
	}{
		{
			name:     "NonExistentUser",
			email:    "nonexistent@example.com",
			password: "anypassword",
			expected: struct {
				success    bool
				statusCode int
				contains   string
			}{
				success:    false,
				statusCode: http.StatusOK,
				contains:   "Invalid",
			},
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		testCtx := suite.SetupLoginTest(t, dep)
		defer suite.TeardownLoginTest(testCtx)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
				defer opCancel()

				// Initiate OAuth2 flow to get a valid login challenge
				oauth2Client, err := testCtx.OAuth2Client.CreateOAuth2Client(opCtx, tc.name)
				require.NoError(t, err)

				loginChallenge, err := testCtx.OAuth2Client.InitiateLoginFlow(opCtx, oauth2Client)
				require.NoError(t, err)
				assert.NotEmpty(t, loginChallenge, "Should receive a valid login challenge")

				// Test login with test case credentials
				loginResult, _, err := testCtx.OAuth2Client.PerformLoginWithErrorCapture(opCtx, loginChallenge, tc.email, tc.password)
				require.NoError(t, err)

				// Verify login failure
				assert.False(t, loginResult.Success, "Login should fail for non-existent user")
				assert.Equal(t, tc.expected.statusCode, loginResult.StatusCode, "Should return 200 OK with error form")

				// Verify service is working
				assert.NotNil(t, testCtx.AuthServer.Service())
			})
		}
	})
}

// TestLoginMultipleFailedAttempts tests multiple failed login attempts followed by successful login
func (suite *LoginTestSuite) TestLoginMultipleFailedAttempts() {
	// Test cases
	testCases := []struct {
		name            string
		email           string
		correctPassword string
		wrongPassword   string
		failedAttempts  int
		expected        struct {
			finalSuccess bool
			statusCode   int
		}
	}{
		{
			name:            "MultipleFailedThenSuccess",
			email:           "multitest@example.com",
			correctPassword: "correctpass123",
			wrongPassword:   "wrongpass",
			failedAttempts:  3,
			expected: struct {
				finalSuccess bool
				statusCode   int
			}{
				finalSuccess: true,
				statusCode:   http.StatusSeeOther,
			},
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		testCtx := suite.SetupLoginTest(t, dep)
		defer suite.TeardownLoginTest(testCtx)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
				defer opCancel()

				// Create test user
				err := suite.CreateTestUser(opCtx, testCtx.AuthServer, testCtx.LoginRepo, tc.email, tc.correctPassword)
				require.NoError(t, err)

				// Create OAuth2 client for this test case
				oauth2Client, err := testCtx.OAuth2Client.CreateOAuth2Client(opCtx, tc.name)
				require.NoError(t, err)

				// Perform multiple failed login attempts
				for i := 0; i < tc.failedAttempts; i++ {
					loginChallenge, err := testCtx.OAuth2Client.InitiateLoginFlow(opCtx, oauth2Client)
					require.NoError(t, err)

					loginResult, _, err := testCtx.OAuth2Client.PerformLoginWithErrorCapture(opCtx, loginChallenge, tc.email, tc.wrongPassword)
					require.NoError(t, err)
					assert.False(t, loginResult.Success, fmt.Sprintf("Attempt %d should fail with wrong password", i+1))
				}

				// Now perform successful login
				result, err := testCtx.OAuth2Client.CompleteOAuth2Flow(opCtx, oauth2Client, tc.email, tc.correctPassword)
				require.NoError(t, err)
				assert.NotNil(t, result.LoginResult, "Should have login result")
				assert.Equal(t, tc.expected.finalSuccess, result.LoginResult.Success, "Final login attempt should succeed")
				assert.NotEmpty(t, result.AuthorizationCode, "Should receive authorization code after successful login")

				t.Logf("SUCCESS: Multiple failed attempts followed by successful login for test case: %s", tc.name)

				// Verify service is working
				assert.NotNil(t, testCtx.AuthServer.Service())
			})
		}
	})
}

// TestLoginFormValidation tests form field validation
func (suite *LoginTestSuite) TestLoginFormValidation() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		testCtx := suite.SetupLoginTest(t, dep)
		defer suite.TeardownLoginTest(testCtx)

		// Create operation context with timeout
		opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
		defer opCancel()

		// Get a valid login challenge
		oauth2Client, err := testCtx.OAuth2Client.CreateOAuth2Client(opCtx, "TestLoginFormValidation")
		require.NoError(t, err)

		loginChallenge, err := testCtx.OAuth2Client.InitiateLoginFlow(opCtx, oauth2Client)
		require.NoError(t, err)
		assert.NotEmpty(t, loginChallenge, "Should receive a valid login challenge")

		// Test cases for form validation
		testCases := []struct {
			name     string
			email    string
			password string
			expected string
		}{
			{
				name:     "Empty email",
				email:    "",
				password: "somepassword",
				expected: "unable to log you in",
			},
			{
				name:     "Empty password",
				email:    "test@example.com",
				password: "",
				expected: "unable to log you in",
			},
			{
				name:     "Both empty",
				email:    "",
				password: "",
				expected: "unable to log you in",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				loginResult, _, err := testCtx.OAuth2Client.PerformLoginWithErrorCapture(opCtx, loginChallenge, tc.email, tc.password)
				require.NoError(t, err)

				// Verify validation failure
				assert.False(t, loginResult.Success, "Login should fail for %s", tc.name)
				assert.Equal(t, http.StatusOK, loginResult.StatusCode, "Should return 200 OK with error form for %s", tc.name)
			})
		}
	})
}

// TestCompleteOAuth2FlowWithAccessToken tests the complete OAuth2 flow and obtains an access token
func (suite *LoginTestSuite) TestCompleteOAuth2FlowWithAccessToken() {
	// Test cases
	testCases := []struct {
		name     string
		email    string
		password string
		expected struct {
			success      bool
			hasToken     bool
			hasTokenType bool
			validExpiry  bool
		}
	}{
		{
			name:     "CompleteFlowWithToken",
			email:    "tokentest@example.com",
			password: "tokenpassword123",
			expected: struct {
				success      bool
				hasToken     bool
				hasTokenType bool
				validExpiry  bool
			}{
				success:      true,
				hasToken:     true,
				hasTokenType: true,
				validExpiry:  true,
			},
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		testCtx := suite.SetupLoginTest(t, dep)
		defer suite.TeardownLoginTest(testCtx)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create operation context with timeout
				opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
				defer opCancel()

				// Create test user
				err := suite.CreateTestUser(opCtx, testCtx.AuthServer, testCtx.LoginRepo, tc.email, tc.password)
				require.NoError(t, err)

				// Create OAuth2 client for this test case
				oauth2Client, err := testCtx.OAuth2Client.CreateOAuth2Client(opCtx, tc.name)
				require.NoError(t, err)

				// Perform complete OAuth2 flow
				result, err := testCtx.OAuth2Client.CompleteOAuth2Flow(opCtx, oauth2Client, tc.email, tc.password)
				require.NoError(t, err)
				assert.NotNil(t, result.LoginResult, "Should have login result")
				assert.Equal(t, tc.expected.success, result.LoginResult.Success, "OAuth2 flow should complete successfully")
				assert.NotEmpty(t, result.AuthorizationCode, "Should receive authorization code")

				// Exchange authorization code for access token
				tokenResult, err := testCtx.OAuth2Client.ExchangeCodeForToken(opCtx, oauth2Client, result.AuthorizationCode)
				require.NoError(t, err)

				// Verify token response
				if tc.expected.hasToken {
					assert.NotEmpty(t, tokenResult.AccessToken, "Should receive access token")
				}
				if tc.expected.hasTokenType {
					assert.NotEmpty(t, tokenResult.TokenType, "Should receive token type")
				}
				if tc.expected.validExpiry {
					assert.Greater(t, tokenResult.ExpiresIn, 0, "Should have valid expiration time")
				}

				t.Logf("SUCCESS: Complete OAuth2 flow with access token for test case: %s!", tc.name)
				t.Logf("Access Token: %s", tokenResult.AccessToken[:min(50, len(tokenResult.AccessToken))]+"...")
				t.Logf("Token Type: %s", tokenResult.TokenType)
				t.Logf("Expires In: %d seconds", tokenResult.ExpiresIn)

				// Verify service is working
				assert.NotNil(t, testCtx.AuthServer.Service())
			})
		}
	})
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
