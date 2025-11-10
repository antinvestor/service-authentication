package handlers_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/tests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/structpb"
)

// Global mutex to ensure sequential execution of integration tests
var testMutex sync.Mutex

// Test timeout constants
const (
	TestTimeout      = 60 * time.Second // Overall test timeout
	OperationTimeout = 15 * time.Second // Individual operation timeout
	CleanupTimeout   = 5 * time.Second  // Cleanup operation timeout
)

// PasswordlessLoginTestSuite provides a dedicated test suite for passwordless login functionality
type PasswordlessLoginTestSuite struct {
	tests.BaseTestSuite
}

// TestPasswordlessLoginTestSuite runs the passwordless login test suite
func TestPasswordlessLoginTestSuite(t *testing.T) {
	suite.Run(t, new(PasswordlessLoginTestSuite))
}

// PasswordlessLoginTestContext holds common test setup for passwordless login tests
type PasswordlessLoginTestContext struct {
	AuthServer   *handlers.AuthServer
	Context      context.Context
	Cancel       context.CancelFunc
	OAuth2Client *tests.OAuth2TestClient
	LoginRepo    repository.LoginRepository
	TestServer   *httptest.Server
}

// SetupPasswordlessLoginTest creates a common test setup for passwordless login tests with timeout handling
func (suite *PasswordlessLoginTestSuite) SetupPasswordlessLoginTest(t *testing.T, dep *definition.DependencyOption) *PasswordlessLoginTestContext {
	// Use global mutex to ensure sequential execution
	testMutex.Lock()

	// Create context with timeout for overall test
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)

	baseCtx, authServer, deps := suite.CreateService(t, dep)

	// Set up HTTP test server
	router := authServer.SetupRouterV1(baseCtx)
	testServer := httptest.NewServer(router)

	// Create OAuth2 test client with test server URL
	oauth2Client := tests.NewOAuth2TestClient(authServer)
	oauth2Client.AuthServiceURL = testServer.URL

	// Create login repository
	loginRepo := deps.LoginRepo

	return &PasswordlessLoginTestContext{
		AuthServer:   authServer,
		Context:      ctx,
		Cancel:       cancel,
		OAuth2Client: oauth2Client,
		LoginRepo:    loginRepo,
		TestServer:   testServer,
	}
}

// TeardownPasswordlessLoginTest cleans up test resources with timeout protection
func (suite *PasswordlessLoginTestSuite) TeardownPasswordlessLoginTest(testCtx *PasswordlessLoginTestContext) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic during teardown: %v\n", r)
		}
		testMutex.Unlock()
	}()

	// Create cleanup context with timeout
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), CleanupTimeout)
	defer cleanupCancel()

	if testCtx.OAuth2Client != nil {
		testCtx.OAuth2Client.Cleanup(cleanupCtx)
	}

	if testCtx.TestServer != nil {
		testCtx.TestServer.Close()
	}

	if testCtx.Cancel != nil {
		testCtx.Cancel()
	}
}

// CreateTestProfile creates a test profile for passwordless authentication
func (suite *PasswordlessLoginTestSuite) CreateTestProfile(ctx context.Context, authServer *handlers.AuthServer, contact, name string) (*profilev1.ProfileObject, error) {
	profileCli := authServer.ProfileCli()

	properties, _ := structpb.NewStruct(map[string]any{
		handlers.KeyProfileName: name,
	})

	result, err := profileCli.Create(ctx, connect.NewRequest(&profilev1.CreateRequest{
		Type:       profilev1.ProfileType_PERSON,
		Contact:    contact,
		Properties: properties,
	}))
	if err != nil {
		return nil, err
	}

	return result.Msg.GetData(), nil
}

// CreateVerification creates a mock verification record for testing
func (suite *PasswordlessLoginTestSuite) CreateVerification(ctx context.Context, authServer *handlers.AuthServer, contactID string) (*profilev1.CreateContactVerificationResponse, error) {
	profileCli := authServer.ProfileCli()
	res, err := profileCli.CreateContactVerification(ctx, connect.NewRequest(&profilev1.CreateContactVerificationRequest{
		ContactId:        contactID,
		DurationToExpire: "15m",
	}))
	if err != nil {
		return nil, err
	}

	return res.Msg, nil
}

// TestOAuth2ClientCreation tests just the OAuth2 client creation step
func (suite *PasswordlessLoginTestSuite) TestOAuth2ClientCreation() {
	testCases := []struct {
		name string
	}{
		{
			name: "BasicClientCreation",
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		testCtx := suite.SetupPasswordlessLoginTest(t, dep)
		defer suite.TeardownPasswordlessLoginTest(testCtx)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
				defer opCancel()

				// Test just OAuth2 client creation
				testCtx.OAuth2Client.SetTestingT(t) // Enable debug logging
				oauth2Client, err := testCtx.OAuth2Client.CreateOAuth2Client(opCtx, tc.name)
				if err != nil {
					t.Logf("FAILED: OAuth2 client creation failed: %v", err)
					t.FailNow()
				}
				t.Logf("SUCCESS: OAuth2 client created with ID: %s", oauth2Client.ClientID)

				// Test login challenge initiation
				loginChallenge, err := testCtx.OAuth2Client.InitiateLoginFlow(testCtx.Context, oauth2Client)
				if err != nil {
					t.Logf("FAILED: OAuth2 login flow initiation failed: %v", err)
					t.FailNow()
				}
				t.Logf("SUCCESS: Login challenge received: %s", loginChallenge)

				t.Logf("OAuth2 client creation and login challenge test completed successfully")
			})
		}
	})
}

// TestSuccessfulContactLoginFlow tests the passwordless contact verification flow
func (suite *PasswordlessLoginTestSuite) TestSuccessfulContactLoginFlow() {
	testCases := []struct {
		name        string
		contact     string
		userName    string
		shouldError bool
	}{
		{
			name:        "ValidContactVerification",
			contact:     "test@example.com",
			userName:    "Test User",
			shouldError: false,
		},
		{
			name:        "ValidPhoneVerification",
			contact:     "+12345678990",
			userName:    "Phone User",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {

				testCtx := suite.SetupPasswordlessLoginTest(t, dep)
				defer suite.TeardownPasswordlessLoginTest(testCtx)

				opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
				defer opCancel()

				// Create OAuth2 client for this test
				testCtx.OAuth2Client.SetTestingT(t) // Enable debug logging
				oauth2Client, err := testCtx.OAuth2Client.CreateOAuth2Client(opCtx, tc.name)
				if err != nil {
					t.Logf("FAILED: OAuth2 client creation failed: %v", err)
					t.FailNow()
				}
				t.Logf("SUCCESS: OAuth2 client created with ID: %s", oauth2Client.ClientID)

				// Initiate OAuth2 flow to get a valid login challenge
				loginRedirect, err := testCtx.OAuth2Client.InitiateLoginFlow(testCtx.Context, oauth2Client)
				if err != nil {
					t.Logf("FAILED: OAuth2 login flow initiation failed: %v", err)
					t.FailNow()
				}
				assert.NotEmpty(t, loginRedirect, "Should receive a valid login challenge")

				// Step 1: Submit contact for verification
				contactVerificationResult, err := testCtx.OAuth2Client.PerformContactVerification(testCtx.Context, loginRedirect, tc.contact)
				if err != nil {
					t.Logf("FAILED: Contact verification submission failed: %v", err)
					t.FailNow()
				}

				t.Logf("Contact verification result: Success=%v, VerificationSent=%v, LoginEventID=%s, ProfileName=%s, ErrorMessage=%s",
					contactVerificationResult.Success, contactVerificationResult.VerificationSent,
					contactVerificationResult.LoginEventID, contactVerificationResult.ProfileName, contactVerificationResult.ErrorMessage)

				if !contactVerificationResult.Success {
					t.Logf("FAILED: Contact verification was not successful. Error: %s", contactVerificationResult.ErrorMessage)
					t.FailNow()
				}

				assert.True(t, contactVerificationResult.Success, "Contact verification submission should succeed")
				assert.True(t, contactVerificationResult.VerificationSent, "Verification should be sent")
				assert.NotEmpty(t, contactVerificationResult.LoginEventID, "Should receive login event ID")

				t.Logf("Contact verification submitted successfully:")
				t.Logf("  Login Event ID: %s", contactVerificationResult.LoginEventID)
				t.Logf("  Profile Name: %s", contactVerificationResult.ProfileName)

				// Step 2: Get verification code from database (in real scenario, user would receive this via contact/SMS)
				verificationCode, err := testCtx.OAuth2Client.GetVerificationCodeByLoginEventID(opCtx, testCtx.AuthServer, contactVerificationResult.LoginEventID)
				require.NoError(t, err)
				assert.NotEmpty(t, verificationCode, "Should retrieve verification code from database")

				t.Logf("Retrieved verification code: %s", verificationCode)

				// Step 3: Complete contact verification with the code
				loginResult, err := testCtx.OAuth2Client.PerformCodeVerification(testCtx.Context,
					contactVerificationResult.LoginEventID, contactVerificationResult.ProfileName, verificationCode)
				require.NoError(t, err)
				assert.True(t, loginResult.Success, "Contact verification should succeed with valid code")

				// Verify that we get a consent challenge or authorization code
				var authorizationCode string
				if loginResult.ConsentChallenge != "" {
					// Handle consent flow
					consentResult, err0 := testCtx.OAuth2Client.PerformConsent(testCtx.Context, loginResult.ConsentChallenge)
					require.NoError(t, err0)
					assert.True(t, consentResult.Success, "Consent should succeed")
					assert.NotEmpty(t, consentResult.AuthorizationCode, "Should receive authorization code")
					authorizationCode = consentResult.AuthorizationCode
				} else {
					assert.NotEmpty(t, loginResult.AuthorizationCode, "Should receive authorization code directly")
					authorizationCode = loginResult.AuthorizationCode
				}

				// Step 4: Exchange authorization code for access token
				tokenResult, err := testCtx.OAuth2Client.ExchangeCodeForToken(testCtx.Context, oauth2Client, authorizationCode)
				require.NoError(t, err)
				assert.NotEmpty(t, tokenResult.AccessToken, "Should receive access token")
				assert.NotEmpty(t, tokenResult.TokenType, "Should receive token type")
				assert.Greater(t, tokenResult.ExpiresIn, 0, "Should have valid expiration time")

				// Success! Complete OAuth2 flow completed
				t.Logf("SUCCESS: Complete OAuth2 contact verification flow completed!")
				t.Logf("Access Token: %s", tokenResult.AccessToken[:min(50, len(tokenResult.AccessToken))]+"...")
				t.Logf("Token Type: %s", tokenResult.TokenType)
				t.Logf("Expires In: %d seconds", tokenResult.ExpiresIn)

				t.Logf("Contact verification flow completed for %s", tc.contact)
			})
		}
	})
}

// TestProviderLoginFlow tests OAuth2 provider login integration
func (suite *PasswordlessLoginTestSuite) TestProviderLoginFlow() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		testCtx := suite.SetupPasswordlessLoginTest(t, dep)
		defer suite.TeardownPasswordlessLoginTest(testCtx)

		opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
		defer opCancel()

		// Test that provider login endpoints are accessible
		providerURL := fmt.Sprintf("%s/s/auth/google", testCtx.TestServer.URL)

		req, err := http.NewRequestWithContext(opCtx, "GET", providerURL, nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should either redirect to provider or return error (depending on configuration)
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500,
			"Provider endpoint should be accessible, got %d", resp.StatusCode)

		t.Log("Provider login flow endpoint is accessible")
	})
}
