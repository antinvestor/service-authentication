package handlers_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/tests"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
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
func (suite *PasswordlessLoginTestSuite) SetupPasswordlessLoginTest(t *testing.T, dep *definition.DependancyOption) *PasswordlessLoginTestContext {
	// Use global mutex to ensure sequential execution
	testMutex.Lock()

	// Create context with timeout for overall test
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)

	authServer, baseCtx := suite.CreateService(t, dep)

	// Set up HTTP test server
	router := authServer.SetupRouterV1(baseCtx)
	testServer := httptest.NewServer(router)

	// Create OAuth2 test client
	oauth2Client := tests.NewOAuth2TestClient(authServer)

	// Create login repository
	loginRepo := repository.NewLoginRepository(authServer.Service())

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
func (suite *PasswordlessLoginTestSuite) CreateTestProfile(ctx context.Context, authServer *handlers.AuthServer, email, name string) (*profilev1.ProfileObject, error) {
	profileCli := authServer.ProfileCli()
	return profileCli.CreateProfileByContactAndName(ctx, email, name)
}

// CreateVerification creates a mock verification record for testing
func (suite *PasswordlessLoginTestSuite) CreateVerification(ctx context.Context, authServer *handlers.AuthServer, contactID string) (*profilev1.CreateContactVerificationResponse, error) {
	profileCli := authServer.ProfileCli()
	return profileCli.Svc().CreateContactVerification(ctx, &profilev1.CreateContactVerificationRequest{
		ContactId:        contactID,
		DurationToExpire: "15m",
	})
}

// TestContactVerificationFlow tests the complete contact verification flow
func (suite *PasswordlessLoginTestSuite) TestContactVerificationFlow() {
	testCases := []struct {
		name        string
		email       string
		userName    string
		shouldError bool
	}{
		{
			name:        "ValidContactVerification",
			email:       "test@example.com",
			userName:    "Test User",
			shouldError: false,
		},
		{
			name:        "ValidPhoneVerification",
			email:       "+1234567890",
			userName:    "Phone User",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		testCtx := suite.SetupPasswordlessLoginTest(t, dep)
		defer suite.TeardownPasswordlessLoginTest(testCtx)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
				defer opCancel()

				// Step 1: Create test profile
				profile, err := suite.CreateTestProfile(opCtx, testCtx.AuthServer, tc.email, tc.userName)
				require.NoError(t, err)
				assert.NotNil(t, profile)

				// Step 2: Get contact ID
				var contactID string
				for _, contact := range profile.GetContacts() {
					if strings.EqualFold(tc.email, contact.GetDetail()) {
						contactID = contact.GetId()
						break
					}
				}
				require.NotEmpty(t, contactID, "Contact ID should be found")

				// Step 3: Initiate OAuth2 flow to get login challenge
				oauth2Client, err := testCtx.OAuth2Client.CreateOAuth2Client(opCtx, tc.name)
				require.NoError(t, err)

				loginChallenge, err := testCtx.OAuth2Client.InitiateLoginFlow(opCtx, oauth2Client)
				require.NoError(t, err)
				assert.NotEmpty(t, loginChallenge)

				// Step 4: Test contact verification initiation
				verificationURL := fmt.Sprintf("%s/s/verify/contact/post", testCtx.TestServer.URL)
				formData := url.Values{
					"contact":         {tc.email},
					"login_challenge": {loginChallenge},
				}

				req, err := http.NewRequestWithContext(opCtx, "POST", verificationURL, strings.NewReader(formData.Encode()))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Should redirect to verification page or process successfully
				assert.True(t, resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusOK,
					"Expected redirect or success, got %d", resp.StatusCode)

				t.Logf("Contact verification flow completed for %s", tc.email)
			})
		}
	})
}

// TestLoginSubmissionFlow tests the final login submission with verification code
func (suite *PasswordlessLoginTestSuite) TestLoginSubmissionFlow() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		testCtx := suite.SetupPasswordlessLoginTest(t, dep)
		defer suite.TeardownPasswordlessLoginTest(testCtx)

		opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
		defer opCancel()

		// Create test profile
		email := "submission@example.com"
		userName := "Submission User"
		profile, err := suite.CreateTestProfile(opCtx, testCtx.AuthServer, email, userName)
		require.NoError(t, err)

		// Get contact ID
		var contactID string
		for _, contact := range profile.GetContacts() {
			if strings.EqualFold(email, contact.GetDetail()) {
				contactID = contact.GetId()
				break
			}
		}
		require.NotEmpty(t, contactID)

		// Create mock verification
		verification, err := suite.CreateVerification(opCtx, testCtx.AuthServer, contactID)
		require.NoError(t, err)

		// Create login event manually for testing
		loginRepo := testCtx.LoginRepo
		login := &models.Login{
			ProfileID: profile.GetId(),
			Source:    string(models.LoginSourceDirect),
		}
		login.GenID(opCtx)
		err = loginRepo.Save(opCtx, login)
		require.NoError(t, err)

		loginEventRepo := repository.NewLoginEventRepository(testCtx.AuthServer.Service())
		loginEvent := &models.LoginEvent{
			LoginID:          login.GetID(),
			LoginChallengeID: "test-challenge",
			VerificationID:   verification.GetId(),
			ContactID:        contactID,
		}
		loginEvent.GenID(opCtx)
		err = loginEventRepo.Save(opCtx, loginEvent)
		require.NoError(t, err)

		// Test login submission
		loginURL := fmt.Sprintf("%s/s/login/post", testCtx.TestServer.URL)
		formData := url.Values{
			"login_event_id":    {loginEvent.GetID()},
			"profile_name":      {userName},
			"verification_code": {"123456"}, // Mock verification code
		}

		req, err := http.NewRequestWithContext(opCtx, "POST", loginURL, strings.NewReader(formData.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should process the login submission
		assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 400,
			"Expected success or redirect, got %d", resp.StatusCode)

		t.Log("Login submission flow completed successfully")
	})
}

// TestContactValidation tests the contact validation utility
func (suite *PasswordlessLoginTestSuite) TestContactValidation() {
	testCases := []struct {
		name          string
		contact       string
		expectedType  utils.ContactType
		shouldBeValid bool
	}{
		{
			name:          "ValidEmail",
			contact:       "test@example.com",
			expectedType:  utils.ContactTypeEmail,
			shouldBeValid: true,
		},
		{
			name:          "ValidPhone",
			contact:       "+1234567890",
			expectedType:  utils.ContactTypePhone,
			shouldBeValid: true,
		},
		{
			name:          "InvalidContact",
			contact:       "invalid-contact",
			expectedType:  utils.ContactTypeUnknown,
			shouldBeValid: false,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			contactType, isValid := utils.ValidateContact(tc.contact)

			assert.Equal(t, tc.expectedType, contactType, "Contact type should match expected")
			assert.Equal(t, tc.shouldBeValid, isValid, "Contact validity should match expected")

			if tc.shouldBeValid {
				assert.NotEqual(t, utils.ContactTypeUnknown, contactType, "Valid contacts should not be unknown type")
			}
		})
	}
}

// TestProviderLoginFlow tests OAuth2 provider login integration
func (suite *PasswordlessLoginTestSuite) TestProviderLoginFlow() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
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

// TestLoginOptionsConfiguration tests that login options are properly configured
func (suite *PasswordlessLoginTestSuite) TestLoginOptionsConfiguration() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		testCtx := suite.SetupPasswordlessLoginTest(t, dep)
		defer suite.TeardownPasswordlessLoginTest(testCtx)

		opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
		defer opCancel()

		// Test that login page shows available options
		loginURL := fmt.Sprintf("%s/s/login?login_challenge=test-challenge", testCtx.TestServer.URL)

		req, err := http.NewRequestWithContext(opCtx, "GET", loginURL, nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "Login page should be accessible")

		t.Log("Login options configuration test completed")
	})
}

// TestVerificationPageDisplay tests that the verification page displays correctly
func (suite *PasswordlessLoginTestSuite) TestVerificationPageDisplay() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		testCtx := suite.SetupPasswordlessLoginTest(t, dep)
		defer suite.TeardownPasswordlessLoginTest(testCtx)

		opCtx, opCancel := context.WithTimeout(testCtx.Context, OperationTimeout)
		defer opCancel()

		// Test verification page with parameters
		verificationURL := fmt.Sprintf("%s/s/verify/contact?login_event_id=test-event&profile_name=Test+User",
			testCtx.TestServer.URL)

		req, err := http.NewRequestWithContext(opCtx, "GET", verificationURL, nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "Verification page should be accessible")

		t.Log("Verification page display test completed")
	})
}
