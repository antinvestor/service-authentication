package handlers_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	commonv1 "github.com/antinvestor/apis/go/common/v1"
	notificationv1 "github.com/antinvestor/apis/go/notification/v1"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/tests"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/pitabwire/frame/frametests"
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

	// Create OAuth2 test client with test server URL
	oauth2Client := tests.NewOAuth2TestClient(authServer)
	oauth2Client.AuthServiceURL = testServer.URL

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

// GetVerificationCodeFromDatabase retrieves the actual verification code from the database
func (suite *PasswordlessLoginTestSuite) GetVerificationCodeFromDatabase(ctx context.Context, authServer *handlers.AuthServer, LoginEventID string) (string, error) {

	loginEventRepo := repository.NewLoginEventRepository(authServer.Service())
	loginEvt, err := loginEventRepo.GetByID(ctx, LoginEventID)
	if err != nil {
		return "", err
	}

	notifCli := authServer.NotificationCli()

	notif, err := frametests.WaitForConditionWithResult[notificationv1.Notification](ctx, func() (*notificationv1.Notification, error) {

		resp, err0 := notifCli.Svc().Search(ctx, &commonv1.SearchRequest{
			Limits: &commonv1.Pagination{
				Count: 10,
				Page:  0,
			},
			Extras: map[string]string{"template_id": "9bsv0s23l8og00vgjq90"},
		})
		if err0 != nil {
			return nil, err0
		}

		var nSlice []*notificationv1.Notification
		for {
			n, err1 := resp.Recv()
			if err1 == nil {
				nSlice = append(nSlice, n.GetData()...)
				continue
			}

			if errors.Is(err1, io.EOF) {
				break
			}
			return nil, err1

		}

		if len(nSlice) == 0 {
			return nil, nil
		}

		for _, n := range nSlice {
			if n.GetPayload()["verification_id"] == loginEvt.VerificationID {
				return n, nil
			}
		}

		return nil, nil
	}, 5*time.Second, 300*time.Millisecond)

	if err != nil {
		return "", err
	}

	return notif.GetPayload()["code"], nil
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

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
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

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {

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

				// Step 2: Get verification code from database (in real scenario, user would receive this via email/SMS)
				verificationCode, err := suite.GetVerificationCodeFromDatabase(opCtx, testCtx.AuthServer, contactVerificationResult.LoginEventID)
				require.NoError(t, err)
				assert.NotEmpty(t, verificationCode, "Should retrieve verification code from database")

				t.Logf("Retrieved verification code: %s", verificationCode)

				// Step 3: Complete contact verification with the code
				loginResult, err := testCtx.OAuth2Client.CheckContactVerification(testCtx.Context,
					contactVerificationResult.LoginEventID, contactVerificationResult.ProfileName, verificationCode)
				require.NoError(t, err)
				assert.True(t, loginResult.Success, "Contact verification should succeed with valid code")

				// Verify that we get a consent challenge or authorization code
				var authorizationCode string
				if loginResult.ConsentChallenge != "" {
					// Handle consent flow
					consentResult, err := testCtx.OAuth2Client.PerformConsent(testCtx.Context, loginResult.ConsentChallenge)
					require.NoError(t, err)
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
