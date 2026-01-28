package handlers_test

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/tests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/structpb"
)

// Global mutex to ensure sequential execution of integration tests
var verificationTestMutex sync.Mutex

// Test timeout constants
const (
	VerificationTestTimeout      = 60 * time.Second // Overall test timeout
	VerificationOperationTimeout = 15 * time.Second // Individual operation timeout
)

type LoginVerificationTestSuite struct {
	tests.BaseTestSuite
}

// VerificationTestContext holds common test setup for verification tests
type VerificationTestContext struct {
	AuthServer   *handlers.AuthServer
	Context      context.Context
	Cancel       context.CancelFunc
	OAuth2Client *tests.OAuth2TestClient
	LoginRepo    repository.LoginRepository
}

// SetupVerificationTest creates a common test setup for verification tests with timeout handling
func (suite *LoginVerificationTestSuite) SetupVerificationTest(t *testing.T, dep *definition.DependencyOption) *VerificationTestContext {
	// Use global mutex to ensure sequential execution
	verificationTestMutex.Lock()

	// Create context with timeout for overall test
	ctx, cancel := context.WithTimeout(context.Background(), VerificationTestTimeout)

	baseCtx, authServer, deps := suite.CreateService(t, dep)
	_ = baseCtx

	// Use the suite's server URL since Hydra is configured to call webhooks there
	// Creating a new httptest server would cause webhook calls to fail
	oauth2Client := tests.NewOAuth2TestClient(authServer)
	oauth2Client.AuthServiceURL = suite.ServerUrl()

	// Create login repository
	return &VerificationTestContext{
		AuthServer:   authServer,
		Context:      ctx,
		Cancel:       cancel,
		OAuth2Client: oauth2Client,
		LoginRepo:    deps.LoginRepo,
	}
}

// TeardownVerificationTest cleans up test resources with timeout protection
func (suite *LoginVerificationTestSuite) TeardownVerificationTest(testCtx *VerificationTestContext) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic during teardown: %v\n", r)
		}
		verificationTestMutex.Unlock()
	}()

	// Create cleanup context with timeout
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cleanupCancel()

	if testCtx.OAuth2Client != nil {
		testCtx.OAuth2Client.Cleanup(cleanupCtx)
	}

	if testCtx.Cancel != nil {
		testCtx.Cancel()
	}
}

// CreateTestProfile creates a test profile for verification testing
func (suite *LoginVerificationTestSuite) CreateTestProfile(ctx context.Context, authServer *handlers.AuthServer, email, name string) (*profilev1.ProfileObject, error) {
	profileCli := authServer.ProfileCli()

	props, _ := structpb.NewStruct(map[string]any{handlers.KeyProfileName: name})

	resp, err := profileCli.Create(ctx, connect.NewRequest(&profilev1.CreateRequest{
		Type:       profilev1.ProfileType_PERSON,
		Contact:    email,
		Properties: props,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg.GetData(), nil
}

// CreateVerificationRecord creates a verification record and returns the verification code
func (suite *LoginVerificationTestSuite) CreateVerificationRecord(ctx context.Context, authServer *handlers.AuthServer, contactID string) (*profilev1.CreateContactVerificationResponse, error) {
	profileCli := authServer.ProfileCli()
	resp, err := profileCli.CreateContactVerification(ctx, connect.NewRequest(&profilev1.CreateContactVerificationRequest{
		ContactId:        contactID,
		DurationToExpire: "15m",
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// TestCodeVerificationFlow tests the complete verification flow with real database verification codes
func (suite *LoginVerificationTestSuite) TestCodeVerificationFlow() {
	testCases := []struct {
		name          string
		contact       string
		userName      string
		badLoginCodes []string
		expectSuccess bool
	}{
		{
			name:          "ValidEmailVerification",
			contact:       "verify@example.com",
			userName:      "Verify User",
			badLoginCodes: []string{},
			expectSuccess: true,
		},
		{
			name:          "ValidPhoneVerification",
			contact:       "+12345678900",
			userName:      "Phone User",
			badLoginCodes: []string{},
			expectSuccess: true,
		},
		{
			name:          "One wrong attempt then correct",
			contact:       "onewrong@example.com",
			userName:      "One Wrong User",
			badLoginCodes: []string{"111111"},
			expectSuccess: true,
		},
		{
			name:          "Three wrong attempts then correct",
			contact:       "threewrong@example.com",
			userName:      "Three Wrong User",
			badLoginCodes: []string{"111111", "222222", "333333"},
			expectSuccess: false,
		},
		{
			name:          "Five wrong attempts then the correct one",
			contact:       "fivewrong@example.com",
			userName:      "Five Wrong User",
			badLoginCodes: []string{"111111", "222222", "333333", "444444", "555555"},
			expectSuccess: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {

				testCtx := suite.SetupVerificationTest(t, dep)
				defer suite.TeardownVerificationTest(testCtx)

				opCtx, opCancel := context.WithTimeout(testCtx.Context, VerificationOperationTimeout)
				defer opCancel()

				// Create OAuth2 client for this test
				testCtx.OAuth2Client.SetTestingT(t) // Enable debug logging
				oauth2Client, err := testCtx.OAuth2Client.CreateOAuth2Client(opCtx, tc.name)
				require.NoError(t, err)

				// Initiate OAuth2 flow to get a valid login challenge
				loginRedirect, err := testCtx.OAuth2Client.InitiateLoginFlow(testCtx.Context, oauth2Client)
				require.NoError(t, err)

				// Step 1: Submit contact for verification
				contactVerificationResult, err := testCtx.OAuth2Client.PerformContactVerification(testCtx.Context, loginRedirect, tc.contact)
				require.NoError(t, err)

				if !contactVerificationResult.Success {
					t.Logf("FAILED: Contact verification was not successful. Error: %s", contactVerificationResult.ErrorMessage)
					t.FailNow()
				}

				require.True(t, contactVerificationResult.Success, "Contact verification submission should succeed")

				// Step 2: Get verification code from database (in real scenario, user would receive this via contact/SMS)
				// Use suite.Handler() which accesses the same database as the HTTP handlers
				verificationCode, err := testCtx.OAuth2Client.GetVerificationCodeByLoginEventID(opCtx, suite.Handler(), contactVerificationResult.LoginEventID)
				require.NoError(t, err)
				require.NotEmpty(t, verificationCode, "Should retrieve verification code from database")

				// Try all the wrong codes first
				for i, wrongCode := range tc.badLoginCodes {
					t.Logf("Attempting wrong verification code %d/%d: %s", i+1, len(tc.badLoginCodes), wrongCode)
					result, err2 := testCtx.OAuth2Client.PerformCodeVerification(testCtx.Context,
						contactVerificationResult.LoginEventID, contactVerificationResult.ProfileName, wrongCode)

					// Wrong codes should fail
					if err2 == nil && result.Success {
						t.Errorf("Expected wrong code %s to fail, but it succeeded", wrongCode)
					}

					time.Sleep(1 * time.Second)
				}

				// For tests expecting failure, try the correct code to verify it's blocked
				// For tests expecting success, try the correct code to verify it works
				t.Logf("Now attempting correct verification code: %s", verificationCode)
				finalResult, finalErr := testCtx.OAuth2Client.PerformCodeVerification(testCtx.Context,
					contactVerificationResult.LoginEventID, contactVerificationResult.ProfileName, verificationCode)

				// Validate final result
				if tc.expectSuccess {
					require.NoError(t, finalErr, "Final verification should succeed")
					require.NotNil(t, finalResult, "Final result should not be nil for successful verification")
					require.True(t, finalResult.Success, "Final verification should succeed after wrong attempts")
					t.Logf("Successfully completed verification after %d wrong attempts", len(tc.badLoginCodes))
				} else {
					require.Error(t, finalErr, "Final verification should fail after multiple wrong attempts")
					t.Logf("Verification correctly failed after %d wrong attempts", len(tc.badLoginCodes)+1)
				}

			})
		}
	})
}

// TestVerificationEndpointBasics tests basic verification endpoint functionality
func (suite *LoginVerificationTestSuite) TestVerificationEndpointBasics() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		testCtx := suite.SetupVerificationTest(t, dep)
		defer suite.TeardownVerificationTest(testCtx)

		opCtx, opCancel := context.WithTimeout(testCtx.Context, VerificationOperationTimeout)
		defer opCancel()

		// Test verification page accessibility
		verificationURL := fmt.Sprintf("%s/s/verify/contact/test-event?login_event_id=test-event&profile_name=Test+User", suite.ServerUrl())

		req, err := http.NewRequestWithContext(opCtx, "GET", verificationURL, nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer util.CloseAndLogOnError(testCtx.Context, resp.Body)

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, resp.Header.Get("Content-Type"), "text/html")

		t.Log("Verification endpoint basics test completed")
	})
}

func TestLoginVerification(t *testing.T) {
	suite.Run(t, new(LoginVerificationTestSuite))
}
