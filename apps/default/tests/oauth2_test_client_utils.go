package tests

import (
	"context"
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AccessTokenResult contains the result of access token acquisition
type AccessTokenResult struct {
	AccessToken      string
	TokenType        string
	ExpiresIn        int
	RefreshToken     string
	ProfileID        string
	LoginEventID     string
	OAuth2Client     *OAuth2Client
	VerificationCode string
}

// AcquireAccessTokenForContact performs the complete OAuth2 contact verification flow
// and returns an access token that can be used for authenticated API requests
func (c *OAuth2TestClient) AcquireAccessTokenForContact(ctx context.Context, t *testing.T, authServer *handlers.AuthServer, contact, userName string) (*AccessTokenResult, error) {
	t.Helper()

	// Reset rate limits to ensure tests don't get blocked
	authServer.ResetAllLoginRateLimits()

	// Step 1: Create OAuth2 client for this test
	c.SetTestingT(t) // Enable debug logging
	oauth2Client, err := c.CreateOAuth2Client(ctx, "test_client_"+userName)
	if err != nil {
		return nil, err
	}
	t.Logf("SUCCESS: OAuth2 client created with ID: %s", oauth2Client.ClientID)
	t.Logf("SUCCESS: Partition props : %s", oauth2Client.props)

	// Step 2: Initiate OAuth2 flow to get a valid login challenge
	loginRedirect, err := c.InitiateLoginFlow(ctx, oauth2Client)
	if err != nil {
		return nil, err
	}
	// Step 3: Submit contact for verification
	contactVerificationResult, err := c.PerformContactVerification(ctx, loginRedirect, contact)
	if err != nil {
		return nil, err
	}

	if !contactVerificationResult.Success {
		return nil, err
	}

	// Step 4: Get verification code from database (in real scenario, user would receive this via contact/SMS)
	verificationCode, err := c.GetVerificationCodeByLoginEventID(ctx, authServer, contactVerificationResult.LoginEventID)
	require.NoError(t, err)
	// Step 5: Complete contact verification with the code
	loginResult, err := c.PerformCodeVerification(ctx,
		contactVerificationResult.LoginEventID, contactVerificationResult.ProfileName, verificationCode)
	require.NoError(t, err)
	assert.True(t, loginResult.Success, "Contact verification should succeed with valid code")

	// Step 6: Handle consent flow if needed
	var authorizationCode string
	if loginResult.ConsentChallenge != "" {
		// Handle consent flow
		consentResult, err0 := c.PerformConsent(ctx, loginResult.ConsentChallenge)
		require.NoError(t, err0)
		assert.True(t, consentResult.Success, "Consent should succeed")
		assert.NotEmpty(t, consentResult.AuthorizationCode, "Should receive authorization code")
		authorizationCode = consentResult.AuthorizationCode
	} else {
		assert.NotEmpty(t, loginResult.AuthorizationCode, "Should receive authorization code directly")
		authorizationCode = loginResult.AuthorizationCode
	}

	// Step 7: Exchange authorization code for access token
	tokenResult, err := c.ExchangeCodeForToken(ctx, oauth2Client, authorizationCode)
	require.NoError(t, err)

	// Success! Complete OAuth2 flow completed
	t.Logf("SUCCESS: Complete OAuth2 contact verification flow completed!")
	t.Logf("Access Token: %s", tokenResult.AccessToken[:min(50, len(tokenResult.AccessToken))]+"...")
	t.Logf("Token Type: %s", tokenResult.TokenType)
	t.Logf("Expires In: %d seconds", tokenResult.ExpiresIn)

	// Extract profile ID from the verification result or token claims if available
	profileID := contactVerificationResult.ProfileName // This might need adjustment based on actual data structure

	return &AccessTokenResult{
		AccessToken:      tokenResult.AccessToken,
		TokenType:        tokenResult.TokenType,
		ExpiresIn:        tokenResult.ExpiresIn,
		RefreshToken:     tokenResult.RefreshToken,
		ProfileID:        profileID,
		LoginEventID:     contactVerificationResult.LoginEventID,
		OAuth2Client:     oauth2Client,
		VerificationCode: verificationCode,
	}, nil
}

// AcquireAccessTokenForTestUser is a convenience function that creates a test user and acquires an access token
func (c *OAuth2TestClient) AcquireAccessTokenForTestUser(ctx context.Context, t *testing.T, authServer *handlers.AuthServer) (*AccessTokenResult, error) {
	return c.AcquireAccessTokenForContact(ctx, t, authServer, "test@example.com", "Test User")
}

// min returns the minimum of two integers (helper function for Go versions < 1.21)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
