package tests

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	hydraclientgo "github.com/ory/hydra-client-go/v2"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/require"
)

// OAuth2TestClient provides utilities for testing OAuth2 flows with Hydra
type OAuth2TestClient struct {
	HydraAdminURL  string
	HydraPublicURL string
	AuthServiceURL string
	Client         *http.Client
	t              *testing.T
}

// NewOAuth2TestClient creates a new OAuth2 test client
func NewOAuth2TestClient(t *testing.T, authServer *handlers.AuthServer, authServiceURL string) *OAuth2TestClient {
	// Get the public Hydra URL from config
	publicURL := authServer.Config().Oauth2ServiceURI

	// Convert public URL (port 4444) to admin URL (port 4445)
	adminURL := authServer.Config().Oauth2ServiceAdminURI

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	return &OAuth2TestClient{
		HydraAdminURL:  adminURL,
		HydraPublicURL: publicURL,
		AuthServiceURL: authServiceURL,
		Client: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Don't follow redirects - we want to capture them
				return http.ErrUseLastResponse
			},
		},
		t: t,
	}
}

// OAuth2Client represents an OAuth2 client configuration
type OAuth2Client struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Scope        string
}

// CreateOAuth2Client creates a test OAuth2 client in Hydra
func (c *OAuth2TestClient) CreateOAuth2Client(ctx context.Context) (*OAuth2Client, error) {
	// Generate random client credentials
	clientID := "test-client-" + c.generateRandomString(8)
	clientSecret := c.generateRandomString(32)
	redirectURI := c.AuthServiceURL + "/callback"

	// Create Hydra client configuration
	configuration := hydraclientgo.NewConfiguration()
	configuration.Servers = hydraclientgo.ServerConfigurations{{URL: c.HydraAdminURL}}
	apiClient := hydraclientgo.NewAPIClient(configuration).OAuth2API

	// Create OAuth2 client request
	oAuth2Client := hydraclientgo.NewOAuth2Client()
	oAuth2Client.SetClientId(clientID)
	oAuth2Client.SetClientSecret(clientSecret)
	oAuth2Client.SetRedirectUris([]string{redirectURI})
	oAuth2Client.SetGrantTypes([]string{"authorization_code", "refresh_token"})
	oAuth2Client.SetResponseTypes([]string{"code"})
	oAuth2Client.SetScope("openid profile email")

	// Create the client in Hydra
	createdClient, _, err := apiClient.CreateOAuth2Client(ctx).OAuth2Client(*oAuth2Client).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth2 client: %w", err)
	}

	return &OAuth2Client{
		ClientID:     createdClient.GetClientId(),
		ClientSecret: createdClient.GetClientSecret(),
		RedirectURIs: createdClient.GetRedirectUris(),
		Scope:        "openid profile email",
	}, nil
}

// InitiateLoginFlow starts an OAuth2 authorization code flow and returns the login challenge
func (c *OAuth2TestClient) InitiateLoginFlow(ctx context.Context, client *OAuth2Client) (string, error) {
	// Build authorization URL
	state := c.generateRandomString(16)
	nonce := c.generateRandomString(16)

	params := url.Values{
		"client_id":     {client.ClientID},
		"response_type": {"code"},
		"scope":         {client.Scope},
		"redirect_uri":  {client.RedirectURIs[0]},
		"state":         {state},
		"nonce":         {nonce},
	}

	// Use the standard OAuth2 authorization endpoint
	authURL := fmt.Sprintf("%s/oauth2/auth", c.HydraPublicURL)
	fullAuthURL := fmt.Sprintf("%s?%s", authURL, params.Encode())

	fmt.Printf("DEBUG: HydraPublicURL: %s\n", c.HydraPublicURL)
	fmt.Printf("DEBUG: Full auth URL: %s\n", fullAuthURL)

	// Make request to initiate OAuth2 flow
	req, err := http.NewRequestWithContext(ctx, "GET", fullAuthURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to initiate OAuth2 flow: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	fmt.Printf("DEBUG: Response status: %d\n", resp.StatusCode)

	// Extract login challenge from the redirect URL
	// Hydra should redirect to our auth service with login_challenge parameter
	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		fmt.Printf("DEBUG: Redirect location: %s\n", location)
		if location != "" {
			parsedURL, err := url.Parse(location)
			if err != nil {
				return "", fmt.Errorf("failed to parse redirect URL: %w", err)
			}

			loginChallenge := parsedURL.Query().Get("login_challenge")
			if loginChallenge == "" {
				return "", fmt.Errorf("no login_challenge found in redirect URL: %s", location)
			}

			return loginChallenge, nil
		}
	}

	// If we get here, the OAuth2 flow didn't work as expected
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OAuth2 authorization failed with status %d: %s", resp.StatusCode, string(body))
	}

	return "", fmt.Errorf("unexpected response status: %d", resp.StatusCode)
}

// PerformLogin performs the login process with the given credentials and login challenge
func (c *OAuth2TestClient) PerformLogin(ctx context.Context, loginChallenge, email, password string) (*LoginResult, error) {
	// Step 1: Get the login form to extract CSRF token
	loginFormURL := fmt.Sprintf("%s/s/login?login_challenge=%s", c.AuthServiceURL, loginChallenge)

	req, err := http.NewRequestWithContext(ctx, "GET", loginFormURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create login form request: %w", err)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get login form: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status getting login form: %d", resp.StatusCode)
	}

	// Parse HTML to extract CSRF token
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read login form: %w", err)
	}

	// Extract CSRF token from HTML (look for input with name="gorilla.csrf.Token")
	csrfToken := ""
	bodyStr := string(body)
	if strings.Contains(bodyStr, `name="gorilla.csrf.Token"`) {
		// Simple regex to extract CSRF token value
		re := regexp.MustCompile(`name="gorilla\.csrf\.Token"[^>]*value="([^"]*)"`)
		matches := re.FindStringSubmatch(bodyStr)
		if len(matches) > 1 {
			csrfToken = matches[1]
		}
	}

	// Step 2: Submit login with CSRF token
	loginURL := fmt.Sprintf("%s/s/login/post", c.AuthServiceURL)

	// Prepare form data
	formData := url.Values{}
	formData.Set("contact", email)
	formData.Set("password", password)
	formData.Set("login_challenge", loginChallenge)
	if csrfToken != "" {
		formData.Set("gorilla.csrf.Token", csrfToken)
	}

	req, err = http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", loginFormURL) // Use the login form URL as referer for CSRF validation

	resp, err = c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to submit login: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	result := &LoginResult{
		StatusCode: resp.StatusCode,
		Location:   resp.Header.Get("Location"),
		Success:    false,
	}

	// Check if login was successful (should redirect to consent or back to client)
	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if location != "" {
			parsedURL, err := url.Parse(location)
			if err != nil {
				return result, fmt.Errorf("failed to parse redirect URL: %w", err)
			}

			// Check if redirected to consent flow
			if strings.Contains(location, "consent_challenge") {
				result.ConsentChallenge = parsedURL.Query().Get("consent_challenge")
				result.Success = true
			} else if strings.Contains(location, "code=") {
				// Direct redirect to client with authorization code
				result.AuthorizationCode = parsedURL.Query().Get("code")
				result.Success = true
			}
		}
	}

	return result, nil
}

// PerformLoginWithErrorCapture performs login and captures detailed error information
func (c *OAuth2TestClient) PerformLoginWithErrorCapture(ctx context.Context, loginChallenge, email, password string) (*LoginResult, string, error) {
	// Step 1: Get the login form to extract CSRF token
	loginFormURL := fmt.Sprintf("%s/s/login?login_challenge=%s", c.AuthServiceURL, loginChallenge)

	req, err := http.NewRequestWithContext(ctx, "GET", loginFormURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create login form request: %w", err)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get login form: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, string(body), fmt.Errorf("unexpected status getting login form: %d", resp.StatusCode)
	}

	// Parse HTML to extract CSRF token
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read login form: %w", err)
	}

	// Extract CSRF token from HTML (look for input with name="gorilla.csrf.Token")
	csrfToken := ""
	bodyStr := string(body)
	if strings.Contains(bodyStr, `name="gorilla.csrf.Token"`) {
		// Simple regex to extract CSRF token value
		re := regexp.MustCompile(`name="gorilla\.csrf\.Token"[^>]*value="([^"]*)"`)
		matches := re.FindStringSubmatch(bodyStr)
		if len(matches) > 1 {
			csrfToken = matches[1]
		}
	}

	// Debug logging
	c.t.Logf("DEBUG: CSRF token extracted: %s (length: %d)", csrfToken, len(csrfToken))
	c.t.Logf("DEBUG: Form contains CSRF field: %v", strings.Contains(bodyStr, `name="gorilla.csrf.Token"`))
	if len(bodyStr) > 500 {
		c.t.Logf("DEBUG: Login form HTML snippet: %s", bodyStr[:500])
	} else {
		c.t.Logf("DEBUG: Login form HTML: %s", bodyStr)
	}

	// Step 2: Submit login with CSRF token
	loginURL := fmt.Sprintf("%s/s/login/post", c.AuthServiceURL)

	// Prepare form data
	formData := url.Values{}
	formData.Set("contact", email)
	formData.Set("password", password)
	formData.Set("login_challenge", loginChallenge)
	if csrfToken != "" {
		formData.Set("gorilla.csrf.Token", csrfToken)
	}

	// Debug logging
	c.t.Logf("DEBUG: Submitting login to: %s", loginURL)
	c.t.Logf("DEBUG: Form data: %s", formData.Encode())

	req, err = http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", loginFormURL) // Use the login form URL as referer for CSRF validation

	resp, err = c.Client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to submit login: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	// Read response body to capture error messages
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response body: %w", err)
	}
	responseBody := string(body)

	result := &LoginResult{
		StatusCode: resp.StatusCode,
		Location:   resp.Header.Get("Location"),
		Success:    false,
	}

	// Check if login was successful (should redirect to consent or back to client)
	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if location != "" {
			parsedURL, err := url.Parse(location)
			if err != nil {
				return result, responseBody, fmt.Errorf("failed to parse redirect URL: %w", err)
			}

			// Check if redirected to consent flow
			if strings.Contains(location, "consent_challenge") {
				result.ConsentChallenge = parsedURL.Query().Get("consent_challenge")
				result.Success = true
			} else if strings.Contains(location, "code=") {
				// Direct redirect to client with authorization code
				result.AuthorizationCode = parsedURL.Query().Get("code")
				result.Success = true
			}
		}
	}

	return result, responseBody, nil
}

// PerformConsent handles the consent flow if required
func (c *OAuth2TestClient) PerformConsent(ctx context.Context, consentChallenge string) (*ConsentResult, error) {
	// Get consent request details
	consentURL := fmt.Sprintf("%s/s/consent?consent_challenge=%s", c.AuthServiceURL, consentChallenge)

	req, err := http.NewRequestWithContext(ctx, "GET", consentURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create consent request: %w", err)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get consent: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	result := &ConsentResult{
		StatusCode: resp.StatusCode,
		Location:   resp.Header.Get("Location"),
		Success:    false,
	}

	// Check if consent was handled (should redirect back to client)
	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if location != "" {
			parsedURL, err := url.Parse(location)
			if err != nil {
				return result, fmt.Errorf("failed to parse redirect URL: %w", err)
			}

			if strings.Contains(location, "code=") {
				result.AuthorizationCode = parsedURL.Query().Get("code")
				result.Success = true
			}
		}
	}

	return result, nil
}

// CompleteOAuth2Flow performs the complete OAuth2 authorization code flow
func (c *OAuth2TestClient) CompleteOAuth2Flow(ctx context.Context, client *OAuth2Client, email, password string) (*OAuth2FlowResult, error) {
	// Step 1: Initiate login flow
	loginChallenge, err := c.InitiateLoginFlow(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate login flow: %w", err)
	}

	// Step 2: Perform login
	loginResult, err := c.PerformLogin(ctx, loginChallenge, email, password)
	if err != nil {
		return nil, fmt.Errorf("failed to perform login: %w", err)
	}

	result := &OAuth2FlowResult{
		LoginChallenge: loginChallenge,
		LoginResult:    loginResult,
	}

	if !loginResult.Success {
		return result, nil
	}

	// Step 3: Handle consent if required
	if loginResult.ConsentChallenge != "" {
		consentResult, err := c.PerformConsent(ctx, loginResult.ConsentChallenge)
		if err != nil {
			return result, fmt.Errorf("failed to perform consent: %w", err)
		}
		result.ConsentResult = consentResult

		if consentResult.Success {
			result.AuthorizationCode = consentResult.AuthorizationCode
		}
	} else if loginResult.AuthorizationCode != "" {
		result.AuthorizationCode = loginResult.AuthorizationCode
	}

	return result, nil
}

// TokenResult represents the result of token exchange
type TokenResult struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ExchangeCodeForToken exchanges an authorization code for an access token
func (c *OAuth2TestClient) ExchangeCodeForToken(ctx context.Context, client *OAuth2Client, authorizationCode string) (*TokenResult, error) {
	// Prepare token exchange request
	tokenURL := fmt.Sprintf("%s/oauth2/token", c.HydraPublicURL)

	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", authorizationCode)
	formData.Set("redirect_uri", client.RedirectURIs[0])
	formData.Set("client_id", client.ClientID)
	formData.Set("client_secret", client.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResult TokenResult
	if err := json.NewDecoder(resp.Body).Decode(&tokenResult); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResult, nil
}

// generateRandomString generates a random string of the specified length
func (c *OAuth2TestClient) generateRandomString(length int) string {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		c.t.Fatalf("failed to generate random string: %v", err)
	}
	return hex.EncodeToString(bytes)[:length]
}

// LoginResult represents the result of a login attempt
type LoginResult struct {
	StatusCode        int
	Location          string
	Success           bool
	ConsentChallenge  string
	AuthorizationCode string
}

// ConsentResult represents the result of a consent flow
type ConsentResult struct {
	StatusCode        int
	Location          string
	Success           bool
	AuthorizationCode string
}

// OAuth2FlowResult represents the complete OAuth2 flow result
type OAuth2FlowResult struct {
	LoginChallenge    string
	LoginResult       *LoginResult
	ConsentResult     *ConsentResult
	AuthorizationCode string
}

// CleanupOAuth2Client deletes the OAuth2 client from Hydra
func (c *OAuth2TestClient) CleanupOAuth2Client(ctx context.Context, clientID string) error {
	configuration := hydraclientgo.NewConfiguration()
	configuration.Servers = hydraclientgo.ServerConfigurations{{URL: c.HydraAdminURL}}
	apiClient := hydraclientgo.NewAPIClient(configuration).OAuth2API

	_, err := apiClient.DeleteOAuth2Client(ctx, clientID).Execute()
	return err
}
