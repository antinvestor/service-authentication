package tests

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

	commonv1 "buf.build/gen/go/antinvestor/common/protocolbuffers/go/common/v1"
	notificationv1 "buf.build/gen/go/antinvestor/notification/protocolbuffers/go/notification/v1"
	"buf.build/gen/go/antinvestor/partition/connectrpc/go/partition/v1/partitionv1connect"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/frametests"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

// OAuth2TestClient provides utilities for testing OAuth2 flows with Hydra
type OAuth2TestClient struct {
	HydraAdminURL  string
	HydraPublicURL string
	AuthServiceURL string
	PartitionCli   partitionv1connect.PartitionServiceClient
	Client         *http.Client
	t              *testing.T

	clientIdList []string
	cookieJar    http.CookieJar // Store reference to cookie jar for clearing

	// Store OAuth2 session context to maintain CSRF state
	currentState        string
	currentNonce        string
	currentCodeVerifier string // For PKCE
}

// NewOAuth2TestClient creates a new OAuth2 test client
func NewOAuth2TestClient(authServer *handlers.AuthServer) *OAuth2TestClient {
	// Get the public Hydra URL from config
	publicURL := authServer.Config().Oauth2ServiceURI

	// Convert public URL (port 4444) to admin URL (port 4445)
	adminURL := authServer.Config().Oauth2ServiceAdminURI

	// Create cookie jar with proper options for test environment
	options := &cookiejar.Options{
		PublicSuffixList: nil, // Use default public suffix list
	}
	jar, _ := cookiejar.New(options)

	client := &OAuth2TestClient{
		HydraAdminURL:  adminURL,
		HydraPublicURL: publicURL,
		AuthServiceURL: "", // Will be set by test server
		PartitionCli:   authServer.PartitionCli(),
		Client: &http.Client{
			Jar:     jar,
			Timeout: 10 * time.Second, // Reduced from 30s to 10s for faster failure detection
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				ctx := req.Context()
				util.Log(ctx).Info("Redirecting to : " + req.URL.String())

				// Don't follow redirects automatically - we want to capture them
				return http.ErrUseLastResponse
			},
		},
		t: nil, // No testing.T required for basic functionality
	}
	client.cookieJar = jar // Store reference to cookie jar for clearing
	return client
}

// ClearSession clears all cookies to ensure fresh session for each test
func (c *OAuth2TestClient) ClearSession() {
	// Create a new cookie jar to replace the old one
	options := &cookiejar.Options{
		PublicSuffixList: nil, // Use default public suffix list
	}
	newJar, _ := cookiejar.New(options)
	c.Client.Jar = newJar
	c.cookieJar = newJar

	// Also clear OAuth2 session state
	c.currentState = ""
	c.currentNonce = ""
}

// OAuth2Client represents an OAuth2 client configuration
type OAuth2Client struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Scope        string
	Audience     []string
	props        data.JSONMap
}

func (c *OAuth2TestClient) PostLoginRedirectHandler() {

}

// CreateOAuth2Client creates a test OAuth2 client in Hydra
func (c *OAuth2TestClient) CreateOAuth2Client(ctx context.Context, testName string) (*OAuth2Client, error) {
	// Use a proper callback URI that won't interfere with OAuth2 endpoints
	redirectURI := c.AuthServiceURL + "/oauth2/callback"

	// Create the client in Hydra
	partition, err := NewPartitionForOauthCli(ctx, c.PartitionCli, testName, "Test OAuth2 client",
		data.JSONMap{
			"scope":         "openid offline offline_access profile contact",
			"audience":      "service_devices,service_profile,service_tenancy,service_files,authentication_tests",
			"logo_uri":      "https://testing.com/logo.png",
			"redirect_uris": redirectURI})
	if err != nil {
		if c.t != nil {
			c.t.Logf("DEBUG: Failed to create partition for OAuth2 client: %v", err)
		}
		return nil, fmt.Errorf("failed to create OAuth2 client: %w", err)
	}

	c.clientIdList = append(c.clientIdList, partition.GetId())

	client := &OAuth2Client{
		ClientID:     partition.GetId(),
		ClientSecret: "",
		RedirectURIs: []string{redirectURI + "?partition_id=" + partition.GetId()},
		Scope:        "openid offline_access profile",
		Audience:     []string{"authentication_tests"},
		props:        partition.GetProperties().AsMap(),
	}

	return client, nil
}

// generateCodeVerifier generates a random code verifier for PKCE
func generateCodeVerifier() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateCodeChallenge generates the SHA256 hash of the code verifier for PKCE
func generateCodeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// InitiateLoginFlow starts an OAuth2 authorization code flow and returns the login challenge
func (c *OAuth2TestClient) InitiateLoginFlow(ctx context.Context, client *OAuth2Client) (string, error) {
	// Build authorization URL
	state := util.RandomAlphaNumericString(16)
	nonce := util.RandomAlphaNumericString(16)

	// Generate PKCE code verifier and challenge
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Store session context for continuity
	c.currentState = state
	c.currentNonce = nonce
	c.currentCodeVerifier = codeVerifier

	params := url.Values{
		"client_id":             {client.ClientID},
		"response_type":         {"code"},
		"scope":                 {client.Scope},
		"audience":              client.Audience,
		"redirect_uri":          {client.RedirectURIs[0]},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	// Use the standard OAuth2 authorization endpoint
	authURL := fmt.Sprintf("%s/oauth2/auth", c.HydraPublicURL)
	fullAuthURL := fmt.Sprintf("%s?%s", authURL, params.Encode())

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

	if c.t != nil {
		// Log current cookies in jar
		if jar, ok := c.Client.Jar.(*cookiejar.Jar); ok {
			if hydraURL, err := url.Parse(c.HydraPublicURL); err == nil {
				cookies := jar.Cookies(hydraURL)
				c.t.Logf("DEBUG: Cookies in jar for %s: %v", c.HydraPublicURL, cookies)
			}
		}
	}

	// Return the redirect URL
	// Hydra should redirect to our auth service with login_challenge parameter
	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if location != "" {
			parsedURL, err0 := url.Parse(location)
			if err0 != nil {
				return "", fmt.Errorf("failed to parse redirect URL: %w", err0)
			}

			knownUrl, err0 := url.Parse(c.AuthServiceURL)
			if err0 != nil {
				return "", fmt.Errorf("failed to parse redirect URL: %w", err0)
			}

			parsedURL.Host = knownUrl.Host

			return parsedURL.String(), nil
		}
	}

	// If we get here, the OAuth2 flow didn't work as expected
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OAuth2 authorization failed with status %d: %s", resp.StatusCode, string(body))
	}

	return "", fmt.Errorf("unexpected response status: %d", resp.StatusCode)
}

// extractLoginEventIDFromHTML extracts the loginEventId from the login page HTML
// It looks for form actions like /s/verify/contact/{loginEventId}/post
func extractLoginEventIDFromHTML(html string) string {
	// Look for the form action pattern: /s/verify/contact/{loginEventId}/post
	re := regexp.MustCompile(`/s/verify/contact/([a-zA-Z0-9_-]+)/post`)
	matches := re.FindStringSubmatch(html)
	if len(matches) >= 2 {
		return matches[1]
	}

	// Also try social login pattern: /s/social/login/{loginEventId}/
	re2 := regexp.MustCompile(`/s/social/login/([a-zA-Z0-9_-]+)/`)
	matches2 := re2.FindStringSubmatch(html)
	if len(matches2) >= 2 {
		return matches2[1]
	}

	return ""
}

// extractLoginEventIDFromPath extracts the loginEventId from a URL path like /s/verify/contact/{loginEventId}
func extractLoginEventIDFromPath(urlPath string) string {
	// Pattern: /s/verify/contact/{loginEventId} or /s/verify/contact/{loginEventId}?...
	re := regexp.MustCompile(`/s/verify/contact/([a-zA-Z0-9_-]+)`)
	matches := re.FindStringSubmatch(urlPath)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// PerformContactVerification submits contact for verification and returns verification details
// nolint:gocyclo,nolintlint //This is a test method no need to overthink
func (c *OAuth2TestClient) PerformContactVerification(ctx context.Context, loginPageURL, contact string) (*ContactVerificationResult, error) {
	// Step 1: First visit the login page to get the loginEventId from the rendered HTML
	req, err := http.NewRequestWithContext(ctx, "GET", loginPageURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create login page request: %w", err)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to visit login page: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	// Read response body to extract loginEventId
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	// Handle both 200 OK and 303 See Other (redirect) as valid responses
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSeeOther {
		return &ContactVerificationResult{
			StatusCode:   resp.StatusCode,
			Success:      false,
			ErrorMessage: bodyStr,
		}, fmt.Errorf("unexpected status visiting login page: %d", resp.StatusCode)
	}

	// If we got a redirect, that's also fine - the session should still be established
	if resp.StatusCode == http.StatusSeeOther {
		if c.t != nil {
			location := resp.Header.Get("Location")
			c.t.Logf("DEBUG: Login page redirected to: %s", location)
		}
	}

	// Extract loginEventId from the login page HTML
	loginEventID := extractLoginEventIDFromHTML(bodyStr)
	if loginEventID == "" {
		if c.t != nil {
			c.t.Logf("DEBUG: Failed to extract loginEventId from login page HTML")
			if len(bodyStr) < 2000 {
				c.t.Logf("DEBUG: HTML body: %s", bodyStr)
			}
		}
		return nil, fmt.Errorf("failed to extract loginEventId from login page")
	}

	if c.t != nil {
		c.t.Logf("DEBUG: Extracted loginEventId from login page: %s", loginEventID)
	}

	// Step 2: Now submit contact for verification using the new URL structure with loginEventId in path
	verificationURL := fmt.Sprintf("%s/s/verify/contact/%s/post", c.AuthServiceURL, loginEventID)

	// Prepare form data - login_challenge is now stored server-side keyed by loginEventId
	formData := url.Values{}
	formData.Set("contact", contact)

	if c.t != nil {
		c.t.Logf("DEBUG: Submitting contact verification to: %s", verificationURL)
		c.t.Logf("DEBUG: Form data: %s", formData.Encode())
		c.t.Logf("DEBUG: login_challenge is stored server-side, keyed by loginEventId: %s", loginEventID)
	}

	verifyReq, err := http.NewRequestWithContext(ctx, "POST", verificationURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create verification request: %w", err)
	}

	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Debug: Show cookies being sent with the request
	if c.t != nil {
		cookies := c.Client.Jar.Cookies(verifyReq.URL)
		c.t.Logf("DEBUG: Cookies being sent to %s: %v", verifyReq.URL.String(), cookies)
		for _, cookie := range cookies {
			c.t.Logf("DEBUG: Cookie: %s=%s (Domain: %s, Path: %s)", cookie.Name, cookie.Value, cookie.Domain, cookie.Path)
		}
	}

	verifyResp, err := c.Client.Do(verifyReq)
	if err != nil {
		return nil, fmt.Errorf("failed to submit contact verification: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, verifyResp.Body)

	// Read response body to capture any messages
	verifyBody, err := io.ReadAll(verifyResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	responseBody := string(verifyBody)

	result := &ContactVerificationResult{
		StatusCode: verifyResp.StatusCode,
		Location:   verifyResp.Header.Get("Location"),
		Success:    false,
	}

	// Check if contact verification was submitted successfully
	switch verifyResp.StatusCode {
	case http.StatusSeeOther, http.StatusFound:
		location := verifyResp.Header.Get("Location")
		if location != "" {
			// Should redirect to verification page: /s/verify/contact/{loginEventId}?profile_name=...
			parsedURL, err := url.Parse(location)
			if err != nil {
				result.ErrorMessage = fmt.Sprintf("failed to parse redirect URL: %v", err)
				return result, fmt.Errorf("failed to parse redirect URL: %w", err)
			}

			// Extract login_event_id from URL path (new structure) or query params (fallback)
			result.LoginEventID = extractLoginEventIDFromPath(parsedURL.Path)
			if result.LoginEventID == "" {
				// Fallback to query param if not in path
				result.LoginEventID = parsedURL.Query().Get("login_event_id")
			}

			if parsedURL.Query().Has("profile_name") {
				result.ProfileName = parsedURL.Query().Get("profile_name")
			}
			result.Location = location
			result.Success = true
			result.VerificationSent = true

			if c.t != nil {
				c.t.Logf("DEBUG: Contact verification submitted successfully")
				c.t.Logf("DEBUG: Redirect location: %s", location)
				c.t.Logf("DEBUG: Login Event ID: %s", result.LoginEventID)
				c.t.Logf("DEBUG: Profile Name: %s", result.ProfileName)
				c.t.Logf("DEBUG: Parsed URL query params: %v", parsedURL.Query())

				// Check if this is actually an error redirect
				if strings.Contains(location, "/error") || parsedURL.Query().Get("error") != "" {
					c.t.Logf("DEBUG: WARNING - This appears to be an error redirect!")
					result.Success = false
					result.ErrorMessage = fmt.Sprintf("Redirected to error page: %s", location)
				}
			}
		}
	case http.StatusOK:
		// Check if the response contains error messages or form
		if strings.Contains(responseBody, "error") || strings.Contains(responseBody, "invalid") {
			result.Success = false
			result.ErrorMessage = "Contact verification failed - check response body"
			if c.t != nil {
				c.t.Logf("DEBUG: Contact verification failed with status 200 but contains errors")
				if len(responseBody) < 500 {
					c.t.Logf("DEBUG: Response body: %s", responseBody)
				}
			}
		} else {
			// Might be showing the verification form directly
			result.Success = true
			result.VerificationSent = true
			if c.t != nil {
				c.t.Logf("DEBUG: Contact verification form displayed (status 200)")
			}
		}
	default:
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("unexpected status code: %d", resp.StatusCode)
		if c.t != nil {
			c.t.Logf("DEBUG: Contact verification failed with status: %d", resp.StatusCode)
			if len(responseBody) < 500 {
				c.t.Logf("DEBUG: Response body: %s", responseBody)
			}
		}
	}

	return result, nil
}

// PerformCodeVerification completes the contact verification with the verification code
// nolint:gocyclo,nolintlint //This is a test method no need to overthink
func (c *OAuth2TestClient) PerformCodeVerification(ctx context.Context, loginEventID, profileName, verificationCode string) (*VerificationCodeResult, error) {
	// Step 1: Get the verification form (new URL structure with loginEventId in path)
	verificationFormURL := fmt.Sprintf("%s/s/verify/contact/%s",
		c.AuthServiceURL, url.PathEscape(loginEventID))
	if profileName != "" {
		verificationFormURL = fmt.Sprintf("%s?profile_name=%s", verificationFormURL, url.QueryEscape(profileName))
	}

	req, err := http.NewRequestWithContext(ctx, "GET", verificationFormURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create verification form request: %w", err)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get verification form: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &VerificationCodeResult{
			StatusCode: resp.StatusCode,
			Success:    false,
		}, fmt.Errorf("unexpected status getting verification form: %d, body: %s", resp.StatusCode, string(body))
	}

	// Step 2: Submit verification code (new URL structure with loginEventId in path)
	verificationURL := fmt.Sprintf("%s/s/verify/contact/%s/post", c.AuthServiceURL, url.PathEscape(loginEventID))

	// Prepare form data for login completion - loginEventId is now in URL path
	formData := url.Values{}
	formData.Set("profile_name", profileName)
	formData.Set("verification_code", verificationCode)

	if c.t != nil {
		c.t.Logf("DEBUG: Submitting verification code to: %s", verificationURL)
		c.t.Logf("DEBUG: Form data: %s", formData.Encode())
	}

	req, err = http.NewRequestWithContext(ctx, "POST", verificationURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create verification request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", verificationFormURL)

	resp, err = c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to submit verification: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	result := &VerificationCodeResult{
		StatusCode: resp.StatusCode,
		Location:   resp.Header.Get("Location"),
		Success:    false,
	}

	// Check if verification was successful (should redirect to OAuth2 flow)
	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if location != "" {
			// The verification should redirect back to Hydra's OAuth2 server
			if c.t != nil {
				c.t.Logf("DEBUG: Verification POST redirected to: %s", location)
			}

			// Parse both URLs to compare them properly (handle localhost vs 127.0.0.1)
			hydraURL, err := url.Parse(c.HydraPublicURL)
			if err != nil {
				return result, fmt.Errorf("failed to parse Hydra public URL: %w", err)
			}

			redirectURL, err := url.Parse(location)
			if err != nil {
				return result, fmt.Errorf("failed to parse redirect URL: %w", err)
			}

			// Check if redirected back to verification page (indicates failure)
			if strings.Contains(location, "/s/verify/contact") {
				errorMsg := redirectURL.Query().Get("error")
				if errorMsg != "" {
					if c.t != nil {
						c.t.Logf("DEBUG: Verification failed, redirected back to verification page with error: %s", errorMsg)
					}
					result.Success = false
					result.Location = location
					return result, fmt.Errorf("verification failed: %s", errorMsg)
				}
			}

			// Check if redirect is to Hydra by comparing host and port
			isHydraRedirect := (redirectURL.Port() == hydraURL.Port()) &&
				(redirectURL.Hostname() == hydraURL.Hostname() ||
					(redirectURL.Hostname() == "127.0.0.1" && hydraURL.Hostname() == "localhost") ||
					(redirectURL.Hostname() == "localhost" && hydraURL.Hostname() == "127.0.0.1"))

			if c.t != nil {
				c.t.Logf("DEBUG: Is Hydra redirect: %v", isHydraRedirect)
			}

			if isHydraRedirect {
				// Follow the redirect to complete the OAuth2 flow
				// Normalise the redirect URL to use the same hostname as HydraPublicURL
				normalizedLocation := location
				if redirectURL.Hostname() != hydraURL.Hostname() {
					redirectURL.Host = hydraURL.Host
					normalizedLocation = redirectURL.String()
					if c.t != nil {
						c.t.Logf("DEBUG: Normalised redirect URL from %s to %s", location, normalizedLocation)
					}
				}

				redirectReq, err := http.NewRequestWithContext(ctx, "GET", normalizedLocation, nil)
				if err != nil {
					return result, fmt.Errorf("failed to create redirect request: %w", err)
				}

				redirectResp, err := c.Client.Do(redirectReq)
				if err != nil {
					return result, fmt.Errorf("failed to follow redirect: %w", err)
				}
				defer util.CloseAndLogOnError(ctx, redirectResp.Body)

				if c.t != nil {
					c.t.Logf("DEBUG: Redirect response status: %d", redirectResp.StatusCode)
					c.t.Logf("DEBUG: Redirect response location: %s", redirectResp.Header.Get("Location"))
				}

				// Check if Hydra redirects to consent or directly to client
				if redirectResp.StatusCode == http.StatusSeeOther || redirectResp.StatusCode == http.StatusFound {
					finalLocation := redirectResp.Header.Get("Location")
					if finalLocation != "" {
						finalParsedURL, err := url.Parse(finalLocation)
						if err != nil {
							return result, fmt.Errorf("failed to parse final redirect URL: %w", err)
						}

						// Check if redirected to consent flow
						if strings.Contains(finalLocation, "consent_challenge") {
							result.ConsentChallenge = finalParsedURL.Query().Get("consent_challenge")
							result.Success = true
							result.Location = finalLocation
							if c.t != nil {
								c.t.Logf("DEBUG: Received consent challenge: %s", result.ConsentChallenge)
							}
						} else if strings.Contains(finalLocation, "code=") {
							// Direct redirect to client with authorization code
							result.AuthorizationCode = finalParsedURL.Query().Get("code")
							result.Success = true
							result.Location = finalLocation
							if c.t != nil {
								c.t.Logf("DEBUG: Received authorization code: %s", result.AuthorizationCode[:min(10, len(result.AuthorizationCode))]+"...")
							}
						} else if strings.Contains(finalLocation, "error=") {
							// Handle OAuth2 errors
							errorCode := finalParsedURL.Query().Get("error")
							errorDesc := finalParsedURL.Query().Get("error_description")
							if c.t != nil {
								c.t.Logf("DEBUG: OAuth2 error - %s: %s", errorCode, errorDesc)
							}
							result.Success = false
							result.Location = finalLocation
							return result, fmt.Errorf("OAuth2 error: %s - %s", errorCode, errorDesc)
						}
					}
				}
			} else {
				result.Location = location
				// Direct redirect to client (skip consent)
				if strings.Contains(location, "consent_challenge") {
					consentURL, err := url.Parse(location)
					if err == nil {
						result.ConsentChallenge = consentURL.Query().Get("consent_challenge")
						result.Success = true

					}
				} else if strings.Contains(location, "code=") {
					codeURL, err := url.Parse(location)
					if err == nil {
						result.AuthorizationCode = codeURL.Query().Get("code")
						result.Success = true
					}
				}
			}

			result.Location = location
		}
	} else {
		// Handle error cases
		body, _ := io.ReadAll(resp.Body)
		if c.t != nil {
			c.t.Logf("DEBUG: Verification failed with status: %d, body: %s", resp.StatusCode, string(body))
		}
		return result, fmt.Errorf("verification failed with status: %d", resp.StatusCode)
	}

	return result, nil
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

	// Check if consent was handled (should redirect back to OAuth2 server)
	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if c.t != nil {
			c.t.Logf("DEBUG: Consent redirect status: %d, location: %s", resp.StatusCode, location)
		}

		if location != "" {
			// Follow the redirect to the OAuth2 server to complete the flow
			// This allows the OAuth2 server to handle the authorization code generation
			redirectReq, err := http.NewRequestWithContext(ctx, "GET", location, nil)
			if err != nil {
				return result, fmt.Errorf("failed to create redirect request: %w", err)
			}

			// Use the original client to preserve the exact same session context
			// The client's CheckRedirect is set to return http.ErrUseLastResponse
			// which means it will capture the redirect without following it
			redirectResp, err := c.Client.Do(redirectReq)
			if err != nil {
				return result, fmt.Errorf("failed to follow consent redirect: %w", err)
			}
			defer func() {
				if err := redirectResp.Body.Close(); err != nil {
					if c.t != nil {
						c.t.Logf("DEBUG: Failed to close response body: %v", err)
					}
				}
			}()

			if c.t != nil {
				c.t.Logf("DEBUG: Redirect response status: %d", redirectResp.StatusCode)
				c.t.Logf("DEBUG: Redirect response location: %s", redirectResp.Header.Get("Location"))
				c.t.Logf("DEBUG: Redirect response headers: %v", redirectResp.Header)
				c.t.Logf("DEBUG: Redirect response cookies: %v", redirectResp.Cookies())
			}

			// Check if Hydra redirects to consent or directly to client
			if redirectResp.StatusCode == http.StatusSeeOther || redirectResp.StatusCode == http.StatusFound {
				finalLocation := redirectResp.Header.Get("Location")
				if c.t != nil {
					c.t.Logf("DEBUG: OAuth2 server redirect status: %d, location: %s", redirectResp.StatusCode, finalLocation)
				}

				if finalLocation != "" && strings.Contains(finalLocation, "code=") {
					parsedURL, err := url.Parse(finalLocation)
					if err != nil {
						return result, fmt.Errorf("failed to parse final redirect URL: %w", err)
					}

					result.AuthorizationCode = parsedURL.Query().Get("code")
					result.Success = true
					if c.t != nil {
						c.t.Logf("DEBUG: Extracted authorization code from OAuth2 server redirect: %s", result.AuthorizationCode[:min(10, len(result.AuthorizationCode))]+"...")
					}
				}
			}
		}
	} else {
		if c.t != nil {
			c.t.Logf("DEBUG: Consent response status: %d (expected redirect)", resp.StatusCode)
		}
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
	formData.Set("code_verifier", c.currentCodeVerifier)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// Note: Using client_secret_post method (credentials in form body) instead of client_secret_basic (Authorization header)

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

// VerificationCodeResult represents the result of a login attempt
type VerificationCodeResult struct {
	StatusCode        int
	Location          string
	Success           bool
	ConsentChallenge  string
	AuthorizationCode string
}

// ContactVerificationResult represents the result of contact verification submission
type ContactVerificationResult struct {
	StatusCode       int
	Location         string
	Success          bool
	LoginEventID     string
	ProfileName      string
	VerificationSent bool
	ErrorMessage     string
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
	LoginResult       *VerificationCodeResult
	ConsentResult     *ConsentResult
	AuthorizationCode string
}

// CleanupOAuth2Client deletes the OAuth2 client from Hydra
func (c *OAuth2TestClient) CleanupOAuth2Client(ctx context.Context, clientID string) error {
	if clientID == "" {
		return nil
	}

	deleteURL := fmt.Sprintf("%s/admin/clients/%s", c.HydraAdminURL, clientID)
	req, err := http.NewRequestWithContext(ctx, "DELETE", deleteURL, nil)
	if err != nil {
		return err
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	return nil
}

// GetVerificationCodeByLoginEventID retrieves the actual verification code from the database
func (c *OAuth2TestClient) GetVerificationCodeByLoginEventID(ctx context.Context, authServer *handlers.AuthServer, LoginEventID string) (string, error) {

	loginEventRepo := authServer.LoginEventRepo()
	loginEvt, err := loginEventRepo.GetByID(ctx, LoginEventID)
	if err != nil {
		return "", err
	}

	notifCli := authServer.NotificationCli()

	notif, err := frametests.WaitForConditionWithResult[notificationv1.Notification](ctx, func() (*notificationv1.Notification, error) {

		extras, _ := structpb.NewStruct(map[string]any{"template_id": "9bsv0s23l8og00vgjq90"})

		resp, err0 := notifCli.Search(ctx, connect.NewRequest(&commonv1.SearchRequest{
			Cursor: &commonv1.PageCursor{
				Limit: 10,
				Page:  "",
			},
			Extras: extras,
		}))
		if err0 != nil {
			return nil, err0
		}

		for resp.Receive() {
			err1 := resp.Err()
			if err1 != nil {
				return nil, err1
			}

			nmsg := resp.Msg()
			for _, n := range nmsg.GetData() {
				if n.GetPayload().AsMap()["verification_id"].(string) == loginEvt.VerificationID {
					return n, nil
				}
			}
		}

		return nil, nil
	}, 5*time.Second, 300*time.Millisecond)

	if err != nil {
		return "", err
	}

	return notif.GetPayload().AsMap()["code"].(string), nil
}

// Cleanup performs general cleanup of OAuth2 test client resources
func (c *OAuth2TestClient) Cleanup(ctx context.Context) {
	// General cleanup - specific client cleanup should be done via CleanupOAuth2Client
	for _, clientID := range c.clientIdList {
		_ = c.CleanupOAuth2Client(ctx, clientID)
	}

}

// SetAuthServiceURL sets the authentication service URL for testing
func (c *OAuth2TestClient) SetAuthServiceURL(url string) {
	c.AuthServiceURL = url
}

// SetTestingT sets the testing.T reference for debug logging
func (c *OAuth2TestClient) SetTestingT(t *testing.T) {
	c.t = t
}
