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

	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/pitabwire/util"
)

// OAuth2TestClient provides utilities for testing OAuth2 flows with Hydra
type OAuth2TestClient struct {
	HydraAdminURL  string
	HydraPublicURL string
	AuthServiceURL string
	PartitionCli   *partitionv1.PartitionClient
	Client         *http.Client
	t              *testing.T

	clientIdList []string

	// Store OAuth2 session context to maintain CSRF state
	currentState string
	currentNonce string
}

// NewOAuth2TestClient creates a new OAuth2 test client
func NewOAuth2TestClient(authServer *handlers.AuthServer) *OAuth2TestClient {
	// Get the public Hydra URL from config
	publicURL := authServer.Config().Oauth2ServiceURI

	// Convert public URL (port 4444) to admin URL (port 4445)
	adminURL := authServer.Config().Oauth2ServiceAdminURI

	jar, _ := cookiejar.New(nil)

	return &OAuth2TestClient{
		HydraAdminURL:  adminURL,
		HydraPublicURL: publicURL,
		AuthServiceURL: "", // Will be set by test server
		PartitionCli:   authServer.PartitionCli(),
		Client: &http.Client{
			Jar:     jar,
			Timeout: 10 * time.Second, // Reduced from 30s to 10s for faster failure detection
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				ctx := req.Context()
				util.Log(ctx).Info("Redirecting to : %s" + req.URL.String())

				// Don't follow redirects automatically - we want to capture them
				return http.ErrUseLastResponse
			},
		},
		t: nil, // No testing.T required for basic functionality
	}
}

// OAuth2Client represents an OAuth2 client configuration
type OAuth2Client struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Scope        string
}


func (c *OAuth2TestClient) PostLoginRedirectHandler() {
	
}

// CreateOAuth2Client creates a test OAuth2 client in Hydra
func (c *OAuth2TestClient) CreateOAuth2Client(ctx context.Context, testName string) (*OAuth2Client, error) {
	// Use a proper callback URI that won't interfere with OAuth2 endpoints
	redirectURI := c.AuthServiceURL + "/oauth2/callback"

	// Create the client in Hydra
	partition, err := NewPartForOauthCli(ctx, c.PartitionCli, testName, "Test OAuth2 client",
		map[string]string{
			"scope":         "openid offline offline_access profile contact",
			"audience":      "service_matrix,service_profile,service_partition,service_files",
			"logo_uri":      "https://testing.com/logo.png",
			"redirect_uris": redirectURI})
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth2 client: %w", err)
	}

	c.clientIdList = append(c.clientIdList, partition.GetId())

	return &OAuth2Client{
		ClientID:     partition.GetId(),
		ClientSecret: "",
		RedirectURIs: []string{redirectURI + "?partition_id=" + partition.GetId()},
		Scope:        "openid profile offline_access contact",
	}, nil
}

// InitiateLoginFlow starts an OAuth2 authorization code flow and returns the login challenge
func (c *OAuth2TestClient) InitiateLoginFlow(ctx context.Context, client *OAuth2Client) (string, error) {
	// Build authorization URL
	state := c.generateRandomString(16)
	nonce := c.generateRandomString(16)

	// Store session context for CSRF continuity
	c.currentState = state
	c.currentNonce = nonce

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

	if c.t != nil {
		c.t.Logf("DEBUG: HydraPublicURL: %s", c.HydraPublicURL)
		c.t.Logf("DEBUG: Full auth URL: %s", fullAuthURL)
		c.t.Logf("DEBUG: Storing OAuth2 session - state: %s, nonce: %s", state, nonce)
	}

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
		c.t.Logf("DEBUG: Response status: %d", resp.StatusCode)
		c.t.Logf("DEBUG: Response cookies: %v", resp.Cookies())

		// Log current cookies in jar
		if jar, ok := c.Client.Jar.(*cookiejar.Jar); ok {
			if hydraURL, err := url.Parse(c.HydraPublicURL); err == nil {
				cookies := jar.Cookies(hydraURL)
				c.t.Logf("DEBUG: Cookies in jar for %s: %v", c.HydraPublicURL, cookies)
			}
		}
	}

	// Extract login challenge from the redirect URL
	// Hydra should redirect to our auth service with login_challenge parameter
	if resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if c.t != nil {
			c.t.Logf("DEBUG: Redirect location: %s", location)
		}
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
			// The login POST should redirect back to Hydra's OAuth2 server
			// Instead of manually following redirects, let's validate the redirect URL
			// and extract the necessary information without breaking CSRF session
			if c.t != nil {
				c.t.Logf("DEBUG: Login POST redirected to: %s", location)
			}

			// Parse the redirect URL to understand what Hydra wants us to do
			parsedURL, err := url.Parse(location)
			if err != nil {
				return result, fmt.Errorf("failed to parse redirect URL: %w", err)
			}

			// Check if this is a redirect back to Hydra for consent or authorization
			if c.t != nil {
				c.t.Logf("DEBUG: Checking if redirect is to Hydra - HydraPublicURL: %s", c.HydraPublicURL)
				c.t.Logf("DEBUG: Redirect location: %s", location)
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

			// Check if redirect is to Hydra by comparing host and port
			isHydraRedirect := (redirectURL.Port() == hydraURL.Port()) &&
				(redirectURL.Hostname() == hydraURL.Hostname() ||
					(redirectURL.Hostname() == "127.0.0.1" && hydraURL.Hostname() == "localhost") ||
					(redirectURL.Hostname() == "localhost" && hydraURL.Hostname() == "127.0.0.1"))

			if c.t != nil {
				c.t.Logf("DEBUG: Hydra host:port = %s:%s, Redirect host:port = %s:%s",
					hydraURL.Hostname(), hydraURL.Port(), redirectURL.Hostname(), redirectURL.Port())
				c.t.Logf("DEBUG: Is Hydra redirect: %v", isHydraRedirect)
			}

			if isHydraRedirect {
				if c.t != nil {
					c.t.Logf("DEBUG: Redirect is back to Hydra OAuth2 server")
					c.t.Logf("DEBUG: Following redirect to complete OAuth2 flow: %s", location)
				}

				// This means the login was successful and Hydra is continuing the OAuth2 flow
				// We should follow this redirect with the same HTTP client to maintain session

				// IMPORTANT: Normalize the redirect URL to use the same hostname as HydraPublicURL
				// to ensure cookies are preserved (localhost vs 127.0.0.1 mismatch)
				normalizedLocation := location
				if redirectURL.Hostname() != hydraURL.Hostname() {
					// Replace the hostname in the redirect URL with the hostname from HydraPublicURL
					redirectURL.Host = hydraURL.Host
					normalizedLocation = redirectURL.String()
					if c.t != nil {
						c.t.Logf("DEBUG: Normalized redirect URL from %s to %s for cookie preservation", location, normalizedLocation)
					}
				}

				redirectReq, err := http.NewRequestWithContext(ctx, "GET", normalizedLocation, nil)
				if err != nil {
					if c.t != nil {
						c.t.Logf("DEBUG: Failed to follow redirect: %v", err)
					}
					return result, fmt.Errorf("failed to create redirect request: %w", err)
				}

				// Log cookies being sent with redirect request
				if c.t != nil {
					if jar, ok := c.Client.Jar.(*cookiejar.Jar); ok {
						if normalizedURL, err := url.Parse(normalizedLocation); err == nil {
							cookies := jar.Cookies(normalizedURL)
							c.t.Logf("DEBUG: Cookies being sent with redirect request to %s: %v", normalizedLocation, cookies)
						}
					}
				}

				redirectResp, err := c.Client.Do(redirectReq)
				if err != nil {
					if c.t != nil {
						c.t.Logf("DEBUG: Failed to follow redirect: %v", err)
					}
					return result, fmt.Errorf("failed to follow redirect: %w", err)
				}
				defer util.CloseAndLogOnError(ctx, redirectResp.Body)

				if c.t != nil {
					c.t.Logf("DEBUG: Redirect response status: %d", redirectResp.StatusCode)
					c.t.Logf("DEBUG: Redirect response location: %s", redirectResp.Header.Get("Location"))
					c.t.Logf("DEBUG: Redirect response headers: %v", redirectResp.Header)
					c.t.Logf("DEBUG: Redirect response cookies: %v", redirectResp.Cookies())
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
							// Handle OAuth2 errors (like CSRF issues)
							errorCode := finalParsedURL.Query().Get("error")
							errorDesc := finalParsedURL.Query().Get("error_description")
							if c.t != nil {
								c.t.Logf("DEBUG: OAuth2 error - %s: %s", errorCode, errorDesc)
							}
							result.Success = false
							result.Location = finalLocation
							return result, fmt.Errorf("OAuth2 error: %s - %s", errorCode, errorDesc)
						} else {
							// Unknown redirect, might need to follow further
							if c.t != nil {
								c.t.Logf("DEBUG: Unknown redirect location: %s", finalLocation)
							}
							result.Success = false
							result.Location = finalLocation
							return result, fmt.Errorf("unexpected redirect location: %s", finalLocation)
						}
					}
				} else {
					// If no further redirect, check the response body for consent form or other content
					if c.t != nil {
						c.t.Logf("DEBUG: No further redirect from Hydra, status: %d", redirectResp.StatusCode)
					}

					// Read response body to check for consent form or error
					body, err := io.ReadAll(redirectResp.Body)
					if err != nil {
						return result, fmt.Errorf("failed to read redirect response body: %w", err)
					}

					if c.t != nil {
						c.t.Logf("DEBUG: Redirect response body length: %d", len(body))
						if len(body) > 0 && len(body) < 1000 {
							c.t.Logf("DEBUG: Redirect response body: %s", string(body))
						}
					}

					// Check if this is a consent form by looking for consent_challenge in the body
					bodyStr := string(body)
					if strings.Contains(bodyStr, "consent_challenge") {
						// Extract consent challenge from the form or URL
						if strings.Contains(location, "consent_challenge") {
							parsedURL, err := url.Parse(location)
							if err == nil {
								result.ConsentChallenge = parsedURL.Query().Get("consent_challenge")
								result.Success = true
								result.Location = location
								if c.t != nil {
									c.t.Logf("DEBUG: Extracted consent challenge from original location: %s", result.ConsentChallenge)
								}
							}
						}
					} else {
						result.Success = false
						result.Location = location
						return result, fmt.Errorf("unexpected response from Hydra: status %d", redirectResp.StatusCode)
					}
				}
			} else {
				// Direct redirect to client (skip consent)
				if strings.Contains(location, "consent_challenge") {
					result.ConsentChallenge = parsedURL.Query().Get("consent_challenge")
					result.Success = true
					result.Location = location
				} else if strings.Contains(location, "code=") {
					result.AuthorizationCode = parsedURL.Query().Get("code")
					result.Success = true
					result.Location = location
				}
			}

			result.Location = location
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
	if c.t != nil {
		c.t.Logf("DEBUG: CSRF token extracted: %s (length: %d)", csrfToken, len(csrfToken))
		c.t.Logf("DEBUG: Form contains CSRF field: %v", strings.Contains(bodyStr, `name="gorilla.csrf.Token"`))
		if len(bodyStr) > 500 {
			c.t.Logf("DEBUG: Login form HTML snippet: %s", bodyStr[:500])
		} else {
			c.t.Logf("DEBUG: Login form HTML: %s", bodyStr)
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

	if c.t != nil {
		c.t.Logf("DEBUG: Submitting login to: %s", loginURL)
		c.t.Logf("DEBUG: Form data: %s", formData.Encode())
	}

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
			// The login POST should redirect back to Hydra's OAuth2 server
			// Instead of manually following redirects, let's validate the redirect URL
			// and extract the necessary information without breaking CSRF session
			if c.t != nil {
				c.t.Logf("DEBUG: Login POST redirected to: %s", location)
			}

			// Parse the redirect URL to understand what Hydra wants us to do
			parsedURL, err := url.Parse(location)
			if err != nil {
				return result, responseBody, fmt.Errorf("failed to parse redirect URL: %w", err)
			}

			// Check if this is a redirect back to Hydra for consent or authorization
			if c.t != nil {
				c.t.Logf("DEBUG: Checking if redirect is to Hydra - HydraPublicURL: %s", c.HydraPublicURL)
				c.t.Logf("DEBUG: Redirect location: %s", location)
			}

			// Parse both URLs to compare them properly (handle localhost vs 127.0.0.1)
			hydraURL, err := url.Parse(c.HydraPublicURL)
			if err != nil {
				return result, responseBody, fmt.Errorf("failed to parse Hydra public URL: %w", err)
			}

			redirectURL, err := url.Parse(location)
			if err != nil {
				return result, responseBody, fmt.Errorf("failed to parse redirect URL: %w", err)
			}

			// Check if redirect is to Hydra by comparing host and port
			isHydraRedirect := (redirectURL.Port() == hydraURL.Port()) &&
				(redirectURL.Hostname() == hydraURL.Hostname() ||
					(redirectURL.Hostname() == "127.0.0.1" && hydraURL.Hostname() == "localhost") ||
					(redirectURL.Hostname() == "localhost" && hydraURL.Hostname() == "127.0.0.1"))

			if c.t != nil {
				c.t.Logf("DEBUG: Hydra host:port = %s:%s, Redirect host:port = %s:%s",
					hydraURL.Hostname(), hydraURL.Port(), redirectURL.Hostname(), redirectURL.Port())
				c.t.Logf("DEBUG: Is Hydra redirect: %v", isHydraRedirect)
			}

			if isHydraRedirect {
				if c.t != nil {
					c.t.Logf("DEBUG: Redirect is back to Hydra OAuth2 server")
					c.t.Logf("DEBUG: Following redirect to complete OAuth2 flow: %s", location)
				}

				// This means the login was successful and Hydra is continuing the OAuth2 flow
				// We should follow this redirect with the same HTTP client to maintain session

				// IMPORTANT: Normalize the redirect URL to use the same hostname as HydraPublicURL
				// to ensure cookies are preserved (localhost vs 127.0.0.1 mismatch)
				normalizedLocation := location
				if redirectURL.Hostname() != hydraURL.Hostname() {
					// Replace the hostname in the redirect URL with the hostname from HydraPublicURL
					redirectURL.Host = hydraURL.Host
					normalizedLocation = redirectURL.String()
					if c.t != nil {
						c.t.Logf("DEBUG: Normalized redirect URL from %s to %s for cookie preservation", location, normalizedLocation)
					}
				}

				redirectReq, err := http.NewRequestWithContext(ctx, "GET", normalizedLocation, nil)
				if err != nil {
					return result, responseBody, fmt.Errorf("failed to create redirect request: %w", err)
				}

				// Log cookies being sent with redirect request
				if c.t != nil {
					if jar, ok := c.Client.Jar.(*cookiejar.Jar); ok {
						if normalizedURL, err := url.Parse(normalizedLocation); err == nil {
							cookies := jar.Cookies(normalizedURL)
							c.t.Logf("DEBUG: Cookies being sent with redirect request to %s: %v", normalizedLocation, cookies)
						}
					}
				}

				redirectResp, err := c.Client.Do(redirectReq)
				if err != nil {
					if c.t != nil {
						c.t.Logf("DEBUG: Failed to follow redirect: %v", err)
					}
					return result, responseBody, fmt.Errorf("failed to follow redirect: %w", err)
				}
				defer util.CloseAndLogOnError(ctx, redirectResp.Body)

				if c.t != nil {
					c.t.Logf("DEBUG: Redirect response status: %d", redirectResp.StatusCode)
					c.t.Logf("DEBUG: Redirect response location: %s", redirectResp.Header.Get("Location"))
					c.t.Logf("DEBUG: Redirect response headers: %v", redirectResp.Header)
					c.t.Logf("DEBUG: Redirect response cookies: %v", redirectResp.Cookies())
				}

				// Check if Hydra redirects to consent or directly to client
				if redirectResp.StatusCode == http.StatusSeeOther || redirectResp.StatusCode == http.StatusFound {
					finalLocation := redirectResp.Header.Get("Location")
					if finalLocation != "" {
						finalParsedURL, err := url.Parse(finalLocation)
						if err != nil {
							return result, responseBody, fmt.Errorf("failed to parse final redirect URL: %w", err)
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
							// Handle OAuth2 errors (like CSRF issues)
							errorCode := finalParsedURL.Query().Get("error")
							errorDesc := finalParsedURL.Query().Get("error_description")
							if c.t != nil {
								c.t.Logf("DEBUG: OAuth2 error - %s: %s", errorCode, errorDesc)
							}
							result.Success = false
							result.Location = finalLocation
							return result, responseBody, fmt.Errorf("OAuth2 error: %s - %s", errorCode, errorDesc)
						} else {
							// Unknown redirect, might need to follow further
							if c.t != nil {
								c.t.Logf("DEBUG: Unknown redirect location: %s", finalLocation)
							}
							result.Success = false
							result.Location = finalLocation
							return result, responseBody, fmt.Errorf("unexpected redirect location: %s", finalLocation)
						}
					}
				} else {
					// If no further redirect, check the response body for consent form or other content
					if c.t != nil {
						c.t.Logf("DEBUG: No further redirect from Hydra, status: %d", redirectResp.StatusCode)
					}

					// Read response body to check for consent form or error
					body, err := io.ReadAll(redirectResp.Body)
					if err != nil {
						return result, responseBody, fmt.Errorf("failed to read redirect response body: %w", err)
					}

					if c.t != nil {
						c.t.Logf("DEBUG: Redirect response body length: %d", len(body))
						if len(body) > 0 && len(body) < 1000 {
							c.t.Logf("DEBUG: Redirect response body: %s", string(body))
						}
					}

					// Check if this is a consent form by looking for consent_challenge in the body
					bodyStr := string(body)
					if strings.Contains(bodyStr, "consent_challenge") {
						// Extract consent challenge from the form or URL
						if strings.Contains(location, "consent_challenge") {
							parsedURL, err := url.Parse(location)
							if err == nil {
								result.ConsentChallenge = parsedURL.Query().Get("consent_challenge")
								result.Success = true
								result.Location = location
								if c.t != nil {
									c.t.Logf("DEBUG: Extracted consent challenge from original location: %s", result.ConsentChallenge)
								}
							}
						}
					} else {
						result.Success = false
						result.Location = location
						return result, responseBody, fmt.Errorf("unexpected response from Hydra: status %d", redirectResp.StatusCode)
					}
				}
			} else {
				// Direct redirect to client (skip consent)
				if strings.Contains(location, "consent_challenge") {
					result.ConsentChallenge = parsedURL.Query().Get("consent_challenge")
					result.Success = true
					result.Location = location
				} else if strings.Contains(location, "code=") {
					result.AuthorizationCode = parsedURL.Query().Get("code")
					result.Success = true
					result.Location = location
				}
			}

			result.Location = location
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
			defer redirectResp.Body.Close()

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
