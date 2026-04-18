// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fedcm_test contains end-to-end integration tests for the FedCM
// Identity Provider endpoints. The happy-path test performs the full flow:
//
//  1. Cold-start sign-in via /s/fedcm/login + /s/fedcm/verify/{id}
//     → idp_session cookie is written.
//  2. GET /fedcm/accounts (Sec-Fetch-Dest: webidentity) returns the signed-in account.
//  3. POST /fedcm/id-assertion → {"token": "<id_token>"}.
//  4. POST /fedcm/token-exchange → {"access_token": ..., "refresh_token": ..., "token_type": "Bearer"}.
//  5. JWT claims on the id_token carry profile_id, tenant_id, partition_id, acr="fedcm".
//  6. Token-exchange replay of the same id_token fails with 401.
package fedcm_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/tests"
	internaltests "github.com/antinvestor/service-authentication/pkg/tests"
	"github.com/pitabwire/frame/frametests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testpostgres"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

// FedCMFlowSuite runs the full end-to-end FedCM IdP happy-path flow.
type FedCMFlowSuite struct {
	tests.BaseTestSuite
}

func TestFedCMFlow(t *testing.T) { suite.Run(t, new(FedCMFlowSuite)) }

// SetupSuite overrides the base to inject FedCM-specific config (public origin)
// before the auth server is constructed, so the headless driver knows its
// callback URL and so Hydra can validate the redirect URI.
func (s *FedCMFlowSuite) SetupSuite() {
	s.InitResourceFunc = func(ctx context.Context) []definition.TestResource {
		freePort, _ := frametests.GetFreePort(ctx)
		s.FreeAuthPort = strconv.Itoa(freePort)
		authURL := fmt.Sprintf("http://127.0.0.1:%s", s.FreeAuthPort)

		// Tell the auth server what its own origin is so the FedCM headless driver
		// builds the correct InternalCallbackURL = authURL + "/_internal/fedcm-callback".
		// config.LoadWithOIDC reads this after resources are initialised.
		os.Setenv("FEDCM_PUBLIC_ORIGIN", authURL) //nolint:errcheck // best effort in setup

		return s.initFedCMResources(ctx, authURL, freePort)
	}
	s.BaseTestSuite.SetupSuite()
}

// TearDownSuite cleans up the FedCM env var set in SetupSuite.
func (s *FedCMFlowSuite) TearDownSuite() {
	os.Unsetenv("FEDCM_PUBLIC_ORIGIN") //nolint:errcheck
	s.BaseTestSuite.TearDownSuite()
}

// initFedCMResources mirrors tests.initResources but also accepts a custom
// Hydra config that adds /_internal/fedcm-callback as an allowed redirect URI
// (Hydra does this per-client, not globally; we register it when we create the
// OAuth2 client in the test itself). No Hydra-level change is needed here.
func (s *FedCMFlowSuite) initFedCMResources(_ context.Context, loginURL string, authPort int) []definition.TestResource {
	pg := testpostgres.NewWithOpts("service_authentication",
		definition.WithUserName("ant"), definition.WithCredential("s3cr3t"),
		definition.WithEnableLogging(false), definition.WithUseHostMode(false))

	dockerLoginURL := strings.Replace(loginURL, "127.0.0.1", testcontainers.HostInternal, 1)
	localHydraConfig := strings.Replace(internaltests.HydraConfiguration, "http://127.0.0.1:3000/", dockerLoginURL+"/s/", 3)
	localHydraConfig = strings.Replace(localHydraConfig, "http://127.0.0.1:3000/", dockerLoginURL+"/", 2)
	// Hydra validates redirect_uri per-client (registered when the OAuth2 client is
	// created in the test). No global Hydra config change is needed here.
	hydra := internaltests.NewHydra(
		localHydraConfig, []int{authPort}, definition.WithDependancies(pg),
		definition.WithEnableLogging(false))

	partitionSvc := internaltests.NewPartitionSvc(
		definition.WithDependancies(pg, hydra),
		definition.WithEnableLogging(false),
		definition.WithUseHostMode(true),
	)
	notificationsSvc := internaltests.NewNotificationSvc(
		definition.WithDependancies(pg, hydra),
		definition.WithEnableLogging(false),
		definition.WithUseHostMode(true),
	)
	profileSvc := internaltests.NewProfile(
		definition.WithDependancies(pg, hydra, notificationsSvc),
		definition.WithEnableLogging(false),
		definition.WithUseHostMode(true),
	)
	deviceSvc := internaltests.NewDevice(
		definition.WithDependancies(pg, hydra),
		definition.WithEnableLogging(false),
		definition.WithUseHostMode(true),
	)

	return []definition.TestResource{pg, hydra, partitionSvc, notificationsSvc, profileSvc, deviceSvc}
}

func (s *FedCMFlowSuite) baseURL() string {
	return "http://127.0.0.1:" + s.FreeAuthPort
}

// TestColdStartThenIDAssertion is the FedCM happy-path test:
//  1. Cold-start sign-in via POST /s/fedcm/login + POST /s/fedcm/verify/{id}
//  2. GET /fedcm/accounts with Sec-Fetch-Dest: webidentity
//  3. POST /fedcm/id-assertion → {"token": "<id_token>"}
//  4. POST /fedcm/token-exchange → access+refresh tokens
//  5. JWT claims verification (profile_id, tenant_id, partition_id)
//  6. Replay of the same id_token returns 401
//
// NOTE: This test uses the shared handler created in SetupSuite (accessible
// via s.Handler()) so that HTTP requests hitting the shared server and DB
// queries to retrieve login events both use the same database schema.
func (s *FedCMFlowSuite) TestColdStartThenIDAssertion() {
	const testContact = "fedcmtest@example.com"

	t := s.T()
	testCtx, testCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer testCancel()

	// Use the shared handler (Service A, created in SetupSuite) for DB queries.
	// The shared HTTP server (also Service A) listens on s.baseURL().
	authServer := s.Handler()
	require.NotNil(t, authServer, "shared auth server must be initialised by SetupSuite")

	// Reset rate limits so test IPs are not blocked.
	authServer.ResetLoginRateLimit(testCtx, "127.0.0.1")
	authServer.ResetLoginRateLimit(testCtx, "::1")

	// ------------------------------------------------------------------
	// Step 0: create an OAuth2 client (partition) whose redirect URIs
	// include the FedCM internal callback. The headless driver will use
	// this client to drive the headless authorization_code flow.
	// ------------------------------------------------------------------
	oauthTestCli := tests.NewOAuth2TestClient(authServer)
	oauthTestCli.SetAuthServiceURL(s.baseURL())
	oauthTestCli.SetTestingT(t)

	// Build redirect URIs including the FedCM internal callback.
	callbackURI := s.baseURL() + "/_internal/fedcm-callback"
	standardURI := s.baseURL() + "/oauth2/callback"

	fedcmClient, err := oauthTestCli.CreateFedCMOAuth2Client(testCtx, "fedcm_e2e_test", standardURI, callbackURI)
	require.NoError(t, err, "create FedCM OAuth2 client")
	t.Logf("FedCM OAuth2 client created: %s", fedcmClient.ClientID)

	// ------------------------------------------------------------------
	// Step 1: Cold-start sign-in — POST /s/fedcm/login
	// ------------------------------------------------------------------
	jar := newCookieJar(t)
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	loginEventID := s.performFedCMColdStartLogin(t, testCtx, httpClient, testContact)
	t.Logf("Cold-start login event ID: %s", loginEventID)

	// ------------------------------------------------------------------
	// Step 1b: Get the verification code from the notification service.
	// ------------------------------------------------------------------
	verCode, err := oauthTestCli.GetVerificationCodeByLoginEventID(testCtx, authServer, loginEventID)
	require.NoError(t, err, "get verification code")
	t.Logf("Got verification code (len=%d)", len(verCode))

	// ------------------------------------------------------------------
	// Step 1c: Submit the verification code to /s/fedcm/verify/{id}
	//          On success the handler writes the idp_session cookie.
	// ------------------------------------------------------------------
	s.performFedCMVerify(t, testCtx, httpClient, loginEventID, verCode)
	t.Logf("FedCM verify succeeded — idp_session cookie should be set")

	// ------------------------------------------------------------------
	// Step 2: GET /fedcm/accounts — must include the signed-in account.
	// ------------------------------------------------------------------
	accountsResp := s.doFedCMAccounts(t, testCtx, httpClient)
	require.NotEmpty(t, accountsResp.Accounts, "accounts endpoint must return at least one account")
	accountID := accountsResp.Accounts[0].ID
	t.Logf("Accounts endpoint returned %d account(s), first account ID: %s", len(accountsResp.Accounts), accountID)

	// ------------------------------------------------------------------
	// Step 3: POST /fedcm/id-assertion — triggers headless Hydra flow.
	// ------------------------------------------------------------------
	idToken := s.doFedCMIdAssertion(t, testCtx, httpClient, fedcmClient.ClientID, accountID, "test-nonce-001")
	t.Logf("id-assertion returned id_token (len=%d)", len(idToken))

	// ------------------------------------------------------------------
	// Step 4: POST /fedcm/token-exchange — consume the one-shot stash.
	// ------------------------------------------------------------------
	tokenResp := s.doFedCMTokenExchange(t, testCtx, httpClient, idToken)
	t.Logf("token-exchange returned access_token (len=%d)", len(tokenResp.AccessToken))
	require.Equal(t, "Bearer", tokenResp.TokenType)
	require.NotEmpty(t, tokenResp.AccessToken)

	// ------------------------------------------------------------------
	// Step 5: Verify id_token JWT claims.
	// ------------------------------------------------------------------
	claims := decodeJWTClaims(t, idToken)
	t.Logf("id_token claims: %v", claims)
	require.NotEmpty(t, claims["sub"], "sub claim must be present")
	// tenant_id and partition_id are injected by the headless flow's consent accept.
	require.NotEmpty(t, claims["tenant_id"], "tenant_id claim must be present")
	require.NotEmpty(t, claims["partition_id"], "partition_id claim must be present")
	require.Equal(t, "fedcm", claims["acr"], "acr claim must be fedcm")

	// ------------------------------------------------------------------
	// Step 6: Replay the same id_token → must fail with 401.
	// ------------------------------------------------------------------
	s.doFedCMTokenExchangeExpectStatus(t, testCtx, httpClient, idToken, http.StatusUnauthorized)
	t.Logf("Replay of id_token correctly rejected with 401")
}

// performFedCMColdStartLogin posts the contact form to /s/fedcm/login and
// follows the redirect to /s/fedcm/verify/{loginEventId}. Returns the loginEventID.
func (s *FedCMFlowSuite) performFedCMColdStartLogin(
	t *testing.T,
	ctx context.Context,
	client *http.Client,
	contact string,
) string {
	t.Helper()

	loginURL := s.baseURL() + "/s/fedcm/login"

	// First visit the GET page to establish any session cookies.
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	require.NoError(t, err)
	getResp, err := client.Do(getReq)
	require.NoError(t, err)
	_, _ = io.ReadAll(getResp.Body)
	getResp.Body.Close()

	// POST the contact form.
	formData := url.Values{}
	formData.Set("contact", contact)

	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(formData.Encode()))
	require.NoError(t, err)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	postResp, err := client.Do(postReq)
	require.NoError(t, err)
	body, _ := io.ReadAll(postResp.Body)
	postResp.Body.Close()

	require.Equal(t, http.StatusSeeOther, postResp.StatusCode,
		"fedcm/login POST should redirect; body: %s", string(body))

	location := postResp.Header.Get("Location")
	require.NotEmpty(t, location, "redirect Location must be set")
	t.Logf("fedcm/login redirected to: %s", location)

	// Extract loginEventID from the redirect path: /s/fedcm/verify/{loginEventId}
	// The path may be relative or absolute.
	parsedLoc, err := url.Parse(location)
	require.NoError(t, err)

	parts := strings.Split(strings.TrimPrefix(parsedLoc.Path, "/"), "/")
	// Expected path: s/fedcm/verify/{loginEventId}
	require.GreaterOrEqual(t, len(parts), 4, "unexpected redirect path: %s", parsedLoc.Path)
	loginEventID := parts[3]
	require.NotEmpty(t, loginEventID, "loginEventID must be non-empty in redirect path")

	return loginEventID
}

// performFedCMVerify submits the verification code to /s/fedcm/verify/{id}.
// The handler writes the idp_session cookie on success.
func (s *FedCMFlowSuite) performFedCMVerify(
	t *testing.T,
	ctx context.Context,
	client *http.Client,
	loginEventID string,
	code string,
) {
	t.Helper()

	verifyURL := fmt.Sprintf("%s/s/fedcm/verify/%s", s.baseURL(), loginEventID)

	// GET the verify form first (so any session cookies are present).
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	require.NoError(t, err)
	getResp, err := client.Do(getReq)
	require.NoError(t, err)
	getBody, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	require.Equal(t, http.StatusOK, getResp.StatusCode,
		"fedcm verify GET should return 200; body: %s", string(getBody))

	// POST the verification code.
	formData := url.Values{}
	formData.Set("verification_code", code)
	formData.Set("login_event_id", loginEventID)
	formData.Set("contact_type", "email")
	formData.Set("profile_name", "")

	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, strings.NewReader(formData.Encode()))
	require.NoError(t, err)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	postResp, err := client.Do(postReq)
	require.NoError(t, err)
	postBody, _ := io.ReadAll(postResp.Body)
	postResp.Body.Close()

	require.Equal(t, http.StatusOK, postResp.StatusCode,
		"fedcm verify POST should return 200 (close page); body: %s", string(postBody))

	// Verify the idp_session cookie is now set.
	parsedBase, _ := url.Parse(s.baseURL())
	cookies := client.Jar.Cookies(parsedBase)
	var hasIdPSession bool
	for _, c := range cookies {
		if c.Name == "idp_session" {
			hasIdPSession = true
			break
		}
	}
	require.True(t, hasIdPSession, "idp_session cookie must be set after successful verify")
}

// fedcmAccountsResponse mirrors the JSON shape returned by /fedcm/accounts.
type fedcmAccountsResponse struct {
	Accounts []struct {
		ID    string `json:"id"`
		Email string `json:"email,omitempty"`
		Name  string `json:"name"`
	} `json:"accounts"`
}

// doFedCMAccounts calls GET /fedcm/accounts and returns the parsed response.
func (s *FedCMFlowSuite) doFedCMAccounts(
	t *testing.T,
	ctx context.Context,
	client *http.Client,
) fedcmAccountsResponse {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL()+"/fedcm/accounts", nil)
	require.NoError(t, err)
	req.Header.Set("Sec-Fetch-Dest", "webidentity")

	resp, err := client.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"GET /fedcm/accounts should return 200; body: %s", string(body))

	var out fedcmAccountsResponse
	require.NoError(t, json.Unmarshal(body, &out),
		"fedcm/accounts response must be valid JSON; body: %s", string(body))
	return out
}

// doFedCMIdAssertion calls POST /fedcm/id-assertion and returns the id_token string.
func (s *FedCMFlowSuite) doFedCMIdAssertion(
	t *testing.T,
	ctx context.Context,
	client *http.Client,
	clientID string,
	accountID string,
	nonce string,
) string {
	t.Helper()

	body, _ := json.Marshal(map[string]any{
		"client_id":  clientID,
		"nonce":      nonce,
		"account_id": accountID,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL()+"/fedcm/id-assertion", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Dest", "webidentity")
	// Simulate the browser's Origin header (must match a redirect URI of the client).
	req.Header.Set("Origin", s.baseURL())

	resp, err := client.Do(req)
	require.NoError(t, err)
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"POST /fedcm/id-assertion should return 200; body: %s", string(respBody))

	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(respBody, &out))
	require.NotEmpty(t, out.Token, "id-assertion must return a non-empty token")
	return out.Token
}

// doFedCMTokenExchange calls POST /fedcm/token-exchange and returns the parsed response.
func (s *FedCMFlowSuite) doFedCMTokenExchange(
	t *testing.T,
	ctx context.Context,
	client *http.Client,
	idToken string,
) struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
} {
	t.Helper()

	body, _ := json.Marshal(map[string]string{"id_token": idToken})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL()+"/fedcm/token-exchange", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"POST /fedcm/token-exchange should return 200; body: %s", string(respBody))

	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(respBody, &out))
	return out
}

// doFedCMTokenExchangeExpectStatus is like doFedCMTokenExchange but asserts a
// specific HTTP status code rather than 200. Used for replay/revocation tests.
func (s *FedCMFlowSuite) doFedCMTokenExchangeExpectStatus(
	t *testing.T,
	ctx context.Context,
	client *http.Client,
	idToken string,
	expectedStatus int,
) {
	t.Helper()

	body, _ := json.Marshal(map[string]string{"id_token": idToken})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL()+"/fedcm/token-exchange", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	require.Equal(t, expectedStatus, resp.StatusCode,
		"expected status %d from /fedcm/token-exchange; body: %s", expectedStatus, string(respBody))
}
