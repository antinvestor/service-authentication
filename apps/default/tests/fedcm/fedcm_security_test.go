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

// Package fedcm_test contains security regression tests for the FedCM IdP
// endpoints. This file covers:
//
//  1. All FedCM endpoints must reject requests missing the Sec-Fetch-Dest header.
//  2. POST /fedcm/id-assertion must reject requests whose Origin header does not
//     match any redirect URI registered for the OAuth2 client (HTTP 403).
//  3. POST /fedcm/disconnect followed by POST /fedcm/id-assertion on the same
//     (profile, client) pair must fail with HTTP 403 / "access_denied".
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
	"github.com/pitabwire/frame/v2/frametests"
	"github.com/pitabwire/frame/v2/frametests/definition"
	"github.com/pitabwire/frame/v2/frametests/deps/testpostgres"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

// FedCMSecuritySuite exercises security properties of the FedCM IdP endpoints.
type FedCMSecuritySuite struct {
	tests.BaseTestSuite
}

func TestFedCMSecurity(t *testing.T) { suite.Run(t, new(FedCMSecuritySuite)) }

func (s *FedCMSecuritySuite) baseURL() string {
	return "http://127.0.0.1:" + s.FreeAuthPort
}

// SetupSuite mirrors FedCMFlowSuite.SetupSuite: allocates a free port, injects
// FEDCM_PUBLIC_ORIGIN, and starts all required test containers.
func (s *FedCMSecuritySuite) SetupSuite() {
	s.InitResourceFunc = func(ctx context.Context) []definition.TestResource {
		freePort, _ := frametests.GetFreePort(ctx)
		s.FreeAuthPort = strconv.Itoa(freePort)
		authURL := fmt.Sprintf("http://127.0.0.1:%s", s.FreeAuthPort)

		os.Setenv("FEDCM_PUBLIC_ORIGIN", authURL) //nolint:errcheck

		return s.initSecurityResources(ctx, authURL, freePort)
	}
	s.BaseTestSuite.SetupSuite()
}

// TearDownSuite cleans up env vars set during SetupSuite.
func (s *FedCMSecuritySuite) TearDownSuite() {
	os.Unsetenv("FEDCM_PUBLIC_ORIGIN") //nolint:errcheck
	s.BaseTestSuite.TearDownSuite()
}

// initSecurityResources builds the same resource graph as FedCMFlowSuite.
func (s *FedCMSecuritySuite) initSecurityResources(_ context.Context, loginURL string, authPort int) []definition.TestResource {
	pg := testpostgres.NewWithOpts("service_authentication",
		definition.WithUserName("ant"), definition.WithCredential("s3cr3t"),
		definition.WithEnableLogging(false), definition.WithUseHostMode(false))

	dockerLoginURL := strings.Replace(loginURL, "127.0.0.1", testcontainers.HostInternal, 1)
	localHydraConfig := strings.Replace(internaltests.HydraConfiguration, "http://127.0.0.1:3000/", dockerLoginURL+"/s/", 3)
	localHydraConfig = strings.Replace(localHydraConfig, "http://127.0.0.1:3000/", dockerLoginURL+"/", 2)

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

// ---------------------------------------------------------------------------
// Shared sign-in helpers (local to this suite; mirrors FedCMFlowSuite methods)
// ---------------------------------------------------------------------------

// secPerformColdStartLogin posts to /s/fedcm/login and returns the loginEventID.
func (s *FedCMSecuritySuite) secPerformColdStartLogin(
	t *testing.T,
	ctx context.Context,
	client *http.Client,
	contact string,
) string {
	t.Helper()

	loginURL := s.baseURL() + "/s/fedcm/login"

	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	require.NoError(t, err)
	getResp, err := client.Do(getReq)
	require.NoError(t, err)
	_, _ = io.ReadAll(getResp.Body)
	getResp.Body.Close()

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
	require.NotEmpty(t, location)

	parsedLoc, err := url.Parse(location)
	require.NoError(t, err)

	parts := strings.Split(strings.TrimPrefix(parsedLoc.Path, "/"), "/")
	// Expected: s/fedcm/verify/{loginEventId}
	require.GreaterOrEqual(t, len(parts), 4, "unexpected redirect path: %s", parsedLoc.Path)
	loginEventID := parts[3]
	require.NotEmpty(t, loginEventID)
	return loginEventID
}

// secPerformVerify submits the verification code to /s/fedcm/verify/{id}.
func (s *FedCMSecuritySuite) secPerformVerify(
	t *testing.T,
	ctx context.Context,
	client *http.Client,
	loginEventID string,
	code string,
) {
	t.Helper()

	verifyURL := fmt.Sprintf("%s/s/fedcm/verify/%s", s.baseURL(), loginEventID)

	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	require.NoError(t, err)
	getResp, err := client.Do(getReq)
	require.NoError(t, err)
	getBody, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	require.Equal(t, http.StatusOK, getResp.StatusCode,
		"fedcm verify GET should return 200; body: %s", string(getBody))

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
		"fedcm verify POST should return 200; body: %s", string(postBody))

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

// secDoAccounts calls GET /fedcm/accounts and returns the parsed response.
func (s *FedCMSecuritySuite) secDoAccounts(
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

// secSignIn performs the full cold-start sign-in flow and returns (accountID, httpClient).
func (s *FedCMSecuritySuite) secSignIn(
	t *testing.T,
	ctx context.Context,
	contact string,
) (accountID string, client *http.Client) {
	t.Helper()

	authServer := s.Handler()
	require.NotNil(t, authServer)
	authServer.ResetLoginRateLimit(ctx, "127.0.0.1")
	authServer.ResetLoginRateLimit(ctx, "::1")

	jar := newCookieJar(t)
	client = &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	oauthTestCli := tests.NewOAuth2TestClient(authServer)
	oauthTestCli.SetAuthServiceURL(s.baseURL())
	oauthTestCli.SetTestingT(t)

	loginEventID := s.secPerformColdStartLogin(t, ctx, client, contact)
	t.Logf("cold-start loginEventID: %s", loginEventID)

	verCode, err := oauthTestCli.GetVerificationCodeByLoginEventID(ctx, authServer, loginEventID)
	require.NoError(t, err)

	s.secPerformVerify(t, ctx, client, loginEventID, verCode)

	accountsResp := s.secDoAccounts(t, ctx, client)
	require.NotEmpty(t, accountsResp.Accounts)
	accountID = accountsResp.Accounts[0].ID
	t.Logf("signed-in accountID: %s", accountID)
	return accountID, client
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// waitForServer blocks until the auth server HTTP listener is accepting
// connections, or until 10 seconds have elapsed. It uses the /fedcm/accounts
// endpoint (which returns 400 without a Sec-Fetch-Dest header, not a network
// error) as the readiness probe.
func (s *FedCMSecuritySuite) waitForServer() {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(s.baseURL() + "/fedcm/accounts") //nolint:noctx
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.T().Fatal("auth server did not become ready within 10 seconds")
}

// TestAllFedCMEndpointsRejectMissingSecFetchDest verifies that every FedCM
// endpoint returns HTTP 400 when the Sec-Fetch-Dest header is absent.
func (s *FedCMSecuritySuite) TestAllFedCMEndpointsRejectMissingSecFetchDest() {
	// Ensure the HTTP listener is accepting before probing it.
	s.waitForServer()

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/fedcm/accounts"},
		{http.MethodGet, "/fedcm/client_metadata?client_id=foo"},
		{http.MethodPost, "/fedcm/id-assertion"},
		{http.MethodPost, "/fedcm/disconnect"},
	}
	for _, tc := range cases {
		s.Run(tc.method+" "+tc.path, func() {
			var reqBody []byte
			if tc.method == http.MethodPost {
				reqBody, _ = json.Marshal(map[string]string{
					"client_id":    "foo",
					"nonce":        "bar",
					"account_id":   "baz",
					"account_hint": "baz",
				})
			}
			req, err := http.NewRequest(tc.method, s.baseURL()+tc.path, bytes.NewReader(reqBody))
			s.Require().NoError(err)
			if tc.method == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
			}
			// Deliberately omit Sec-Fetch-Dest.

			resp, err := http.DefaultClient.Do(req)
			s.Require().NoError(err)
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			s.Require().Equal(http.StatusBadRequest, resp.StatusCode,
				"%s %s should return 400 without Sec-Fetch-Dest; got %d body: %s",
				tc.method, tc.path, resp.StatusCode, string(body))
		})
	}
}

// TestIdAssertionOriginMismatchReturns403 verifies that /fedcm/id-assertion
// returns HTTP 403 when the Origin header does not match any registered
// redirect URI of the OAuth2 client.
func (s *FedCMSecuritySuite) TestIdAssertionOriginMismatchReturns403() {
	const testContact = "sec-origin-test@example.com"

	t := s.T()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	authServer := s.Handler()
	require.NotNil(t, authServer)

	oauthTestCli := tests.NewOAuth2TestClient(authServer)
	oauthTestCli.SetAuthServiceURL(s.baseURL())
	oauthTestCli.SetTestingT(t)

	callbackURI := s.baseURL() + "/_internal/fedcm-callback"
	standardURI := s.baseURL() + "/oauth2/callback"

	fedcmClient, err := oauthTestCli.CreateFedCMOAuth2Client(ctx, "sec_origin_test", standardURI, callbackURI)
	require.NoError(t, err)
	t.Logf("FedCM client created: %s", fedcmClient.ClientID)

	accountID, client := s.secSignIn(t, ctx, testContact)

	// Build an id-assertion request with a mismatched origin.
	body, _ := json.Marshal(map[string]any{
		"client_id":  fedcmClient.ClientID,
		"nonce":      "test-nonce-origin-mismatch",
		"account_id": accountID,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL()+"/fedcm/id-assertion", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Dest", "webidentity")
	// Use an origin that is NOT registered as a redirect URI.
	req.Header.Set("Origin", "https://evil.example.com")

	resp, err := client.Do(req)
	require.NoError(t, err)
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	t.Logf("id-assertion (mismatched origin) response: %d %s", resp.StatusCode, string(respBody))
	require.Equal(t, http.StatusForbidden, resp.StatusCode,
		"id-assertion with mismatched Origin must return 403; body: %s", string(respBody))

	var errResp map[string]string
	if json.Unmarshal(respBody, &errResp) == nil {
		t.Logf("error response: %v", errResp)
	}
}

// TestDisconnectThenIdAssertionReturnsAccessDenied verifies the revocation flow:
// after a successful /fedcm/disconnect the same (account, client) pair must be
// refused by /fedcm/id-assertion with HTTP 403 / "access_denied".
func (s *FedCMSecuritySuite) TestDisconnectThenIdAssertionReturnsAccessDenied() {
	const testContact = "sec-revoke-test@example.com"

	t := s.T()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	authServer := s.Handler()
	require.NotNil(t, authServer)

	oauthTestCli := tests.NewOAuth2TestClient(authServer)
	oauthTestCli.SetAuthServiceURL(s.baseURL())
	oauthTestCli.SetTestingT(t)

	callbackURI := s.baseURL() + "/_internal/fedcm-callback"
	standardURI := s.baseURL() + "/oauth2/callback"

	fedcmClient, err := oauthTestCli.CreateFedCMOAuth2Client(ctx, "sec_revoke_test", standardURI, callbackURI)
	require.NoError(t, err)
	t.Logf("FedCM client for revocation test: %s", fedcmClient.ClientID)

	accountID, client := s.secSignIn(t, ctx, testContact)

	// ------------------------------------------------------------------
	// Step 1: Call /fedcm/disconnect to revoke (accountID, clientID).
	// ------------------------------------------------------------------
	disconnBody, _ := json.Marshal(map[string]string{
		"client_id":    fedcmClient.ClientID,
		"account_hint": accountID,
	})
	disconnReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.baseURL()+"/fedcm/disconnect", bytes.NewReader(disconnBody))
	require.NoError(t, err)
	disconnReq.Header.Set("Content-Type", "application/json")
	disconnReq.Header.Set("Sec-Fetch-Dest", "webidentity")

	disconnResp, err := client.Do(disconnReq)
	require.NoError(t, err)
	disconnRespBody, _ := io.ReadAll(disconnResp.Body)
	disconnResp.Body.Close()

	t.Logf("disconnect response: %d %s", disconnResp.StatusCode, string(disconnRespBody))
	require.Equal(t, http.StatusOK, disconnResp.StatusCode,
		"disconnect should return 200; body: %s", string(disconnRespBody))

	// ------------------------------------------------------------------
	// Step 2: Sign in again with a fresh HTTP client so we have a valid
	// idp_session (the previous cookie may have been cleared by disconnect).
	// ------------------------------------------------------------------
	authServer.ResetLoginRateLimit(ctx, "127.0.0.1")
	authServer.ResetLoginRateLimit(ctx, "::1")

	jar2 := newCookieJar(t)
	client2 := &http.Client{
		Jar: jar2,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	oauthTestCli2 := tests.NewOAuth2TestClient(authServer)
	oauthTestCli2.SetAuthServiceURL(s.baseURL())
	oauthTestCli2.SetTestingT(t)

	loginEventID2 := s.secPerformColdStartLogin(t, ctx, client2, testContact)
	verCode2, err := oauthTestCli2.GetVerificationCodeByLoginEventID(ctx, authServer, loginEventID2)
	require.NoError(t, err)
	s.secPerformVerify(t, ctx, client2, loginEventID2, verCode2)

	accountsResp2 := s.secDoAccounts(t, ctx, client2)
	require.NotEmpty(t, accountsResp2.Accounts, "second sign-in must return accounts")
	accountID2 := accountsResp2.Accounts[0].ID

	// ------------------------------------------------------------------
	// Step 3: Attempt id-assertion — must be rejected by revocation check.
	// ------------------------------------------------------------------
	assertBody, _ := json.Marshal(map[string]any{
		"client_id":  fedcmClient.ClientID,
		"nonce":      "test-nonce-after-revoke",
		"account_id": accountID2,
	})
	assertReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.baseURL()+"/fedcm/id-assertion", bytes.NewReader(assertBody))
	require.NoError(t, err)
	assertReq.Header.Set("Content-Type", "application/json")
	assertReq.Header.Set("Sec-Fetch-Dest", "webidentity")
	assertReq.Header.Set("Origin", s.baseURL())

	assertResp, err := client2.Do(assertReq)
	require.NoError(t, err)
	assertRespBody, _ := io.ReadAll(assertResp.Body)
	assertResp.Body.Close()

	t.Logf("id-assertion after disconnect: %d %s", assertResp.StatusCode, string(assertRespBody))
	require.Equal(t, http.StatusForbidden, assertResp.StatusCode,
		"id-assertion after disconnect must return 403; body: %s", string(assertRespBody))

	var errResp map[string]string
	if json.Unmarshal(assertRespBody, &errResp) == nil {
		s.Require().Equal("access_denied", errResp["error"],
			"error field must be 'access_denied'; got %v", errResp)
	}
}
