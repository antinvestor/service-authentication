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

package fedcm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	hydraclientgo "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/util"

	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
)

// AuthorizeURLInput is the set of parameters used to construct the headless
// Hydra authorize URL.
type AuthorizeURLInput struct {
	HydraPublicURL string
	ClientID       string
	RedirectURI    string
	Scopes         []string
	Nonce          string
	State          string
	CodeChallenge  string
}

// BuildAuthorizeURL constructs the Hydra /oauth2/auth URL used in the headless
// FedCM flow.
//
// We intentionally omit prompt=none because Hydra short-circuits to an error
// when no Hydra session exists, preventing our admin-API login/consent accept
// path from ever running. The redirect-follower in Run handles the /s/login
// and /s/consent intercepts directly.
func BuildAuthorizeURL(in AuthorizeURLInput) (string, error) {
	if in.HydraPublicURL == "" || in.ClientID == "" || in.RedirectURI == "" || in.State == "" || in.CodeChallenge == "" {
		return "", fmt.Errorf("missing required field on AuthorizeURLInput")
	}
	base, err := url.Parse(in.HydraPublicURL)
	if err != nil {
		return "", fmt.Errorf("parse hydra public url: %w", err)
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/oauth2/auth"
	q := base.Query()
	q.Set("response_type", "code")
	q.Set("client_id", in.ClientID)
	q.Set("redirect_uri", in.RedirectURI)
	q.Set("scope", strings.Join(in.Scopes, " "))
	q.Set("state", in.State)
	q.Set("code_challenge", in.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	if in.Nonce != "" {
		q.Set("nonce", in.Nonce)
	}
	base.RawQuery = q.Encode()
	return base.String(), nil
}

// GeneratePKCEPair returns a verifier and its S256-encoded challenge.
func GeneratePKCEPair() (verifier, challenge string, err error) {
	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// ExtractLoginChallenge pulls `login_challenge` from a Hydra redirect URL.
func ExtractLoginChallenge(location string) (string, error) {
	return extractQuery(location, "login_challenge")
}

// ExtractConsentChallenge pulls `consent_challenge` from a Hydra redirect URL.
func ExtractConsentChallenge(location string) (string, error) {
	return extractQuery(location, "consent_challenge")
}

// ExtractCallbackCode pulls `code` and `state` from the FedCM internal callback URL.
func ExtractCallbackCode(location string) (code, state string, err error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", "", err
	}
	q := u.Query()
	c, s := q.Get("code"), q.Get("state")
	if c == "" {
		return "", "", fmt.Errorf("callback has no code (%s)", q.Get("error"))
	}
	return c, s, nil
}

func extractQuery(location, key string) (string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	v := u.Query().Get(key)
	if v == "" {
		return "", fmt.Errorf("redirect missing %s: %s", key, location)
	}
	return v, nil
}

// HeadlessRequest parameterises a single headless FedCM token issuance.
type HeadlessRequest struct {
	ClientID     string
	ClientSecret string
	SubjectID    string
	Nonce        string
	Scopes       []string
	Claims       map[string]any
	ACR          string
	AMR          []string
	DeviceID     string
}

// HeadlessResult is what the driver returns when successful.
type HeadlessResult struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresIn    int
}

// HeadlessDriver runs a full headless authorization_code flow against Hydra.
// It never redirects the caller; all intermediate hops are executed as
// server-to-server HTTP calls with a custom redirect inspector.
type HeadlessDriver struct {
	HydraAdmin          hydra.Hydra
	HydraPublicURL      string
	InternalCallbackURL string
	Now                 func() time.Time
}

// Run executes the headless flow. Concurrency must be serialised by the caller
// using the cache-backed lock (fedcm:lock:<profile_id>:<client_id>).
func (d *HeadlessDriver) Run(ctx context.Context, in HeadlessRequest) (*HeadlessResult, error) {
	log := util.Log(ctx)

	state, err := randomString(32)
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}
	verifier, challenge, err := GeneratePKCEPair()
	if err != nil {
		return nil, fmt.Errorf("generate pkce: %w", err)
	}

	authorizeURL, err := BuildAuthorizeURL(AuthorizeURLInput{
		HydraPublicURL: d.HydraPublicURL,
		ClientID:       in.ClientID,
		RedirectURI:    d.InternalCallbackURL,
		Scopes:         in.Scopes,
		Nonce:          in.Nonce,
		State:          state,
		CodeChallenge:  challenge,
	})
	if err != nil {
		return nil, err
	}

	// Use a cookie jar so Hydra's CSRF cookie is preserved across redirects.
	// Without it Hydra rejects the login_verifier with "No CSRF value available
	// in the session cookie."
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	httpCli := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	code, err := d.driveHydra(ctx, httpCli, authorizeURL, in)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", d.InternalCallbackURL)
	form.Set("client_id", in.ClientID)
	form.Set("code_verifier", verifier)
	if in.ClientSecret != "" {
		form.Set("client_secret", in.ClientSecret)
	}

	tokenURL := strings.TrimRight(d.HydraPublicURL, "/") + "/oauth2/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpCli.Do(req)
	if err != nil {
		log.WithError(err).Error("fedcm token exchange transport error")
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || tok.AccessToken == "" {
		return nil, fmt.Errorf("hydra token endpoint returned %d: %s: %s", resp.StatusCode, tok.Error, tok.ErrorDesc)
	}

	return &HeadlessResult{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      tok.IDToken,
		ExpiresIn:    tok.ExpiresIn,
	}, nil
}

func (d *HeadlessDriver) driveHydra(ctx context.Context, httpCli *http.Client, authorizeURL string, in HeadlessRequest) (string, error) {
	current := authorizeURL
	for i := 0; i < 8; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return "", err
		}
		resp, err := httpCli.Do(req)
		if err != nil {
			return "", err
		}
		_ = resp.Body.Close()

		util.Log(ctx).WithField("iteration", i).WithField("status", resp.StatusCode).Debug("fedcm driveHydra step")

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return "", fmt.Errorf("hydra returned non-redirect status %d", resp.StatusCode)
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return "", fmt.Errorf("hydra redirect missing Location header")
		}

		switch {
		case strings.Contains(loc, "/s/login") && strings.Contains(loc, "login_challenge="):
			chal, err := ExtractLoginChallenge(loc)
			if err != nil {
				return "", err
			}
			redirectTo, err := d.acceptLogin(ctx, chal, in)
			if err != nil {
				return "", err
			}
			// AcceptLoginRequest returns a Hydra-generated redirect URL (containing a
			// login_verifier token). Following THAT URL drives Hydra to the consent step.
			// The original /s/login URL would only re-render the login HTML page.
			if redirectTo != "" {
				current = redirectTo
			} else {
				current = loc
			}
		case strings.Contains(loc, "/s/consent") && strings.Contains(loc, "consent_challenge="):
			chal, err := ExtractConsentChallenge(loc)
			if err != nil {
				return "", err
			}
			redirectURL, err := d.acceptConsent(ctx, chal, in)
			if err != nil {
				return "", err
			}
			// AcceptConsentRequest returns a Hydra-internal consent_verifier URL.
			// We must follow it so Hydra can complete the flow and issue the final
			// redirect to the callback URI with the authorization code.
			if strings.HasPrefix(redirectURL, d.InternalCallbackURL) {
				// Hydra already resolved to the callback — extract code directly.
				code, _, err := ExtractCallbackCode(redirectURL)
				if err != nil {
					return "", err
				}
				return code, nil
			}
			current = redirectURL
		case strings.HasPrefix(loc, d.InternalCallbackURL):
			code, _, err := ExtractCallbackCode(loc)
			if err != nil {
				return "", err
			}
			return code, nil
		default:
			current = loc
		}
	}
	return "", fmt.Errorf("headless flow exceeded redirect budget")
}

func (d *HeadlessDriver) acceptLogin(ctx context.Context, challenge string, in HeadlessRequest) (string, error) {
	params := &hydra.AcceptLoginRequestParams{
		LoginChallenge: challenge,
		SubjectID:      in.SubjectID,
		Remember:       false,
	}
	redirectTo, err := d.HydraAdmin.AcceptLoginRequest(ctx, params, nil, in.ACR, in.AMR...)
	if err != nil {
		return "", fmt.Errorf("accept login: %w", err)
	}
	// Rewrite the redirect URL to use the host-accessible Hydra public URL.
	// In Docker/testcontainer setups the admin API returns its internal hostname;
	// the headless driver must follow the URL from the host network.
	return d.normalizeHydraURL(redirectTo), nil
}

// normalizeHydraURL rewrites a Hydra-internal URL (e.g. http://hydra:4444/…)
// to the host-accessible HydraPublicURL, preserving path and query. If the
// incoming URL already uses the correct host, it is returned unchanged.
func (d *HeadlessDriver) normalizeHydraURL(rawURL string) string {
	if rawURL == "" || d.HydraPublicURL == "" {
		return rawURL
	}
	src, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	dst, err := url.Parse(d.HydraPublicURL)
	if err != nil {
		return rawURL
	}
	// Only rewrite if the hosts differ (same host means already accessible).
	if src.Host == dst.Host {
		return rawURL
	}
	src.Scheme = dst.Scheme
	src.Host = dst.Host
	return src.String()
}

func (d *HeadlessDriver) acceptConsent(ctx context.Context, challenge string, in HeadlessRequest) (string, error) {
	consentReq, err := d.HydraAdmin.GetConsentRequest(ctx, challenge)
	if err != nil {
		return "", fmt.Errorf("get consent: %w", err)
	}
	redirectURL, err := d.HydraAdmin.AcceptConsentRequest(ctx, &hydra.AcceptConsentRequestParams{
		ConsentChallenge:  challenge,
		GrantScope:        consentReq.GetRequestedScope(),
		GrantAudience:     audienceOrEmpty(consentReq),
		AccessTokenExtras: in.Claims,
		IdTokenExtras:     in.Claims,
		Remember:          false,
	})
	if err != nil {
		return "", fmt.Errorf("accept consent: %w", err)
	}
	// Rewrite to host-accessible URL in case Hydra returned its internal hostname.
	return d.normalizeHydraURL(redirectURL), nil
}

func audienceOrEmpty(c *hydraclientgo.OAuth2ConsentRequest) []string {
	if c == nil {
		return nil
	}
	// Use the audience that was actually requested in the authorize call, not the
	// client's full registered audience. Hydra requires GrantAudience ⊆ RequestedAudience;
	// granting the full client audience when no audience was requested in the
	// authorize URL results in request_forbidden.
	if aud := c.GetRequestedAccessTokenAudience(); len(aud) > 0 {
		return aud
	}
	return nil
}

func randomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
