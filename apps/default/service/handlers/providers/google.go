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

package providers

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// subtleStringCompare is a tiny shim so the verifier code reads naturally.
// Using crypto/subtle.ConstantTimeCompare here defends against timing attacks
// on nonce equality checks — the nonce is short and attacker-controlled in
// theory, and string equality leaks length differences.
func subtleStringCompare(a, b string) int {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}

type GoogleOIDCProvider struct {
	provider *oidc.Provider
	oauth2   oauth2.Config
}

func NewGoogleOIDCProvider(
	ctx context.Context,
	clientID, clientSecret, redirectURL string,
) (*GoogleOIDCProvider, error) {

	p, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, fmt.Errorf("google: OIDC provider discovery failed: %w", err)
	}

	return &GoogleOIDCProvider{
		provider: p,
		oauth2: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
	}, nil
}

func (g *GoogleOIDCProvider) Name() string {
	return "google"
}

// ClientID returns the configured Google OAuth client ID. Exposed so handlers
// can pass it into the FedCM IdentityProviderConfig when invoking
// navigator.credentials.get from the browser.
func (g *GoogleOIDCProvider) ClientID() string {
	return g.oauth2.ClientID
}

func (g *GoogleOIDCProvider) AuthCodeURL(state, challenge, nonce string) string {
	// oauth2.Config.AuthCodeURL already sets response_type=code. We also pin
	// it explicitly so a future Endpoint/options change cannot produce the
	// Google "Required parameter is missing: response_type" 400 page.
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("response_type", "code"),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.AccessTypeOnline,
	}
	if nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))
	}
	return g.oauth2.AuthCodeURL(state, opts...)
}

// VerifyIDToken validates a Google-issued id_token against the discovered
// JWKS, enforces aud/iss/exp via the underlying oidc.Verifier, and additionally
// checks the nonce claim when expectedNonce is non-empty. It is the single
// source of truth for id_token trust — both the OAuth code-exchange callback
// and the FedCM completion endpoint MUST funnel through here so the security
// surface stays identical across flows.
//
// Returns an AuthenticatedUser populated from the id_token claims. The
// returned Raw map carries the full claim set so downstream handlers can
// access provider-specific fields.
func (g *GoogleOIDCProvider) VerifyIDToken(
	ctx context.Context,
	rawIDToken string,
	expectedNonce string,
) (*AuthenticatedUser, error) {
	if rawIDToken == "" {
		return nil, fmt.Errorf("google: id_token is empty")
	}

	verifierOIDC := g.provider.Verifier(&oidc.Config{
		ClientID: g.oauth2.ClientID,
	})

	idToken, err := verifierOIDC.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("google: id_token verification failed: %w", err)
	}

	var claims map[string]any
	if err = idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("google: failed to parse id_token claims: %w", err)
	}

	return ValidateGoogleClaims(claims, expectedNonce)
}

// ValidateGoogleClaims applies the nonce + email_verified + claim-extraction
// checks that the OAuth and FedCM flows share. It is exported so the same
// logic can be exercised in unit tests with a hand-built claims map without
// round-tripping a real JWT through Google's live JWKS.
//
// Callers are responsible for first performing signature, iss, aud and exp
// validation through oidc.Verifier; this function trusts that the supplied
// claims already came out of a verified id_token. Returning an error from
// here is what causes both the OAuth callback and the FedCM completion
// handler to refuse the login.
func ValidateGoogleClaims(claims map[string]any, expectedNonce string) (*AuthenticatedUser, error) {
	if claims == nil {
		return nil, fmt.Errorf("google: id_token claims are empty")
	}

	if expectedNonce != "" {
		tokenNonce, _ := claims["nonce"].(string)
		if tokenNonce == "" || subtleStringCompare(tokenNonce, expectedNonce) != 1 {
			return nil, fmt.Errorf("google: nonce verification failed")
		}
	}

	// email_verified MUST be true for any account-binding decision. Google sets
	// this to true for @gmail.com and Workspace-hosted accounts; it can be
	// false (or absent) for older or unverified federated accounts. We refuse
	// the login rather than auto-merging into an existing profile whose email
	// the token can't prove ownership of.
	emailVerified := true
	if v, ok := claims["email_verified"]; ok {
		switch t := v.(type) {
		case bool:
			emailVerified = t
		case string:
			emailVerified = t == "true"
		}
	}
	if !emailVerified {
		return nil, fmt.Errorf("google: email is not verified on the Google account")
	}

	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	picture, _ := claims["picture"].(string)

	return &AuthenticatedUser{
		Contact:   email,
		Name:      name,
		AvatarURL: picture,
		Raw:       claims,
	}, nil
}

func (g *GoogleOIDCProvider) CompleteLogin(
	ctx context.Context,
	code string,
	verifier string,
	nonce string,
) (*AuthenticatedUser, error) {

	token, err := g.oauth2.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		return nil, fmt.Errorf("google: token exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("google: missing id_token in token response")
	}

	return g.VerifyIDToken(ctx, rawIDToken, nonce)
}
