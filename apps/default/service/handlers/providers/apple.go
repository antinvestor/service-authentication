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
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type AppleProvider struct {
	provider   *oidc.Provider
	oauth2     oauth2.Config
	httpClient *http.Client
}

func NewAppleProvider(
	ctx context.Context,
	clientID, redirectURL string,
	clientSecret string, // pre-generated JWT
	httpClient *http.Client,
) (*AppleProvider, error) {

	p, err := oidc.NewProvider(withOAuthHTTPClient(ctx, httpClient), "https://appleid.apple.com")
	if err != nil {
		return nil, fmt.Errorf("apple: OIDC provider discovery failed: %w", err)
	}

	return &AppleProvider{
		provider:   p,
		httpClient: httpClient,
		oauth2: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "name"},
		},
	}, nil
}

func (a *AppleProvider) Name() string {
	return "apple"
}

func (a *AppleProvider) AuthCodeURL(state, challenge, nonce string) string {
	authURL := a.oauth2.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("response_mode", "form_post"),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	if nonce != "" {
		authURL = a.oauth2.AuthCodeURL(
			state,
			oauth2.SetAuthURLParam("response_mode", "form_post"),
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			oauth2.SetAuthURLParam("nonce", nonce),
		)
	}
	return authURL
}

func (a *AppleProvider) CompleteLogin(
	ctx context.Context,
	code string,
	verifier string,
	nonce string,
) (*AuthenticatedUser, error) {

	token, err := a.oauth2.Exchange(
		withOAuthHTTPClient(ctx, a.httpClient),
		code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		return nil, fmt.Errorf("apple: token exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("apple: missing id_token in token response")
	}

	verifierOIDC := a.provider.Verifier(&oidc.Config{
		ClientID: a.oauth2.ClientID,
	})

	idToken, err := verifierOIDC.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("apple: id_token verification failed: %w", err)
	}

	var claims map[string]any
	if claimErr := idToken.Claims(&claims); claimErr != nil {
		return nil, fmt.Errorf("apple: failed to parse id_token claims: %w", claimErr)
	}

	if nonce != "" {
		tokenNonce, _ := claims["nonce"].(string)
		if tokenNonce == "" || tokenNonce != nonce {
			return nil, fmt.Errorf("apple: nonce verification failed")
		}
	}

	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	return &AuthenticatedUser{
		Contact: email,
		Name:    name,
		Raw:     claims,
	}, nil
}
