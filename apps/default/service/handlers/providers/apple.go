package providers

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type AppleProvider struct {
	provider *oidc.Provider
	oauth2   oauth2.Config
}

func NewAppleProvider(
	ctx context.Context,
	clientID, redirectURL string,
	clientSecret string, // pre-generated JWT
) (*AppleProvider, error) {

	p, err := oidc.NewProvider(ctx, "https://appleid.apple.com")
	if err != nil {
		return nil, fmt.Errorf("apple: OIDC provider discovery failed: %w", err)
	}

	return &AppleProvider{
		provider: p,
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

func (a *AppleProvider) AuthCodeURL(state, challenge string) string {
	return a.oauth2.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("response_mode", "form_post"),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (a *AppleProvider) CompleteLogin(
	ctx context.Context,
	code string,
	verifier string,
) (*AuthenticatedUser, error) {

	token, err := a.oauth2.Exchange(
		ctx,
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

	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	return &AuthenticatedUser{
		Contact: email,
		Name:    name,
		Raw:     claims,
	}, nil
}
