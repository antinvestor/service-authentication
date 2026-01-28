package providers

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

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

func (g *GoogleOIDCProvider) AuthCodeURL(state, challenge string) string {
	return g.oauth2.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (g *GoogleOIDCProvider) CompleteLogin(
	ctx context.Context,
	code string,
	verifier string,
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

	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	return &AuthenticatedUser{
		Contact: email,
		Name:    name,
		Raw:     claims,
	}, nil
}
