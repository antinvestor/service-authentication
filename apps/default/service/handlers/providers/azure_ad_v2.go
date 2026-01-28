package providers

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type MicrosoftProvider struct {
	provider *oidc.Provider
	oauth2   oauth2.Config
}

func NewMicrosoftProvider(
	ctx context.Context,
	tenant, clientID, clientSecret, redirectURL string,
) (*MicrosoftProvider, error) {

	issuer := fmt.Sprintf(
		"https://login.microsoftonline.com/%s/v2.0",
		tenant, // "common", "organisations", or tenant ID
	)

	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("microsoft: OIDC provider discovery failed for tenant %s: %w", tenant, err)
	}

	return &MicrosoftProvider{
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

func (m *MicrosoftProvider) Name() string {
	return "microsoft"
}

func (m *MicrosoftProvider) AuthCodeURL(state, challenge string) string {
	return m.oauth2.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (m *MicrosoftProvider) CompleteLogin(
	ctx context.Context,
	code string,
	verifier string,
) (*AuthenticatedUser, error) {

	token, err := m.oauth2.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		return nil, fmt.Errorf("microsoft: token exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("microsoft: missing id_token in token response")
	}

	verifierOIDC := m.provider.Verifier(&oidc.Config{
		ClientID: m.oauth2.ClientID,
	})

	idToken, err := verifierOIDC.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("microsoft: id_token verification failed: %w", err)
	}

	var claims map[string]any
	if claimErr := idToken.Claims(&claims); claimErr != nil {
		return nil, fmt.Errorf("microsoft: failed to parse id_token claims: %w", claimErr)
	}

	email, _ := claims["preferred_username"].(string)
	if email == "" {
		email, _ = claims["email"].(string)
	}

	name, _ := claims["name"].(string)

	return &AuthenticatedUser{
		Contact: email,
		Name:    name,
		Raw:     claims,
	}, nil
}
