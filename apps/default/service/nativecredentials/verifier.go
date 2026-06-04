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

package nativecredentials

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	ProviderGoogle = "google"
	ProviderApple  = "apple"

	GoogleIssuer      = "https://accounts.google.com"
	GoogleIssuerShort = "accounts.google.com"
	AppleIssuer       = "https://appleid.apple.com"
)

type Identity struct {
	Provider      string
	Issuer        string
	Subject       string
	SubjectHash   string
	Email         string
	EmailVerified bool
	Name          string
	GivenName     string
	FamilyName    string
	Picture       string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	RawClaims     map[string]any
	TokenHash     string
}

type Verifier struct {
	mu        sync.Mutex
	providers map[string]*oidc.Provider
	now       func() time.Time
}

func NewVerifier() *Verifier {
	return &Verifier{
		providers: make(map[string]*oidc.Provider),
		now:       time.Now,
	}
}

func (v *Verifier) VerifyIDToken(ctx context.Context, issuer, audience, rawToken string) (*Identity, error) {
	issuer = canonicalIssuer(issuer)
	if issuer == "" {
		return nil, fmt.Errorf("subject_issuer is required")
	}
	if audience == "" {
		return nil, fmt.Errorf("provider audience is not configured")
	}
	if rawToken == "" {
		return nil, fmt.Errorf("subject_token is required")
	}

	providerName, discoveryIssuer, err := providerForIssuer(issuer)
	if err != nil {
		return nil, err
	}

	p, err := v.oidcProvider(ctx, discoveryIssuer)
	if err != nil {
		return nil, err
	}

	idToken, err := p.Verifier(&oidc.Config{ClientID: audience}).Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("%s: id_token verification failed: %w", providerName, err)
	}

	if providerName == ProviderGoogle && idToken.Issuer != GoogleIssuer && idToken.Issuer != GoogleIssuerShort {
		return nil, fmt.Errorf("google: unexpected issuer %q", idToken.Issuer)
	}
	if providerName == ProviderApple && idToken.Issuer != AppleIssuer {
		return nil, fmt.Errorf("apple: unexpected issuer %q", idToken.Issuer)
	}

	var claims map[string]any
	if err = idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%s: parse id_token claims: %w", providerName, err)
	}

	identity := identityFromClaims(providerName, idToken, claims, rawToken)
	if identity.Subject == "" {
		return nil, fmt.Errorf("%s: subject claim is missing", providerName)
	}
	if identity.IssuedAt.IsZero() {
		return nil, fmt.Errorf("%s: issued-at claim is missing", providerName)
	}
	if v.now().After(identity.IssuedAt.Add(5*time.Minute + 30*time.Second)) {
		return nil, fmt.Errorf("%s: id_token is too old for native exchange", providerName)
	}
	if identity.Email == "" && identity.Provider == ProviderGoogle {
		return nil, fmt.Errorf("google: email claim is required")
	}
	if identity.Provider == ProviderGoogle && !identity.EmailVerified {
		return nil, fmt.Errorf("google: email is not verified")
	}

	return identity, nil
}

func (v *Verifier) oidcProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	v.mu.Lock()
	p := v.providers[issuer]
	v.mu.Unlock()
	if p != nil {
		return p, nil
	}

	created, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC issuer %s: %w", issuer, err)
	}

	v.mu.Lock()
	if existing := v.providers[issuer]; existing != nil {
		v.mu.Unlock()
		return existing, nil
	}
	v.providers[issuer] = created
	v.mu.Unlock()
	return created, nil
}

func providerForIssuer(issuer string) (provider, discoveryIssuer string, err error) {
	switch issuer {
	case GoogleIssuer, GoogleIssuerShort:
		return ProviderGoogle, GoogleIssuer, nil
	case AppleIssuer:
		return ProviderApple, AppleIssuer, nil
	default:
		return "", "", fmt.Errorf("unsupported subject_issuer %q", issuer)
	}
}

func canonicalIssuer(issuer string) string {
	issuer = strings.TrimSpace(issuer)
	if strings.EqualFold(issuer, GoogleIssuerShort) {
		return GoogleIssuerShort
	}
	return strings.TrimRight(issuer, "/")
}

func identityFromClaims(provider string, token *oidc.IDToken, claims map[string]any, rawToken string) *Identity {
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	givenName, _ := claims["given_name"].(string)
	familyName, _ := claims["family_name"].(string)
	picture, _ := claims["picture"].(string)
	emailVerified := boolClaim(claims["email_verified"])

	subjectHash := ""
	if token.Subject != "" {
		sum := sha256.Sum256([]byte(provider + ":" + token.Subject))
		subjectHash = hex.EncodeToString(sum[:])
	}
	tokenSum := sha256.Sum256([]byte(rawToken))

	return &Identity{
		Provider:      provider,
		Issuer:        token.Issuer,
		Subject:       token.Subject,
		SubjectHash:   subjectHash,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		GivenName:     givenName,
		FamilyName:    familyName,
		Picture:       picture,
		IssuedAt:      token.IssuedAt,
		ExpiresAt:     token.Expiry,
		RawClaims:     claims,
		TokenHash:     hex.EncodeToString(tokenSum[:]),
	}
}

func boolClaim(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	default:
		return false
	}
}
