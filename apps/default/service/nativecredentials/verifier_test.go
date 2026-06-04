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
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
)

func TestCanonicalIssuer(t *testing.T) {
	cases := map[string]string{
		"  https://accounts.google.com/ ": GoogleIssuer,
		"accounts.google.com":             GoogleIssuerShort,
		"ACCOUNTS.GOOGLE.COM":             GoogleIssuerShort,
		"https://appleid.apple.com/":      AppleIssuer,
		"":                                "",
		"https://other.example.com//":     "https://other.example.com",
	}
	for in, want := range cases {
		require.Equalf(t, want, canonicalIssuer(in), "input %q", in)
	}
}

func TestProviderForIssuer(t *testing.T) {
	p, disc, err := providerForIssuer(GoogleIssuer)
	require.NoError(t, err)
	require.Equal(t, ProviderGoogle, p)
	require.Equal(t, GoogleIssuer, disc)

	p, disc, err = providerForIssuer(GoogleIssuerShort)
	require.NoError(t, err)
	require.Equal(t, ProviderGoogle, p)
	require.Equal(t, GoogleIssuer, disc)

	p, disc, err = providerForIssuer(AppleIssuer)
	require.NoError(t, err)
	require.Equal(t, ProviderApple, p)
	require.Equal(t, AppleIssuer, disc)

	_, _, err = providerForIssuer("https://evil.example.com")
	require.Error(t, err)
}

func TestBoolClaim(t *testing.T) {
	require.True(t, boolClaim(true))
	require.True(t, boolClaim("true"))
	require.True(t, boolClaim("TRUE"))
	require.False(t, boolClaim("1"))
	require.False(t, boolClaim(false))
	require.False(t, boolClaim(nil))
	require.False(t, boolClaim(1))
}

func TestIdentityFromClaims(t *testing.T) {
	issuedAt := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	token := &oidc.IDToken{
		Issuer:   GoogleIssuer,
		Subject:  "sub-123",
		IssuedAt: issuedAt,
		Expiry:   issuedAt.Add(time.Hour),
	}
	claims := map[string]any{
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Test User",
		"given_name":     "Test",
		"family_name":    "User",
		"picture":        "https://img.example.com/a.png",
	}

	id := identityFromClaims(ProviderGoogle, token, claims, "raw-token")
	require.Equal(t, ProviderGoogle, id.Provider)
	require.Equal(t, "sub-123", id.Subject)
	require.Equal(t, "user@example.com", id.Email)
	require.True(t, id.EmailVerified)
	require.Equal(t, "Test User", id.Name)
	require.Equal(t, issuedAt, id.IssuedAt)

	wantSubjectHash := sha256.Sum256([]byte(ProviderGoogle + ":sub-123"))
	require.Equal(t, hex.EncodeToString(wantSubjectHash[:]), id.SubjectHash)

	wantTokenHash := sha256.Sum256([]byte("raw-token"))
	require.Equal(t, hex.EncodeToString(wantTokenHash[:]), id.TokenHash)
}

func TestIdentityFromClaimsEmptySubjectHasNoHash(t *testing.T) {
	id := identityFromClaims(ProviderApple, &oidc.IDToken{Issuer: AppleIssuer}, map[string]any{}, "raw")
	require.Empty(t, id.SubjectHash)
	require.False(t, id.EmailVerified)
}

func TestVerifyIDTokenInputValidation(t *testing.T) {
	v := NewVerifier()
	ctx := t.Context()

	_, err := v.VerifyIDToken(ctx, "", "aud", "tok")
	require.ErrorContains(t, err, "subject_issuer is required")

	_, err = v.VerifyIDToken(ctx, GoogleIssuer, "", "tok")
	require.ErrorContains(t, err, "audience is not configured")

	_, err = v.VerifyIDToken(ctx, GoogleIssuer, "aud", "")
	require.ErrorContains(t, err, "subject_token is required")

	_, err = v.VerifyIDToken(ctx, "https://evil.example.com", "aud", "tok")
	require.ErrorContains(t, err, "unsupported subject_issuer")
}
