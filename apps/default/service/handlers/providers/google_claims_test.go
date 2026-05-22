// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package providers_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/antinvestor/service-authentication/apps/default/service/handlers/providers"
)

// TestValidateGoogleClaims_HappyPath asserts that the canonical Google
// id_token claim shape is accepted and the AuthenticatedUser is populated
// from the expected claim keys.
func TestValidateGoogleClaims_HappyPath(t *testing.T) {
	claims := map[string]any{
		"sub":            "1234567890",
		"email":          "jane@example.com",
		"email_verified": true,
		"name":           "Jane Doe",
		"picture":        "https://lh3.googleusercontent.com/a/abc",
		"nonce":          "expected-nonce",
	}

	user, err := providers.ValidateGoogleClaims(claims, "expected-nonce")
	require.NoError(t, err)
	require.Equal(t, "jane@example.com", user.Contact)
	require.Equal(t, "Jane Doe", user.Name)
	require.Equal(t, "https://lh3.googleusercontent.com/a/abc", user.AvatarURL)
	require.Equal(t, claims, user.Raw, "Raw must carry the full claim set for downstream use")
}

// TestValidateGoogleClaims_NoNonceCheckWhenExpectedEmpty: the OAuth code
// path does its own nonce check inside go-oidc; the FedCM path passes a
// server-bound nonce. When expectedNonce is empty (legacy / nonceless
// flows) the validator must not enforce it.
func TestValidateGoogleClaims_NoNonceCheckWhenExpectedEmpty(t *testing.T) {
	claims := map[string]any{
		"email":          "a@example.com",
		"email_verified": true,
	}
	user, err := providers.ValidateGoogleClaims(claims, "")
	require.NoError(t, err)
	require.Equal(t, "a@example.com", user.Contact)
}

// TestValidateGoogleClaims_NonceMismatchRejected is the core defence
// against an attacker swapping in an unrelated Google id_token. This test
// must keep passing — if nonce checking silently degrades, FedCM
// completions could be replayed across sessions.
func TestValidateGoogleClaims_NonceMismatchRejected(t *testing.T) {
	claims := map[string]any{
		"email":          "a@example.com",
		"email_verified": true,
		"nonce":          "wrong-nonce",
	}
	_, err := providers.ValidateGoogleClaims(claims, "expected-nonce")
	require.Error(t, err)
	require.Contains(t, err.Error(), "nonce verification failed")
}

// TestValidateGoogleClaims_NonceMissingRejectedWhenExpected: if we issued
// a nonce, an id_token without one is malformed for our flow. Must reject.
func TestValidateGoogleClaims_NonceMissingRejectedWhenExpected(t *testing.T) {
	claims := map[string]any{
		"email":          "a@example.com",
		"email_verified": true,
	}
	_, err := providers.ValidateGoogleClaims(claims, "expected-nonce")
	require.Error(t, err)
	require.Contains(t, err.Error(), "nonce verification failed")
}

// TestValidateGoogleClaims_NonceTimingSafe: the comparison is via
// crypto/subtle, so different lengths and same-length-different-content
// must both reject identically. This protects against timing oracles on
// the nonce.
func TestValidateGoogleClaims_NonceTimingSafe(t *testing.T) {
	for _, mismatched := range []string{
		"short",
		"this-is-much-longer-than-the-expected-value",
		strings.Repeat("x", len("expected-nonce")), // same length, all wrong
		"",
	} {
		claims := map[string]any{
			"email":          "a@example.com",
			"email_verified": true,
			"nonce":          mismatched,
		}
		_, err := providers.ValidateGoogleClaims(claims, "expected-nonce")
		require.Error(t, err, "mismatched nonce %q must reject", mismatched)
	}
}

// TestValidateGoogleClaims_EmailVerifiedFalseRejected is the defence against
// auto-binding into an existing profile keyed on an unverified email. If
// Google ever issues an id_token with email_verified=false, the auth
// service must NOT silently merge the session with that profile.
func TestValidateGoogleClaims_EmailVerifiedFalseRejected(t *testing.T) {
	claims := map[string]any{
		"email":          "a@example.com",
		"email_verified": false,
	}
	_, err := providers.ValidateGoogleClaims(claims, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "email is not verified")
}

// TestValidateGoogleClaims_EmailVerifiedStringTrueAccepted: some legacy
// JWT serialisers stringify booleans. Accept "true" / reject "false".
func TestValidateGoogleClaims_EmailVerifiedStringTrueAccepted(t *testing.T) {
	claims := map[string]any{
		"email":          "a@example.com",
		"email_verified": "true",
	}
	user, err := providers.ValidateGoogleClaims(claims, "")
	require.NoError(t, err)
	require.Equal(t, "a@example.com", user.Contact)
}

func TestValidateGoogleClaims_EmailVerifiedStringFalseRejected(t *testing.T) {
	claims := map[string]any{
		"email":          "a@example.com",
		"email_verified": "false",
	}
	_, err := providers.ValidateGoogleClaims(claims, "")
	require.Error(t, err)
}

// TestValidateGoogleClaims_EmailVerifiedAbsentAccepted: when the claim is
// missing entirely we default to true (verified). This matches Google's
// historical behaviour where the claim was optional for @gmail.com
// accounts. If we ever want to tighten this to "require explicit true",
// flip the default in ValidateGoogleClaims and update this test.
func TestValidateGoogleClaims_EmailVerifiedAbsentAccepted(t *testing.T) {
	claims := map[string]any{
		"email": "a@example.com",
		"sub":   "u1",
	}
	user, err := providers.ValidateGoogleClaims(claims, "")
	require.NoError(t, err)
	require.Equal(t, "a@example.com", user.Contact)
}

// TestValidateGoogleClaims_NilClaimsRejected: defensive guard so that a
// caller passing nil never produces an "empty success".
func TestValidateGoogleClaims_NilClaimsRejected(t *testing.T) {
	_, err := providers.ValidateGoogleClaims(nil, "")
	require.Error(t, err)
}

// TestValidateGoogleClaims_NonStringClaimsCoercedToEmpty checks that
// surprising claim shapes (e.g. email as a number) don't produce a panic
// or a non-empty Contact populated with garbage.
func TestValidateGoogleClaims_NonStringClaimsCoercedToEmpty(t *testing.T) {
	claims := map[string]any{
		"email":          12345, // wrong type
		"email_verified": true,
	}
	user, err := providers.ValidateGoogleClaims(claims, "")
	require.NoError(t, err)
	require.Empty(t, user.Contact, "non-string email must coerce to empty so downstream contact-resolution fails fast")
}
