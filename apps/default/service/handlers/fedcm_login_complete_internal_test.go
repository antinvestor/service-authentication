// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// readIDTokenSubject does NOT verify the JWT signature — it just extracts
// `sub` from the unverified payload. The freshness cache + AcceptLogin
// single-use enforce real security; this helper exists only for the
// follow-up subject lookup. These tests guard against a regression that
// would let an empty / malformed token slide through.

// jwtForTest builds a base64url-encoded JWT-like string with the given
// payload embedded. The signature is a fixed sentinel — readIDTokenSubject
// must not care what's there.
func jwtForTest(payload any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	body, _ := json.Marshal(payload)
	bodyEnc := base64.RawURLEncoding.EncodeToString(body)
	return header + "." + bodyEnc + ".sig"
}

func TestReadIDTokenSubject_HappyPath(t *testing.T) {
	tok := jwtForTest(map[string]any{"sub": "u-123", "iss": "https://hydra"})
	sub, err := readIDTokenSubject(tok)
	require.NoError(t, err)
	require.Equal(t, "u-123", sub)
}

func TestReadIDTokenSubject_RejectsNonJWT(t *testing.T) {
	_, err := readIDTokenSubject("not-a-jwt-string")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a JWT")
}

func TestReadIDTokenSubject_RejectsCorruptBase64(t *testing.T) {
	tok := "header." + strings.Repeat("?", 12) + ".sig"
	_, err := readIDTokenSubject(tok)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode JWT payload")
}

func TestReadIDTokenSubject_RejectsMissingSubClaim(t *testing.T) {
	tok := jwtForTest(map[string]any{"iss": "https://hydra", "aud": "abc"})
	_, err := readIDTokenSubject(tok)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing sub claim")
}

func TestReadIDTokenSubject_RejectsEmptySub(t *testing.T) {
	tok := jwtForTest(map[string]any{"sub": "", "iss": "https://hydra"})
	_, err := readIDTokenSubject(tok)
	require.Error(t, err)
}

// TestLoginEventStringProperty_TypeSafety guards the small typed accessor
// for the LoginEvent properties map. Cache round-trips the map as
// map[string]any so callers see various types; we want the accessor to
// return ("", false) on anything that isn't a string rather than
// panicking on a type assertion.
func TestLoginEventStringProperty_TypeSafety(t *testing.T) {
	tests := []struct {
		name    string
		props   map[string]any
		key     string
		wantStr string
		wantOK  bool
	}{
		{"present string", map[string]any{"k": "v"}, "k", "v", true},
		{"present non-string", map[string]any{"k": 42}, "k", "", false},
		{"present nil", map[string]any{"k": nil}, "k", "", false},
		{"missing key", map[string]any{"other": "v"}, "k", "", false},
		{"nil map", nil, "k", "", false},
		{"empty string value", map[string]any{"k": ""}, "k", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, ok := loginEventStringProperty(tc.props, tc.key)
			require.Equal(t, tc.wantStr, s)
			require.Equal(t, tc.wantOK, ok)
		})
	}
}
