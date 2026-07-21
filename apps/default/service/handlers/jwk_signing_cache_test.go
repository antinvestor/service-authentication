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

package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestJWKSigningCache_GetSet(t *testing.T) {
	c := newJWKSigningCache()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, _, ok := c.get(defaultJWKSetName)
	require.False(t, ok)

	c.set(defaultJWKSetName, key, "kid-1", time.Minute)
	signer, kid, ok := c.get(defaultJWKSetName)
	require.True(t, ok)
	require.Equal(t, "kid-1", kid)
	require.Equal(t, key, signer)
}

func TestJWKSigningCache_Expires(t *testing.T) {
	c := newJWKSigningCache()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	c.set(defaultJWKSetName, key, "kid-1", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	_, _, ok := c.get(defaultJWKSetName)
	require.False(t, ok, "expired entry must miss")
}

func TestIsDefinitiveServiceAccountMiss(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"deadline", contextDeadlineErr(), false},
		{"timeout wording", errString("Get client: context deadline exceeded"), false},
		{"connection refused", errString("dial tcp: connection refused"), false},
		{"not found", errString("oauth2 client not found"), true},
		{"does not exist", errString("The requested OAuth 2.0 Client does not exist"), true},
		{"metadata incomplete", errString("hydra client metadata incomplete for client_id x"), true},
		{"unknown", errString("something weird"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, isDefinitiveServiceAccountMiss(tc.err))
		})
	}
}

func contextDeadlineErr() error {
	return context.DeadlineExceeded
}

type stringError string

func (e stringError) Error() string { return string(e) }

func errString(s string) error { return stringError(s) }
