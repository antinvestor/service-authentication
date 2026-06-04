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

package events

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnsureFedCMCallbackRedirectURI(t *testing.T) {
	t.Setenv("FEDCM_PUBLIC_ORIGIN", "https://accounts.example.com")
	const callback = "https://accounts.example.com/_internal/fedcm-callback"

	t.Run("appends for authorization_code clients", func(t *testing.T) {
		got := ensureFedCMCallbackRedirectURI(
			[]string{"https://app.example.com/cb"},
			[]string{"authorization_code", "refresh_token"},
		)
		require.Equal(t, []string{"https://app.example.com/cb", callback}, got)
	})

	t.Run("skips non authorization_code clients", func(t *testing.T) {
		in := []string{"https://app.example.com/cb"}
		got := ensureFedCMCallbackRedirectURI(in, []string{"client_credentials"})
		require.Equal(t, in, got)
	})

	t.Run("does not duplicate when already present", func(t *testing.T) {
		in := []string{callback}
		got := ensureFedCMCallbackRedirectURI(in, []string{"authorization_code"})
		require.Equal(t, in, got)
		require.Len(t, got, 1)
	})

	t.Run("matches case-insensitively without duplicating", func(t *testing.T) {
		in := []string{"AUTHORIZATION_CODE-callback-placeholder", callback}
		got := ensureFedCMCallbackRedirectURI(in, []string{"AUTHORIZATION_CODE"})
		require.Len(t, got, 2)
	})
}

func TestEnsureFedCMCallbackRedirectURIDefaultOrigin(t *testing.T) {
	t.Setenv("FEDCM_PUBLIC_ORIGIN", "")
	got := ensureFedCMCallbackRedirectURI(nil, []string{"authorization_code"})
	require.Equal(t, []string{defaultFedCMPublicOrigin + "/_internal/fedcm-callback"}, got)
}

func TestContainsString(t *testing.T) {
	require.True(t, containsString([]string{"a", "b"}, "b"))
	require.True(t, containsString([]string{" Authorization_Code "}, "authorization_code"))
	require.False(t, containsString([]string{"a"}, "c"))
	require.False(t, containsString(nil, "x"))
}
