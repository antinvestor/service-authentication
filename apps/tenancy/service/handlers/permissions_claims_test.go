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
	"testing"

	"github.com/pitabwire/frame/v2/security"
	"github.com/stretchr/testify/require"
)

func TestServiceAccountIDFromClaims(t *testing.T) {
	t.Parallel()

	require.Equal(t, "", serviceAccountIDFromClaims(nil))
	require.Equal(t, "", serviceAccountIDFromClaims(&security.AuthenticationClaims{}))

	// Preferred flat shape under Ext (Hydra mirrors access_token extras under ext).
	require.Equal(t, "sa-1", serviceAccountIDFromClaims(&security.AuthenticationClaims{
		Ext: map[string]any{"service_account_id": "sa-1"},
	}))

	// Legacy double-nested shape from nested "ext" map in token extras.
	require.Equal(t, "sa-legacy", serviceAccountIDFromClaims(&security.AuthenticationClaims{
		Ext: map[string]any{
			"ext": map[string]any{"service_account_id": "sa-legacy"},
		},
	}))

	// Prefer flat over nested.
	require.Equal(t, "sa-flat", serviceAccountIDFromClaims(&security.AuthenticationClaims{
		Ext: map[string]any{
			"service_account_id": "sa-flat",
			"ext":                map[string]any{"service_account_id": "sa-nested"},
		},
	}))
}
