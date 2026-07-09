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

	"github.com/stretchr/testify/require"
)

func TestValidTenancyPair(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		tenantID    string
		partitionID string
		want        bool
	}{
		{name: "both set", tenantID: "t1", partitionID: "p1", want: true},
		{name: "trimmed both set", tenantID: " t1 ", partitionID: " p1 ", want: true},
		{name: "only tenant", tenantID: "t1", partitionID: "", want: false},
		{name: "only partition", tenantID: "", partitionID: "p1", want: false},
		{name: "both empty", tenantID: "", partitionID: "", want: false},
		{name: "whitespace only", tenantID: "  ", partitionID: "  ", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, ValidTenancyPair(tc.tenantID, tc.partitionID))
		})
	}
}

func TestClaimsHaveTenancyPair(t *testing.T) {
	t.Parallel()

	require.True(t, ClaimsHaveTenancyPair(map[string]any{
		"tenant_id":    "t1",
		"partition_id": "p1",
	}))
	require.False(t, ClaimsHaveTenancyPair(map[string]any{
		"tenant_id": "t1",
	}))
	require.False(t, ClaimsHaveTenancyPair(map[string]any{
		"partition_id": "p1",
	}))
	require.False(t, ClaimsHaveTenancyPair(nil))
}
