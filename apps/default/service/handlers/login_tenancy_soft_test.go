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
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	hydraclientgo "github.com/ory/hydra-client-go/v25"
	"github.com/stretchr/testify/require"
)

func TestTenancyIDsFromOAuth2Client(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		meta    map[string]any
		nilCli  bool
		wantOK  bool
		wantTID string
		wantPID string
	}{
		{
			name: "complete metadata",
			meta: map[string]any{
				"tenant_id":    "tenant-a",
				"partition_id": "part-a",
			},
			wantOK:  true,
			wantTID: "tenant-a",
			wantPID: "part-a",
		},
		{
			name:   "incomplete metadata",
			meta:   map[string]any{"tenant_id": "tenant-a"},
			wantOK: false,
		},
		{
			name:   "nil client",
			nilCli: true,
			wantOK: false,
		},
		{
			name:   "empty metadata map",
			meta:   map[string]any{},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.nilCli {
				_, _, ok := tenancyIDsFromOAuth2Client(nil)
				require.Equal(t, tt.wantOK, ok)
				return
			}
			cli := hydraclientgo.NewOAuth2Client()
			if tt.meta != nil {
				cli.SetMetadata(tt.meta)
			}
			tid, pid, ok := tenancyIDsFromOAuth2Client(cli)
			require.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				require.Equal(t, tt.wantTID, tid)
				require.Equal(t, tt.wantPID, pid)
			}
		})
	}
}

func TestSoftEnrichLoginEventTenancyFromLoginRequestMeta(t *testing.T) {
	t.Parallel()

	h := &AuthServer{}
	cli := hydraclientgo.NewOAuth2Client()
	cli.SetClientId("client-1")
	cli.SetMetadata(map[string]any{
		"tenant_id":    "t1",
		"partition_id": "p1",
	})
	loginReq := hydraclientgo.NewOAuth2LoginRequest("chal", *cli, "http://example", false, "")
	ev := &models.LoginEvent{ClientID: "client-1"}
	ev.ID = "evt-1"

	src := h.softEnrichLoginEventTenancy(context.Background(), ev, loginReq)
	require.Equal(t, tenancySourceLoginRequestMeta, src)
	require.Equal(t, "t1", ev.TenantID)
	require.Equal(t, "p1", ev.PartitionID)
}

func TestSoftEnrichLoginEventTenancyNoneWithoutBackends(t *testing.T) {
	t.Parallel()

	h := &AuthServer{}
	ev := &models.LoginEvent{ClientID: "missing-client"}
	ev.ID = "evt-2"
	// No hydra client, no tenancy client — soft path must not panic or hang.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	src := h.softEnrichLoginEventTenancy(ctx, ev, nil)
	require.Equal(t, tenancySourceNone, src)
	require.Empty(t, ev.TenantID)
}

func TestStableSASessionID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, want string
	}{
		{"service-savings", "sa_sess_service-savings"},
		{"  x  ", "sa_sess_x"},
		{"", "sa_sess_"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, stableSASessionID(tt.in))
		})
	}
}

func TestRateLimitBucketKeyNATSSafe(t *testing.T) {
	t.Parallel()
	key := rateLimitBucketKey("1.2.3.4", time.Hour, time.Unix(1_700_000_000, 0).UTC())
	require.Contains(t, key, rateLimitCachePrefix)
	require.NotContains(t, key, ":")
	for _, r := range key {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '/' || r == '=' || r == '.'
		require.Truef(t, ok, "invalid rune %q in key %q", r, key)
	}
}

func TestBuildServiceAccountClaimsStableSession(t *testing.T) {
	t.Parallel()
	sessionID := stableSASessionID("svc-1")
	claims, err := buildServiceAccountClaims(sessionID, &serviceAccountAuthContext{
		ServiceAccountID: "sa-1",
		TenantID:         "t1",
		PartitionID:      "p1",
		ProfileID:        "prof-1",
	}, "access-1", []string{"internal"})
	require.NoError(t, err)
	require.Equal(t, sessionID, claims["session_id"])
	require.Equal(t, sessionID, claims["login_event_id"])
}
