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

	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/pitabwire/frame/v2/cache"
	"github.com/stretchr/testify/require"
)

func TestSAClaimsCache_SharedRawCacheRoundTrip(t *testing.T) {
	t.Parallel()

	raw := cache.NewInMemoryCache()
	t.Cleanup(func() { _ = raw.Close() })

	mgr := cache.NewManager()
	mgr.AddCache("defaultCache", raw)

	h := &AuthServer{
		cacheMan: mgr,
		config:   &aconfig.AuthenticationConfig{CacheName: "defaultCache"},
	}

	ctx := context.Background()
	sa := &serviceAccountAuthContext{
		ClientID:         "svc-1",
		ServiceAccountID: "sa-1",
		TenantID:         "t1",
		PartitionID:      "p1",
		ProfileID:        "prof-1",
		Type:             "internal",
		AccessID:         "a1",
	}

	h.setCachedServiceAccount(ctx, "svc-1", sa, time.Minute)
	got, neg, ok := h.getCachedServiceAccount(ctx, "svc-1")
	require.True(t, ok)
	require.False(t, neg)
	require.Equal(t, "prof-1", got.ProfileID)
	require.Equal(t, "internal", got.Type)

	h.setCachedServiceAccountNegative(ctx, "missing", time.Minute)
	_, neg, ok = h.getCachedServiceAccount(ctx, "missing")
	require.True(t, ok)
	require.True(t, neg)
}
