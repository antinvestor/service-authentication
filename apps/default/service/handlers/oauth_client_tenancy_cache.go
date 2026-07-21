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
	"strings"

	"github.com/pitabwire/frame/v2/cache"
	"github.com/pitabwire/util"
)

// oauthClientTenancyPayload caches tenant_id/partition_id by OAuth client_id
// in the shared Frame cache (multi-replica safe).
type oauthClientTenancyPayload struct {
	TenantID    string `json:"tenant_id"`
	PartitionID string `json:"partition_id"`
}

func (h *AuthServer) oauthClientTenancyCache() cache.Cache[string, oauthClientTenancyPayload] {
	raw := h.rawSharedCache()
	if raw == nil {
		return nil
	}
	return cache.NewGenericCache[string, oauthClientTenancyPayload](raw, func(clientID string) string {
		return oauthClientTenancyPrefix + strings.TrimSpace(clientID)
	})
}

func (h *AuthServer) getCachedOAuthClientTenancy(ctx context.Context, clientID string) (tenantID, partitionID string, ok bool) {
	c := h.oauthClientTenancyCache()
	if c == nil || strings.TrimSpace(clientID) == "" {
		return "", "", false
	}
	cacheCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loginCacheTimeout)
	defer cancel()
	p, found, err := c.Get(cacheCtx, clientID)
	if err != nil {
		util.Log(ctx).WithError(err).WithField("client_id", clientID).Debug("oauth client tenancy cache get failed")
		return "", "", false
	}
	if !found || !ValidTenancyPair(p.TenantID, p.PartitionID) {
		return "", "", false
	}
	return p.TenantID, p.PartitionID, true
}

func (h *AuthServer) setCachedOAuthClientTenancy(ctx context.Context, clientID, tenantID, partitionID string) {
	c := h.oauthClientTenancyCache()
	if c == nil || strings.TrimSpace(clientID) == "" || !ValidTenancyPair(tenantID, partitionID) {
		return
	}
	// Detach from spent soft-tenancy budgets so Valkey SET always has a full
	// loginCacheTimeout window.
	cacheCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loginCacheTimeout)
	defer cancel()
	if err := c.Set(cacheCtx, clientID, oauthClientTenancyPayload{
		TenantID:    tenantID,
		PartitionID: partitionID,
	}, oauthClientTenancyTTL); err != nil {
		util.Log(ctx).WithError(err).WithField("client_id", clientID).Debug("oauth client tenancy cache set failed")
	}
}
