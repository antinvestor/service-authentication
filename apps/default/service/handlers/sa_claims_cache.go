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
	"time"

	"github.com/pitabwire/frame/v2/cache"
	"github.com/pitabwire/util"
)

// stableSASessionID returns the durable session / login_event id for SA tokens.
// NATS-safe charset (alnum + underscore). JWT session_id and login_events.id
// must both equal this value when durable audit succeeds.
func stableSASessionID(clientID string) string {
	return "sa_sess_" + strings.TrimSpace(clientID)
}

// saClaimsCachePayload is stored via Frame GenericCache on the shared backend
// (memory / NATS JetStream KV / Valkey). Horizontal scale depends on the
// shared cache — no per-pod maps or mutexes.
type saClaimsCachePayload struct {
	Negative         bool   `json:"negative,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	ServiceAccountID string `json:"service_account_id,omitempty"`
	TenantID         string `json:"tenant_id,omitempty"`
	PartitionID      string `json:"partition_id,omitempty"`
	ProfileID        string `json:"profile_id,omitempty"`
	Type             string `json:"type,omitempty"`
	AccessID         string `json:"access_id,omitempty"`
}

func (h *AuthServer) saClaimsCache() cache.Cache[string, saClaimsCachePayload] {
	raw := h.rawSharedCache()
	if raw == nil {
		return nil
	}
	return cache.NewGenericCache[string, saClaimsCachePayload](raw, func(clientID string) string {
		return saClaimsCachePrefix + strings.TrimSpace(clientID)
	})
}

func (h *AuthServer) getCachedServiceAccount(ctx context.Context, clientID string) (*serviceAccountAuthContext, bool, bool) {
	c := h.saClaimsCache()
	if c == nil || strings.TrimSpace(clientID) == "" {
		return nil, false, false
	}
	p, ok, err := c.Get(ctx, clientID)
	if err != nil {
		util.Log(ctx).WithError(err).WithField("client_id", clientID).Debug("sa claims cache get failed")
		return nil, false, false
	}
	if !ok {
		return nil, false, false
	}
	if p.Negative {
		return nil, true, true
	}
	return &serviceAccountAuthContext{
		ClientID:         p.ClientID,
		ServiceAccountID: p.ServiceAccountID,
		TenantID:         p.TenantID,
		PartitionID:      p.PartitionID,
		ProfileID:        p.ProfileID,
		Type:             p.Type,
		AccessID:         p.AccessID,
	}, false, true
}

func (h *AuthServer) setCachedServiceAccount(ctx context.Context, clientID string, sa *serviceAccountAuthContext, ttl time.Duration) {
	c := h.saClaimsCache()
	if c == nil || strings.TrimSpace(clientID) == "" || sa == nil {
		return
	}
	p := saClaimsCachePayload{
		ClientID:         sa.ClientID,
		ServiceAccountID: sa.ServiceAccountID,
		TenantID:         sa.TenantID,
		PartitionID:      sa.PartitionID,
		ProfileID:        sa.ProfileID,
		Type:             sa.Type,
		AccessID:         sa.AccessID,
	}
	if err := c.Set(ctx, clientID, p, ttl); err != nil {
		util.Log(ctx).WithError(err).WithField("client_id", clientID).Debug("sa claims cache set failed")
	}
}

func (h *AuthServer) setCachedServiceAccountNegative(ctx context.Context, clientID string, ttl time.Duration) {
	c := h.saClaimsCache()
	if c == nil || strings.TrimSpace(clientID) == "" {
		return
	}
	if err := c.Set(ctx, clientID, saClaimsCachePayload{Negative: true}, ttl); err != nil {
		util.Log(ctx).WithError(err).WithField("client_id", clientID).Debug("sa claims negative cache set failed")
	}
}
