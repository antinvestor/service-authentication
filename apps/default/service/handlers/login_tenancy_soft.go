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
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	hydraclientgo "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/util"
)

// tenancySource labels for structured logs (and future metrics).
const (
	tenancySourceLoginRequestMeta = "login_request_meta"
	tenancySourceHydraAdmin       = "hydra_admin"
	tenancySourceTenancy          = "tenancy"
	tenancySourceNone             = "none"
)

// tenancyIDsFromOAuth2Client reads tenant_id/partition_id from a Hydra OAuth2
// client object (e.g. embedded on OAuth2LoginRequest). Best-effort only.
func tenancyIDsFromOAuth2Client(cli *hydraclientgo.OAuth2Client) (tenantID, partitionID string, ok bool) {
	if cli == nil {
		return "", "", false
	}
	metaMap := metadataAsMap(cli.GetMetadata())
	if metaMap == nil {
		return "", "", false
	}
	tenantID = metaString(metaMap, "tenant_id")
	partitionID = metaString(metaMap, "partition_id")
	if !ValidTenancyPair(tenantID, partitionID) {
		return "", "", false
	}
	return tenantID, partitionID, true
}

func applyLoginEventTenancy(loginEvt *models.LoginEvent, tenantID, partitionID string) {
	if loginEvt == nil {
		return
	}
	loginEvt.TenantID = tenantID
	loginEvt.PartitionID = partitionID
}

const tenancySourceCache = "valkey_map"

// softEnrichLoginEventTenancy never fails the login page. Resolution order:
//  1. Embedded client metadata on the login request (free optimization)
//  2. Shared Frame cache map auth_oauth_client_tenancy_* (multi-replica)
//  3. Hydra admin GetOAuth2Client with a short timeout (reliable primary)
//  4. Tenancy service resolve with a short timeout (best-effort)
//
// Missing tenancy is OK here — verification and consent re-resolve with strong budgets.
func (h *AuthServer) softEnrichLoginEventTenancy(
	ctx context.Context,
	loginEvt *models.LoginEvent,
	loginReq *hydraclientgo.OAuth2LoginRequest,
) string {
	if loginEvt == nil {
		return tenancySourceNone
	}
	log := util.Log(ctx).WithField("login_event_id", loginEvt.GetID())
	start := time.Now()

	budgetCtx, cancel := context.WithTimeout(ctx, loginSoftTenancyBudget)
	defer cancel()

	finish := func(tid, pid, source string) string {
		applyLoginEventTenancy(loginEvt, tid, pid)
		if loginEvt.ClientID != "" {
			h.setCachedOAuthClientTenancy(budgetCtx, loginEvt.ClientID, tid, pid)
		}
		_ = h.setLoginEventToCache(budgetCtx, loginEvt)
		log.WithFields(map[string]any{
			"tenancy_source": source,
			"duration_ms":    time.Since(start).Milliseconds(),
		}).Debug("login event soft-enriched with tenancy")
		return source
	}

	if loginReq != nil {
		cli := loginReq.GetClient()
		if tid, pid, ok := tenancyIDsFromOAuth2Client(&cli); ok {
			return finish(tid, pid, tenancySourceLoginRequestMeta)
		}
	}

	if loginEvt.ClientID != "" {
		if tid, pid, ok := h.getCachedOAuthClientTenancy(budgetCtx, loginEvt.ClientID); ok {
			applyLoginEventTenancy(loginEvt, tid, pid)
			_ = h.setLoginEventToCache(budgetCtx, loginEvt)
			log.WithFields(map[string]any{
				"tenancy_source": tenancySourceCache,
				"duration_ms":    time.Since(start).Milliseconds(),
			}).Debug("login event soft-enriched with tenancy")
			return tenancySourceCache
		}
	}

	if loginEvt.ClientID != "" {
		adminCtx, adminCancel := context.WithTimeout(budgetCtx, loginHydraAdminTimeout)
		tid, pid, err := h.tenancyIDsFromHydraClient(adminCtx, loginEvt.ClientID)
		adminCancel()
		if err == nil {
			return finish(tid, pid, tenancySourceHydraAdmin)
		}
		if budgetCtx.Err() == nil {
			log.WithError(err).Debug("hydra admin tenancy soft-enrich failed")
		}
	}

	if loginEvt.ClientID != "" && budgetCtx.Err() == nil {
		tenCtx, tenCancel := context.WithTimeout(budgetCtx, loginTenancySoftTimeout)
		part, err := h.resolvePartitionByClientID(tenCtx, loginEvt.ClientID)
		tenCancel()
		if err == nil && part != nil && ValidTenancyPair(part.GetTenantId(), part.GetId()) {
			return finish(part.GetTenantId(), part.GetId(), tenancySourceTenancy)
		}
		if err != nil && budgetCtx.Err() == nil {
			log.WithError(err).Debug("tenancy service soft-enrich failed")
		}
	}

	log.WithFields(map[string]any{
		"tenancy_source": tenancySourceNone,
		"duration_ms":    time.Since(start).Milliseconds(),
	}).Debug("login event rendered without tenancy enrichment")
	return tenancySourceNone
}
