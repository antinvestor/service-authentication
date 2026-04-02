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
	"encoding/json"
	"math"
	"net/http"
	"strconv"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

// defaultSyncLimit is large enough to cover all records in a single invocation.
// StableSearch internally batches at 50 rows, so memory usage stays bounded
// regardless of this value.
const defaultSyncLimit = math.MaxInt32

const SyncClientsHTTPPath = "/_system/sync/clients"

func (prtSrv *TenancyServer) SynchronizeSystemClients(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	log := util.Log(ctx)

	log.WithFields(map[string]any{
		"method": req.Method,
		"url":    req.URL.String(),
	}).Info("synchronise system clients called")

	prtSrv.executeSyncClients(rw, req)
}

// executeSyncClients performs the actual sync work. Called by both the
// authenticated handler and the internal (unauthenticated) handler.
func (prtSrv *TenancyServer) executeSyncClients(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	log := util.Log(ctx)

	// Skip tenancy checks on downstream queries so the sync can read all partitions.
	ctx = security.SkipTenancyChecksOnClaims(ctx)

	response := map[string]any{}
	response["triggered"] = true

	// Optional count parameter caps total records per category.
	// Default is unlimited — all records are synced.
	limit := defaultSyncLimit
	if limitStr := req.URL.Query().Get("count"); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}

	log.WithField("limit", limit).Debug("starting synchronisation")

	// Resolve bot profiles before syncing to Hydra. This ensures service
	// accounts seeded via SQL migrations get real profile_id values from
	// the profile service, so Hydra metadata and token subjects are correct.
	botResolution := prtSrv.resolveBotProfiles(ctx)
	if botResolution.Unresolved > 0 {
		response["unresolved_bot_profiles"] = botResolution.Unresolved
		log.WithField("unresolved", botResolution.Unresolved).
			Warn("some service accounts still have placeholder profile_ids")
	}
	if botResolution.Resolved > 0 {
		response["resolved_bot_profiles"] = botResolution.Resolved
	}

	syncQuery := func() *data.SearchQuery {
		return data.NewSearchQuery(data.WithSearchLimit(limit))
	}

	err := business.ReQueuePrimaryPartitionsForSync(ctx, prtSrv.PartitionRepo, prtSrv.eventsMan, syncQuery())
	if err != nil {
		log.WithError(err).Error("internal service error synchronising partitions")
		response["partition_sync_error"] = err.Error()
	}

	// Sync clients — register/update Hydra OAuth2 clients for Client records
	err = business.ReQueueClientsForHydraSync(ctx, prtSrv.ClientRepo, prtSrv.eventsMan, syncQuery())
	if err != nil {
		log.WithError(err).Error("internal service error synchronising clients on Hydra")
		response["client_hydra_sync_error"] = err.Error()
	}

	// Sync service accounts — register/update Hydra OAuth2 clients (legacy SAs without ClientRef)
	err = business.ReQueueServiceAccountsForHydraSync(ctx, prtSrv.ServiceAccountRepo, prtSrv.eventsMan, syncQuery())
	if err != nil {
		log.WithError(err).Error("internal service error synchronising service accounts on Hydra")
		response["service_account_hydra_sync_error"] = err.Error()
	}

	// Also sync service account Keto tuples
	err = business.ReQueueServiceAccountsForSync(ctx, prtSrv.ServiceAccountRepo, prtSrv.eventsMan, syncQuery())
	if err != nil {
		log.WithError(err).Error("internal service error synchronising service account authz")
		response["service_account_authz_sync_error"] = err.Error()
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(response)
}

func (prtSrv *TenancyServer) NewSecureRouterV1() *http.ServeMux {
	userServeMux := http.NewServeMux()

	userServeMux.HandleFunc(SyncClientsHTTPPath, prtSrv.SynchronizeSystemClients)

	return userServeMux
}

// NewInternalSyncHandler returns an http.Handler for the internal (unauthenticated)
// sync endpoint. This is used for bootstrap: syncing seeded clients to Hydra before
// any service can obtain tokens. Only accessible within the cluster — not exposed
// through the API gateway.
func (prtSrv *TenancyServer) NewInternalSyncHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		log := util.Log(req.Context())
		log.Debug("internal sync endpoint called")
		prtSrv.executeSyncClients(rw, req)
	})
}
