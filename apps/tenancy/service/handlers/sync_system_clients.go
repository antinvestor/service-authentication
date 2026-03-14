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

func (prtSrv *PartitionServer) SynchronizeSystemClients(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	log := util.Log(ctx)

	log.WithField("method", req.Method).
		WithField("url", req.URL.String()).
		Info("synchronise system clients called")

	if err := prtSrv.authz.CanPartitionManage(ctx); err != nil {
		log.WithError(err).Error("failed to authorize partition management")

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(rw).Encode(map[string]string{"error": "failed to authorize partition management"})
		return
	}

	prtSrv.executeSyncClients(rw, req)
}

// executeSyncClients performs the actual sync work. Called by both the
// authenticated handler and the internal (unauthenticated) handler.
func (prtSrv *PartitionServer) executeSyncClients(rw http.ResponseWriter, req *http.Request) {
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

	log.WithField("limit", limit).Info("starting synchronisation")

	syncQuery := func() *data.SearchQuery {
		return data.NewSearchQuery(data.WithSearchLimit(limit))
	}

	err := business.ReQueuePrimaryPartitionsForSync(ctx, prtSrv.PartitionRepo, prtSrv.eventsMan, syncQuery())
	if err != nil {
		log.WithError(err).Error("internal service error synchronising partitions")
		response["partition_sync_error"] = err.Error()
	} else {
		log.Info("partition sync queued successfully")
	}

	// Sync clients — register/update Hydra OAuth2 clients for Client records
	err = business.ReQueueClientsForHydraSync(ctx, prtSrv.ClientRepo, prtSrv.eventsMan, syncQuery())
	if err != nil {
		log.WithError(err).Error("internal service error synchronising clients on Hydra")
		response["client_hydra_sync_error"] = err.Error()
	} else {
		log.Info("client hydra sync queued successfully")
	}

	// Sync service accounts — register/update Hydra OAuth2 clients (legacy SAs without ClientRef)
	err = business.ReQueueServiceAccountsForHydraSync(ctx, prtSrv.ServiceAccountRepo, prtSrv.eventsMan, syncQuery())
	if err != nil {
		log.WithError(err).Error("internal service error synchronising service accounts on Hydra")
		response["service_account_hydra_sync_error"] = err.Error()
	} else {
		log.Info("service account hydra sync queued successfully")
	}

	// Also sync service account Keto tuples
	err = business.ReQueueServiceAccountsForSync(ctx, prtSrv.ServiceAccountRepo, prtSrv.eventsMan, syncQuery())
	if err != nil {
		log.WithError(err).Error("internal service error synchronising service account authz")
		response["service_account_authz_sync_error"] = err.Error()
	} else {
		log.Info("service account authz sync queued successfully")
	}

	log.Info("synchronise system clients completed")

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(response)
}

func (prtSrv *PartitionServer) NewSecureRouterV1() *http.ServeMux {
	userServeMux := http.NewServeMux()

	userServeMux.HandleFunc(SyncClientsHTTPPath, prtSrv.SynchronizeSystemClients)

	return userServeMux
}

// NewInternalSyncHandler returns an http.Handler for the internal (unauthenticated)
// sync endpoint. This is used for bootstrap: syncing seeded clients to Hydra before
// any service can obtain tokens. Only accessible within the cluster — not exposed
// through the API gateway.
func (prtSrv *PartitionServer) NewInternalSyncHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		log := util.Log(req.Context())
		log.Info("internal sync endpoint called (unauthenticated)")
		prtSrv.executeSyncClients(rw, req)
	})
}
