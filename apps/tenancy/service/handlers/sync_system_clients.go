package handlers

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"

	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

const SyncClientsHTTPPath = "/_system/sync/clients"

func (prtSrv *PartitionServer) SynchronizeSystemClients(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	claims := security.ClaimsFromContext(ctx)
	if claims == nil || !slices.Contains(claims.GetRoles(), "system_internal") {
		rw.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(rw).Encode(map[string]string{"error": "system_internal role required"})
		return
	}

	ctx = security.SkipTenancyChecksOnClaims(ctx)

	cfg, ok := prtSrv.svc.Config().(*config.PartitionConfig)
	if !ok {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := map[string]any{}
	if !cfg.SynchronizeClients {

		response["triggered"] = false

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(rw).Encode(response)
		return
	}

	response["triggered"] = true

	pageStr := req.URL.Query().Get("page")
	page, err := strconv.Atoi(pageStr)
	if err != nil {
		page = 0
	}
	limitStr := req.URL.Query().Get("count")
	count, err := strconv.Atoi(limitStr)
	if err != nil {
		count = 50
	}

	query := data.NewSearchQuery(
		data.WithSearchLimit(count), data.WithSearchOffset(page))

	log := util.Log(ctx)

	err = business.ReQueuePrimaryPartitionsForSync(ctx, prtSrv.PartitionRepo, prtSrv.eventsMan, query)
	if err != nil {
		log.WithError(err).Error("internal service error synchronising partitions")
		response["partition_sync_error"] = err.Error()
	}

	// Sync clients — register/update Hydra OAuth2 clients for Client records
	clientQuery := data.NewSearchQuery(
		data.WithSearchLimit(count), data.WithSearchOffset(page))
	err = business.ReQueueClientsForHydraSync(ctx, prtSrv.ClientRepo, prtSrv.eventsMan, clientQuery)
	if err != nil {
		log.WithError(err).Error("internal service error synchronising clients on Hydra")
		response["client_hydra_sync_error"] = err.Error()
	}

	// Sync service accounts — register/update Hydra OAuth2 clients (legacy SAs without ClientRef)
	saQuery := data.NewSearchQuery(
		data.WithSearchLimit(count), data.WithSearchOffset(page))
	err = business.ReQueueServiceAccountsForHydraSync(ctx, prtSrv.ServiceAccountRepo, prtSrv.eventsMan, saQuery)
	if err != nil {
		log.WithError(err).Error("internal service error synchronising service accounts on Hydra")
		response["service_account_hydra_sync_error"] = err.Error()
	}

	// Also sync service account Keto tuples
	saAuthzQuery := data.NewSearchQuery(
		data.WithSearchLimit(count), data.WithSearchOffset(page))
	err = business.ReQueueServiceAccountsForSync(ctx, prtSrv.ServiceAccountRepo, prtSrv.eventsMan, saAuthzQuery)
	if err != nil {
		log.WithError(err).Error("internal service error synchronising service account authz")
		response["service_account_authz_sync_error"] = err.Error()
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(response)
}

func (prtSrv *PartitionServer) NewSecureRouterV1() *http.ServeMux {
	userServeMux := http.NewServeMux()

	userServeMux.HandleFunc(SyncClientsHTTPPath, prtSrv.SynchronizeSystemClients)

	return userServeMux
}
