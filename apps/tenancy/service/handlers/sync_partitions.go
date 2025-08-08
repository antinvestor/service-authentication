package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/pitabwire/frame/datastore"
)

const syncPartitionsPath = "/_system/sync/partitions"

func (prtSrv *PartitionServer) SynchronizePartitions(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	cfg, ok := prtSrv.Service.Config().(*config.PartitionConfig)
	if !ok {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := map[string]any{}
	if !cfg.SynchronizePrimaryPartitions {

		response["triggered"] = false

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(rw).Encode(response)
	}

	response["triggered"] = true

	queryStr := req.URL.Query().Get("q")
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
	query, err := datastore.NewSearchQuery(
		ctx,
		queryStr, make(map[string]any),
		page, count)
	if err != nil {

		logger := prtSrv.Service.Log(ctx)
		logger.WithError(err).Error("could not create search query")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	business.ReQueuePrimaryPartitionsForSync(ctx, prtSrv.Service, query)

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(response)
}

func (prtSrv *PartitionServer) NewSecureRouterV1() *http.ServeMux {
	userServeMux := http.NewServeMux()

	userServeMux.HandleFunc(syncPartitionsPath, prtSrv.SynchronizePartitions)

	return userServeMux
}
