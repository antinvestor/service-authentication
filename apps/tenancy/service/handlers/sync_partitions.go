package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/security"
)

const SyncPartitionsHTTPPath = "/_system/sync/partitions"

func (prtSrv *PartitionServer) SynchronizePartitions(rw http.ResponseWriter, req *http.Request) {
	ctx := security.SkipTenancyChecksOnClaims(req.Context())

	cfg, ok := prtSrv.svc.Config().(*config.PartitionConfig)
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
		return
	}

	response["triggered"] = true

	queryStr := req.URL.Query().Get("q")
	_ = queryStr
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
	err = business.ReQueuePrimaryPartitionsForSync(ctx, prtSrv.PartitionRepo, prtSrv.eventsMan, query)
	if err != nil {

		rw.Header().Set("Content-Type", "application/json")

		log := prtSrv.svc.Log(ctx).WithError(err)
		log.Error("internal service error synchronising partitions")

		_, err = fmt.Fprintf(rw, " internal processing err message: %s", err.Error())
		if err != nil {
			log.Error("could not write error to response")
		}

	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(response)
}

func (prtSrv *PartitionServer) NewSecureRouterV1() *http.ServeMux {
	userServeMux := http.NewServeMux()

	userServeMux.HandleFunc(SyncPartitionsHTTPPath, prtSrv.SynchronizePartitions)

	return userServeMux
}
