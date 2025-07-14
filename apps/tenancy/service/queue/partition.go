package queue

import (
	"context"
	"encoding/json"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"

	"github.com/pitabwire/frame"
)

type PartitionSyncQueueHandler struct {
	Service *frame.Service
}

func (psq *PartitionSyncQueueHandler) Handle(ctx context.Context, _ map[string]string, payload []byte) error {
	partition := &models.Partition{}
	err := json.Unmarshal(payload, &partition) // Fixed: Added & to properly pass pointer for json.Unmarshal
	if err != nil {
		return err
	}

	return business.SyncPartitionOnHydra(ctx, psq.Service, partition)
}
