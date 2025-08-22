package queue

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
)

type PartitionSyncQueueHandler struct {
	service             *frame.Service
	partitionRepository repository.PartitionRepository
}

func NewPartitionSyncQueueHandler(svc *frame.Service) frame.SubscribeWorker {
	return &PartitionSyncQueueHandler{
		service:             svc,
		partitionRepository: repository.NewPartitionRepository(svc),
	}
}

func (psq *PartitionSyncQueueHandler) Handle(ctx context.Context, _ map[string]string, payload []byte) error {
	partitionID := string(payload)

	partition, err := psq.partitionRepository.GetByID(ctx, partitionID)
	if err != nil {
		return err
	}

	return business.SyncPartitionOnHydra(ctx, psq.service, partition)
}
