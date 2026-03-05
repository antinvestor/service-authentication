package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/workerpool"
)

type clientRepository struct {
	datastore.BaseRepository[*models.Client]
}

func (r *clientRepository) GetByClientID(ctx context.Context, clientID string) (*models.Client, error) {
	client := &models.Client{}
	err := r.Pool().DB(ctx, true).First(client, "client_id = ?", clientID).Error
	return client, err
}

func (r *clientRepository) ListByPartition(ctx context.Context, partitionID string) ([]*models.Client, error) {
	var clients []*models.Client
	err := r.Pool().DB(ctx, true).Where("partition_id = ?", partitionID).Find(&clients).Error
	return clients, err
}

func NewClientRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) ClientRepository {
	return &clientRepository{
		BaseRepository: datastore.NewBaseRepository[*models.Client](
			ctx, dbPool, workMan, func() *models.Client { return &models.Client{} },
		),
	}
}
