package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/workerpool"
)

type accessRepository struct {
	datastore.BaseRepository[*models.Access]
}

func (ar *accessRepository) GetByPartitionAndProfile(
	ctx context.Context,
	partitionID string,
	profileID string,
) (*models.Access, error) {
	access := &models.Access{}
	err := ar.Pool().DB(ctx, true).First(access, " partition_id = ? AND profile_id = ?", partitionID, profileID).Error
	if err != nil {
		return nil, err
	}

	return access, nil
}

func NewAccessRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) AccessRepository {
	return &accessRepository{
		BaseRepository: datastore.NewBaseRepository[*models.Access](
			ctx, dbPool, workMan, func() *models.Access { return &models.Access{} },
		),
	}
}
