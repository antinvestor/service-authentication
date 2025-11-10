package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/workerpool"
)

type partitionRoleRepository struct {
	datastore.BaseRepository[*models.PartitionRole]
}

func (pr *partitionRoleRepository) GetByPartitionID(ctx context.Context, partitionID string) ([]*models.PartitionRole, error) {
	partitionRoles := make([]*models.PartitionRole, 0)
	err := pr.Pool().DB(ctx, true).Find(&partitionRoles, "partition_id = ?", partitionID).Error
	return partitionRoles, err
}

func (pr *partitionRoleRepository) GetRolesByID(ctx context.Context, idList ...string) ([]*models.PartitionRole, error) {
	partitionRoles := make([]*models.PartitionRole, 0)
	err := pr.Pool().DB(ctx, true).Find(&partitionRoles, "id IN ?", idList).Error
	return partitionRoles, err
}

func NewPartitionRoleRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) PartitionRoleRepository {
	return &partitionRoleRepository{
		BaseRepository: datastore.NewBaseRepository[*models.PartitionRole](
			ctx, dbPool, workMan, func() *models.PartitionRole { return &models.PartitionRole{} },
		),
	}
}
