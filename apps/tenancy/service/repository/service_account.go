package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/workerpool"
)

type serviceAccountRepository struct {
	datastore.BaseRepository[*models.ServiceAccount]
}

func (r *serviceAccountRepository) GetByPartitionAndProfile(
	ctx context.Context,
	partitionID string,
	profileID string,
) (*models.ServiceAccount, error) {
	sa := &models.ServiceAccount{}
	err := r.Pool().DB(ctx, true).First(sa, "partition_id = ? AND profile_id = ?", partitionID, profileID).Error
	if err != nil {
		return nil, err
	}
	return sa, nil
}

func (r *serviceAccountRepository) GetByClientAndProfile(
	ctx context.Context,
	clientID string,
	profileID string,
) (*models.ServiceAccount, error) {
	sa := &models.ServiceAccount{}
	err := r.Pool().DB(ctx, true).First(sa, "client_id = ? AND profile_id = ?", clientID, profileID).Error
	if err != nil {
		return nil, err
	}
	return sa, nil
}

func (r *serviceAccountRepository) GetByClientID(
	ctx context.Context,
	clientID string,
) (*models.ServiceAccount, error) {
	sa := &models.ServiceAccount{}
	err := r.Pool().DB(ctx, true).First(sa, "client_id = ?", clientID).Error
	if err != nil {
		return nil, err
	}
	return sa, nil
}

func (r *serviceAccountRepository) GetByClientRef(
	ctx context.Context,
	clientRef string,
) (*models.ServiceAccount, error) {
	sa := &models.ServiceAccount{}
	err := r.Pool().DB(ctx, true).First(sa, "client_ref = ?", clientRef).Error
	return sa, err
}

func (r *serviceAccountRepository) ListByPartition(
	ctx context.Context,
	partitionID string,
) ([]*models.ServiceAccount, error) {
	var accounts []*models.ServiceAccount
	err := r.Pool().DB(ctx, true).Where("partition_id = ?", partitionID).Find(&accounts).Error
	if err != nil {
		return nil, err
	}
	return accounts, nil
}

func (r *serviceAccountRepository) CountByPartitionID(ctx context.Context, partitionID string) (int64, error) {
	var count int64
	err := r.Pool().DB(ctx, true).Model(&models.ServiceAccount{}).Where("partition_id = ?", partitionID).Count(&count).Error
	return count, err
}

func NewServiceAccountRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) ServiceAccountRepository {
	return &serviceAccountRepository{
		BaseRepository: datastore.NewBaseRepository[*models.ServiceAccount](
			ctx, dbPool, workMan, func() *models.ServiceAccount { return &models.ServiceAccount{} },
		),
	}
}
