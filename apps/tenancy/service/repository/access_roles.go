package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/workerpool"
)

type accessRoleRepository struct {
	datastore.BaseRepository[*models.AccessRole]
}

func (ar *accessRoleRepository) GetByAccessID(ctx context.Context, accessID string) ([]*models.AccessRole, error) {
	accessRoles := make([]*models.AccessRole, 0)
	err := ar.Pool().DB(ctx, true).
		Find(&accessRoles, " access_id = ?", accessID).Error

	return accessRoles, err
}

func NewAccessRoleRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) AccessRoleRepository {
	return &accessRoleRepository{
		BaseRepository: datastore.NewBaseRepository[*models.AccessRole](
			ctx, dbPool, workMan, func() *models.AccessRole { return &models.AccessRole{} },
		),
	}
}
