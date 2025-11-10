package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/workerpool"
)

type tenantRepository struct {
	datastore.BaseRepository[*models.Tenant]
}

func NewTenantRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) TenantRepository {
	return &tenantRepository{
		BaseRepository: datastore.NewBaseRepository[*models.Tenant](
			ctx, dbPool, workMan, func() *models.Tenant { return &models.Tenant{} },
		),
	}
}
