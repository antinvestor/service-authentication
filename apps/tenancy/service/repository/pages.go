package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/workerpool"
)

type pageRepository struct {
	datastore.BaseRepository[*models.Page]
}

func (pgr *pageRepository) GetByPartitionAndName(
	ctx context.Context,
	partitionID string,
	name string,
) (*models.Page, error) {
	page := &models.Page{}
	err := pgr.Pool().DB(ctx, true).First(page, "partition_id = ? AND name = ?", partitionID, name).Error
	return page, err
}

func NewPageRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) PageRepository {
	return &pageRepository{
		BaseRepository: datastore.NewBaseRepository[*models.Page](
			ctx, dbPool, workMan, func() *models.Page { return &models.Page{} },
		),
	}
}
