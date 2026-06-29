// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"github.com/pitabwire/frame/v2/workerpool"
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

func (pgr *pageRepository) ListByPartition(ctx context.Context, partitionID string) ([]*models.Page, error) {
	var pages []*models.Page
	err := pgr.Pool().DB(ctx, true).Where("partition_id = ?", partitionID).Find(&pages).Error
	return pages, err
}

func NewPageRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) PageRepository {
	return &pageRepository{
		BaseRepository: datastore.NewBaseRepository[*models.Page](
			ctx, dbPool, workMan, func() *models.Page { return &models.Page{} },
		),
	}
}
