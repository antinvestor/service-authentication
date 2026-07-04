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

func (r *clientRepository) CountByPartitionID(ctx context.Context, partitionID string) (int64, error) {
	var count int64
	err := r.Pool().DB(ctx, true).Model(&models.Client{}).Where("partition_id = ?", partitionID).Count(&count).Error
	return count, err
}

func NewClientRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) ClientRepository {
	return &clientRepository{
		BaseRepository: datastore.NewBaseRepository[*models.Client](
			ctx, dbPool, workMan, func() *models.Client { return &models.Client{} },
		),
	}
}
