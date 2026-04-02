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

func (ar *accessRepository) ListByPartition(ctx context.Context, partitionID string) ([]*models.Access, error) {
	var accesses []*models.Access
	err := ar.Pool().DB(ctx, true).Where("partition_id = ?", partitionID).Find(&accesses).Error
	return accesses, err
}

func (ar *accessRepository) ListByProfileID(ctx context.Context, profileID string) ([]*models.Access, error) {
	var accesses []*models.Access
	err := ar.Pool().DB(ctx, true).Where("profile_id = ?", profileID).Find(&accesses).Error
	return accesses, err
}

func (ar *accessRepository) CountByPartitionID(ctx context.Context, partitionID string) (int64, error) {
	var count int64
	err := ar.Pool().DB(ctx, true).Model(&models.Access{}).Where("partition_id = ?", partitionID).Count(&count).Error
	return count, err
}

func NewAccessRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) AccessRepository {
	return &accessRepository{
		BaseRepository: datastore.NewBaseRepository[*models.Access](
			ctx, dbPool, workMan, func() *models.Access { return &models.Access{} },
		),
	}
}
