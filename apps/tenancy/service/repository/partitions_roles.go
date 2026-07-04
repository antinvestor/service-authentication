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

type partitionRoleRepository struct {
	datastore.BaseRepository[*models.PartitionRole]
}

func (pr *partitionRoleRepository) GetByPartitionID(ctx context.Context, partitionID string) ([]*models.PartitionRole, error) {
	partitionRoles := make([]*models.PartitionRole, 0)
	err := pr.Pool().DB(ctx, true).Find(&partitionRoles, "partition_id = ?", partitionID).Error
	return partitionRoles, err
}

func (pr *partitionRoleRepository) GetDefaultByPartitionID(ctx context.Context, partitionID string) ([]*models.PartitionRole, error) {
	partitionRoles := make([]*models.PartitionRole, 0)
	err := pr.Pool().DB(ctx, true).Find(&partitionRoles, "partition_id = ? AND is_default = ?", partitionID, true).Error
	return partitionRoles, err
}

func (pr *partitionRoleRepository) GetRolesByID(ctx context.Context, idList ...string) ([]*models.PartitionRole, error) {
	partitionRoles := make([]*models.PartitionRole, 0)
	err := pr.Pool().DB(ctx, true).Find(&partitionRoles, "id IN ?", idList).Error
	return partitionRoles, err
}

func (pr *partitionRoleRepository) GetByPartitionAndNames(ctx context.Context, partitionID string, names []string) ([]*models.PartitionRole, error) {
	partitionRoles := make([]*models.PartitionRole, 0)
	err := pr.Pool().DB(ctx, true).Find(&partitionRoles, "partition_id = ? AND name IN ?", partitionID, names).Error
	return partitionRoles, err
}

func NewPartitionRoleRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) PartitionRoleRepository {
	return &partitionRoleRepository{
		BaseRepository: datastore.NewBaseRepository[*models.PartitionRole](
			ctx, dbPool, workMan, func() *models.PartitionRole { return &models.PartitionRole{} },
		),
	}
}
