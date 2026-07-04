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

type partitionRepository struct {
	datastore.BaseRepository[*models.Partition]
}

func (pr *partitionRepository) GetParents(ctx context.Context, id string) ([]*models.Partition, error) {
	var parents []*models.Partition

	// Use a recursive CTE to get all parents in a single query with depth limit of 5
	query := `
		WITH RECURSIVE parent_hierarchy AS (
			-- Base case: get the immediate parent of the given partition
			SELECT p2.id, p2.created_at, p2.tenant_id, p2.partition_id,
			       p2.name, p2.description, p2.domain, p2.parent_id, p2.allow_auto_access, p2.properties, p2.state,
			       1 as depth
			FROM partitions p1
			JOIN partitions p2 ON p1.parent_id = p2.id
			WHERE p1.id = ? AND p1.parent_id IS NOT NULL AND p1.parent_id != ''

			UNION ALL

			-- Recursive case: get the parent of each parent (limited to depth 5)
			-- Note: We don't filter by parent_id here to include root partitions
			SELECT p.id, p.created_at, p.tenant_id, p.partition_id,
			       p.name, p.description, p.domain, p.parent_id, p.allow_auto_access, p.properties, p.state,
			       ph.depth + 1 as depth
			FROM partitions p
			JOIN parent_hierarchy ph ON p.id = ph.parent_id
			WHERE ph.depth < 5 AND (ph.parent_id IS NOT NULL AND ph.parent_id != '')
		)
		SELECT id, created_at, tenant_id, partition_id, name, description, domain, parent_id, allow_auto_access, properties, state
		FROM parent_hierarchy ORDER BY depth DESC
	`

	err := pr.Pool().DB(ctx, true).Raw(query, id).Scan(&parents).Error
	return parents, err
}

func (pr *partitionRepository) GetByDomain(ctx context.Context, domain string) (*models.Partition, error) {
	var partition models.Partition
	err := pr.Pool().DB(ctx, true).First(&partition, "domain = ?", domain).Error
	return &partition, err
}

func (pr *partitionRepository) GetChildren(ctx context.Context, id string) ([]*models.Partition, error) {
	childPartition := make([]*models.Partition, 0)
	err := pr.Pool().DB(ctx, true).Find(&childPartition, "parent_id = ?", id).Error
	return childPartition, err
}

func (pr *partitionRepository) Delete(ctx context.Context, id string) error {
	var partition models.Partition
	if err := pr.Pool().DB(ctx, true).First(&partition, "id = ?", id).Error; err != nil {
		return err
	}
	return pr.Pool().DB(ctx, false).Delete(&partition).Error
}

func (pr *partitionRepository) CountByTenantID(ctx context.Context, tenantID string) (int64, error) {
	var count int64
	err := pr.Pool().DB(ctx, true).Model(&models.Partition{}).Where("tenant_id = ?", tenantID).Count(&count).Error
	return count, err
}

func NewPartitionRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) PartitionRepository {
	return &partitionRepository{
		BaseRepository: datastore.NewBaseRepository[*models.Partition](
			ctx, dbPool, workMan, func() *models.Partition { return &models.Partition{} },
		),
	}
}
