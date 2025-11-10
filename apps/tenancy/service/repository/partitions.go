package repository

import (
	"context"
	"errors"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/workerpool"
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
			       p2.name, p2.description, p2.parent_id, p2.client_secret, p2.properties, p2.state,
			       1 as depth
			FROM partitions p1
			JOIN partitions p2 ON p1.parent_id = p2.id
			WHERE p1.id = ? AND p1.parent_id IS NOT NULL AND p1.parent_id != ''
			
			UNION ALL
			
			-- Recursive case: get the parent of each parent (limited to depth 5)
			-- Note: We don't filter by parent_id here to include root partitions
			SELECT p.id, p.created_at, p.tenant_id, p.partition_id,
			       p.name, p.description, p.parent_id, p.client_secret, p.properties, p.state,
			       ph.depth + 1 as depth
			FROM partitions p
			JOIN parent_hierarchy ph ON p.id = ph.parent_id
			WHERE ph.depth < 5 AND (ph.parent_id IS NOT NULL AND ph.parent_id != '')
		)
		SELECT id, created_at, tenant_id, partition_id, name, description, parent_id, client_secret, properties, state 
		FROM parent_hierarchy ORDER BY depth DESC
	`

	err := pr.Pool().DB(ctx, true).Raw(query, id).Scan(&parents).Error
	return parents, err
}

func (pr *partitionRepository) GetChildren(ctx context.Context, id string) ([]*models.Partition, error) {
	childPartition := make([]*models.Partition, 0)
	err := pr.Pool().DB(ctx, true).Find(&childPartition, "parent_id = ?", id).Error
	return childPartition, err
}

func (pr *partitionRepository) Delete(ctx context.Context, id string) error {
	// Check if the partition has children
	var childCount int64
	db := pr.Pool().DB(ctx, true)
	if err := db.Model(&models.Partition{}).Where("parent_id = ?", id).Count(&childCount).Error; err != nil {
		return err
	}
	if childCount > 0 {
		return errors.New("cannot delete partition with children")
	}

	var partition models.Partition
	if err := pr.Pool().DB(ctx, true).First(&partition, "id = ?", id).Error; err != nil {
		return err
	}
	return pr.Pool().DB(ctx, false).Delete(&partition).Error
}

func NewPartitionRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) PartitionRepository {
	return &partitionRepository{
		BaseRepository: datastore.NewBaseRepository[*models.Partition](
			ctx, dbPool, workMan, func() *models.Partition { return &models.Partition{} },
		),
	}
}
