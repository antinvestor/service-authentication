package repository

import (
	"context"
	"errors"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/framedata"
)

type partitionRepository struct {
	service *frame.Service
}

func (pr *partitionRepository) GetByID(ctx context.Context, id string) (*models.Partition, error) {
	partition := &models.Partition{}
	err := pr.service.DB(ctx, true).First(partition, "id = ?", id).Error
	return partition, err
}

func (pr *partitionRepository) Search(
	ctx context.Context, query *framedata.SearchQuery) (
	frame.JobResultPipe[[]*models.Partition], error) {

	return framedata.StableSearch[models.Partition](ctx, pr.service, query, func(
		ctx context.Context,
		query *framedata.SearchQuery,
	) ([]*models.Partition, error) {
		var partitionList []*models.Partition

		paginator := query.Pagination

		db := pr.service.DB(ctx, true).
			Limit(paginator.Limit).Offset(paginator.Offset)

		if query.Fields != nil {

			partitionID, pok := query.Fields["id"]
			if pok {
				db = db.Where("id = ?", partitionID)
			}
			parentID, pok := query.Fields["parent_id"]
			if pok {
				db = db.Where("parent_id = ?", parentID)
			}
		}

		if query.Query != "" {

			likeQuery := "%" + query.Query + "%"

			db = db.Where("name iLike ? OR description @@ plainto_tsquery(?) OR search_vector @@ plainto_tsquery(?) ",
				likeQuery, query.Query, query.Query)
		}

		err := db.Find(&partitionList).Error
		if err != nil {
			return nil, err
		}

		return partitionList, nil
	})
}

func (pr *partitionRepository) GetChildren(ctx context.Context, id string) ([]*models.Partition, error) {
	childPartition := make([]*models.Partition, 0)
	err := pr.service.DB(ctx, true).Find(&childPartition, "parent_id = ?", id).Error
	return childPartition, err
}

func (pr *partitionRepository) Save(ctx context.Context, partition *models.Partition) error {
	return pr.service.DB(ctx, false).Save(partition).Error
}

func (pr *partitionRepository) Delete(ctx context.Context, id string) error {
	// Check if the partition has children
	var childCount int64
	db := pr.service.DB(ctx, true)
	if err := db.Model(&models.Partition{}).Where("parent_id = ?", id).Count(&childCount).Error; err != nil {
		return err
	}
	if childCount > 0 {
		return errors.New("cannot delete partition with children")
	}

	var partition models.Partition
	if err := pr.service.DB(ctx, true).First(&partition, "id = ?", id).Error; err != nil {
		return err
	}
	return pr.service.DB(ctx, false).Delete(&partition).Error
}

func (pr *partitionRepository) GetRoles(ctx context.Context, partitionID string) ([]*models.PartitionRole, error) {
	partitionRoles := make([]*models.PartitionRole, 0)
	err := pr.service.DB(ctx, true).Find(&partitionRoles, "partition_id = ?", partitionID).Error
	return partitionRoles, err
}

func (pr *partitionRepository) GetRolesByID(ctx context.Context, idList ...string) ([]*models.PartitionRole, error) {
	partitionRoles := make([]*models.PartitionRole, 0)
	err := pr.service.DB(ctx, true).Find(&partitionRoles, "id IN ?", idList).Error
	return partitionRoles, err
}

func (pr *partitionRepository) SaveRole(ctx context.Context, role *models.PartitionRole) error {
	return pr.service.DB(ctx, false).Save(role).Error
}

func (pr *partitionRepository) RemoveRole(ctx context.Context, partitionRoleID string) error {
	return pr.service.DB(ctx, false).Where("id = ?", partitionRoleID).Delete(&models.PartitionRole{}).Error
}

func NewPartitionRepository(service *frame.Service) PartitionRepository {
	repo := partitionRepository{
		service: service,
	}
	return &repo
}
