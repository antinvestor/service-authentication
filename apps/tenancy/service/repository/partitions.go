package repository

import (
	"context"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"

	"github.com/pitabwire/frame"
)

type partitionRepository struct {
	service *frame.Service
}

func (pr *partitionRepository) GetByID(ctx context.Context, id string) (*models.Partition, error) {
	partition := &models.Partition{}
	err := pr.service.DB(ctx, true).First(partition, "id = ?", id).Error
	return partition, err
}

func (pr *partitionRepository) GetByQuery(ctx context.Context,
	query string, count uint32, page uint32) ([]*models.Partition, error) {
	partitionList := make([]*models.Partition, 0)
	query = "%" + query + "%"
	err := pr.service.DB(ctx, true).Find(&partitionList,
		"id = ? OR tenant_id = ? OR parent_id = ?  OR name iLike ? OR description iLike ? ",
		query, query, query, query, query).Offset(int(page * count)).Limit(int(count)).Error
	return partitionList, err
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
	partition, err := pr.GetByID(ctx, id)
	if err != nil {
		return err
	}
	return pr.service.DB(ctx, false).Delete(partition).Error
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
