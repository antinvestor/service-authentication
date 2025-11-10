package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame"
)

type accessRepository struct {
	service *frame.Service
}

func (ar *accessRepository) GetByID(ctx context.Context, id string) (*models.Access, error) {
	access := &models.Access{}
	err := ar.Pool().DB(ctx, true).First(access, " accesses.id = ?", id).Error

	if err != nil {
		return nil, err
	}

	return access, nil
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

func (ar *accessRepository) Save(ctx context.Context, access *models.Access) error {
	return ar.Pool().DB(ctx, false).Save(access).Error
}

func (ar *accessRepository) Delete(ctx context.Context, id string) error {
	err := ar.Pool().DB(ctx, false).Where(" access_id = ?", id).Delete(&models.AccessRole{}).Error
	if err != nil {
		return err
	}

	return ar.Pool().DB(ctx, false).Where(" id = ?", id).Delete(&models.Access{}).Error
}

func (ar *accessRepository) GetRoles(ctx context.Context, accessID string) ([]*models.AccessRole, error) {
	accessRoles := make([]*models.AccessRole, 0)
	err := ar.Pool().DB(ctx, true).
		Find(&accessRoles, " access_id = ?", accessID).Error

	return accessRoles, err
}

func (ar *accessRepository) SaveRole(ctx context.Context, role *models.AccessRole) error {
	return ar.Pool().DB(ctx, false).Save(role).Error
}

func (ar *accessRepository) RemoveRole(ctx context.Context, accessRoleID string) error {
	return ar.Pool().DB(ctx, false).Where(" id = ?", accessRoleID).Delete(&models.AccessRole{}).Error
}

func NewAccessRepository(service *frame.Service) AccessRepository {
	partitionRepository := accessRepository{
		service: service,
	}
	return &partitionRepository
}
