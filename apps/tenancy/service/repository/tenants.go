package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame"
)

type tenantRepository struct {
	service *frame.Service
}

func (tr *tenantRepository) GetByID(ctx context.Context, id string) (*models.Tenant, error) {
	tenant := &models.Tenant{}
	err := tr.service.DB(ctx, true).First(tenant, "id = ?", id).Error
	return tenant, err
}

func (tr *tenantRepository) GetByQuery(
	ctx context.Context,
	query string,
	count uint32,
	page uint32,
) ([]*models.Tenant, error) {
	tenantList := make([]*models.Tenant, 0)
	query = "%" + query + "%"
	err := tr.service.DB(ctx, true).
		Find(&tenantList, "id iLike ? OR name iLike ? OR description iLike ? ", query, query, query).
		Offset(int(page * count)).
		Limit(int(count)).
		Error
	return tenantList, err
}

func (tr *tenantRepository) Save(ctx context.Context, tenant *models.Tenant) error {
	return tr.service.DB(ctx, false).Save(tenant).Error
}

func (tr *tenantRepository) Delete(ctx context.Context, id string) error {
	tenant, err := tr.GetByID(ctx, id)
	if err != nil {
		return err
	}
	return tr.service.DB(ctx, false).Delete(tenant).Error
}

func NewTenantRepository(service *frame.Service) TenantRepository {
	repo := tenantRepository{
		service: service,
	}
	return &repo
}
