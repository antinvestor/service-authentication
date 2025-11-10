package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/framedata"
)

type tenantRepository struct {
	service *frame.Service
}

func (tr *tenantRepository) GetByID(ctx context.Context, id string) (*models.Tenant, error) {
	tenant := &models.Tenant{}
	err := tr.Pool().DB(ctx, true).First(tenant, "id = ?", id).Error
	return tenant, err
}

func (tr *tenantRepository) Search(
	ctx context.Context,
	query *framedata.SearchQuery) (frame.JobResultPipe[[]*models.Tenant], error) {

	return framedata.StableSearch[models.Tenant](ctx, tr.service, query, func(
		ctx context.Context,
		query *framedata.SearchQuery,
	) ([]*models.Tenant, error) {
		var tenantList []*models.Tenant

		paginator := query.Pagination

		db := tr.Pool().DB(ctx, true).
			Limit(paginator.Limit).Offset(paginator.Offset)

		if query.Fields != nil {

			tenantID, pok := query.Fields["id"]
			if pok {
				db = db.Where("id = ?", tenantID)
			}
		}

		if query.Query != "" {

			likeQuery := "%" + query.Query + "%"

			db = db.Where("name iLike ? OR description iLike ? OR search_vector @@ plainto_tsquery(?) ", likeQuery, likeQuery, query.Query)
		}

		err := db.Find(&tenantList).Error
		if err != nil {
			return nil, err
		}

		return tenantList, nil
	})
}

func (tr *tenantRepository) Save(ctx context.Context, tenant *models.Tenant) error {
	return tr.Pool().DB(ctx, false).Save(tenant).Error
}

func (tr *tenantRepository) Delete(ctx context.Context, id string) error {
	tenant, err := tr.GetByID(ctx, id)
	if err != nil {
		return err
	}
	return tr.Pool().DB(ctx, false).Delete(tenant).Error
}

func NewTenantRepository(service *frame.Service) TenantRepository {
	repo := tenantRepository{
		service: service,
	}
	return &repo
}
