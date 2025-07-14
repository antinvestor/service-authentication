package business

import (
	"context"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"

	commonv1 "github.com/antinvestor/apis/go/common/v1"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/pitabwire/frame"
)

type PageBusiness interface {
	GetPage(ctx context.Context, request *partitionv1.GetPageRequest) (*partitionv1.PageObject, error)
	RemovePage(ctx context.Context, request *partitionv1.RemovePageRequest) error
	CreatePage(ctx context.Context, request *partitionv1.CreatePageRequest) (*partitionv1.PageObject, error)
}

func NewPageBusiness(_ context.Context, service *frame.Service) PageBusiness {
	pageRepo := repository.NewPageRepository(service)
	partitionRepo := repository.NewPartitionRepository(service)

	return &pageBusiness{
		service:       service,
		pageRepo:      pageRepo,
		partitionRepo: partitionRepo,
	}
}

type pageBusiness struct {
	service       *frame.Service
	pageRepo      repository.PageRepository
	partitionRepo repository.PartitionRepository
}

func toAPIPage(pageModel *models.Page) *partitionv1.PageObject {
	return &partitionv1.PageObject{
		PageId: pageModel.GetID(),
		Name:   pageModel.Name,
		Html:   pageModel.HTML,
		State:  commonv1.STATE(pageModel.State),
	}
}

func (ab *pageBusiness) GetPage(
	ctx context.Context,
	request *partitionv1.GetPageRequest,
) (*partitionv1.PageObject, error) {
	access, err := ab.pageRepo.GetByPartitionAndName(ctx, request.GetPartitionId(), request.GetName())
	if err != nil {
		return nil, err
	}

	return toAPIPage(access), nil
}

func (ab *pageBusiness) RemovePage(ctx context.Context, request *partitionv1.RemovePageRequest) error {
	return ab.pageRepo.Delete(ctx, request.GetId())
}

func (ab *pageBusiness) CreatePage(
	ctx context.Context,
	request *partitionv1.CreatePageRequest,
) (*partitionv1.PageObject, error) {
	partition, err := ab.partitionRepo.GetByID(ctx, request.GetPartitionId())
	if err != nil {
		return nil, err
	}

	page := &models.Page{
		Name: request.GetName(),
		HTML: request.GetHtml(),
		BaseModel: frame.BaseModel{
			TenantID:    partition.TenantID,
			PartitionID: partition.GetID(),
		},
	}

	err = ab.pageRepo.Save(ctx, page)
	if err != nil {
		return nil, err
	}

	return toAPIPage(page), nil
}
