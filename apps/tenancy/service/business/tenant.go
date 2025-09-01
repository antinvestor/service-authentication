package business

import (
	"context"

	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/framedata"
)

type TenantBusiness interface {
	GetTenant(ctx context.Context, tenantID string) (*partitionv1.TenantObject, error)
	CreateTenant(ctx context.Context, request *partitionv1.CreateTenantRequest) (*partitionv1.TenantObject, error)
	ListTenant(
		ctx context.Context,
		request *partitionv1.ListTenantRequest,
		stream partitionv1.PartitionService_ListTenantServer,
	) error
}

func NewTenantBusiness(ctx context.Context, service *frame.Service) TenantBusiness {
	tenantRepo := repository.NewTenantRepository(service)

	return NewTenantBusinessWithRepo(ctx, service, tenantRepo)
}

func NewTenantBusinessWithRepo(
	_ context.Context,
	service *frame.Service,
	repo repository.TenantRepository,
) TenantBusiness {
	return &tenantBusiness{
		service:    service,
		tenantRepo: repo,
	}
}

type tenantBusiness struct {
	service    *frame.Service
	tenantRepo repository.TenantRepository
}

func ToModelTenant(tenantAPI *partitionv1.TenantObject) *models.Tenant {
	return &models.Tenant{
		Description: tenantAPI.GetDescription(),
		Properties:  tenantAPI.GetProperties().AsMap(),
	}
}

func (t *tenantBusiness) GetTenant(ctx context.Context, tenantID string) (*partitionv1.TenantObject, error) {
	// err := request.Validate()
	// if err != nil {
	//	return nil, err
	// }

	tenant, err := t.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return tenant.ToAPI(), nil
}

func (t *tenantBusiness) CreateTenant(
	ctx context.Context,
	request *partitionv1.CreateTenantRequest,
) (*partitionv1.TenantObject, error) {

	tenantModel := &models.Tenant{
		Name:        request.GetName(),
		Description: request.GetDescription(),
		Properties:  request.GetProperties().AsMap(),
	}

	err := t.tenantRepo.Save(ctx, tenantModel)
	if err != nil {
		return nil, err
	}

	return tenantModel.ToAPI(), nil
}

func (t *tenantBusiness) ListTenant(
	ctx context.Context,
	request *partitionv1.ListTenantRequest,
	stream partitionv1.PartitionService_ListTenantServer,
) error {

	searchProperties := map[string]any{}

	for _, p := range request.GetProperties() {
		searchProperties[p] = request.GetQuery()
	}

	query := framedata.NewSearchQuery(
		request.GetQuery(), searchProperties,
		int(request.GetPage()),
		int(request.GetCount()),
	)

	jobResult, err := t.tenantRepo.Search(ctx, query)
	if err != nil {
		return err
	}

	for {
		result, ok := jobResult.ReadResult(ctx)

		if !ok {
			return nil
		}

		if result.IsError() {
			return result.Error()
		}

		var responseObjects []*partitionv1.TenantObject
		for _, tenant := range result.Item() {
			responseObjects = append(responseObjects, tenant.ToAPI())
		}

		err = stream.Send(&partitionv1.ListTenantResponse{Data: responseObjects})
		if err != nil {
			return err
		}

	}
}
