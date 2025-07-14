package business

import (
	"context"

	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
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

func ToAPITenant(tenantModel *models.Tenant) *partitionv1.TenantObject {
	properties := frame.DBPropertiesToMap(tenantModel.Properties)

	return &partitionv1.TenantObject{
		Id:          tenantModel.ID,
		Description: tenantModel.Description,
		Properties:  properties,
	}
}

func ToModelTenant(tenantAPI *partitionv1.TenantObject) *models.Tenant {
	return &models.Tenant{
		Description: tenantAPI.GetDescription(),
		Properties:  frame.DBPropertiesFromMap(tenantAPI.GetProperties()),
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

	return ToAPITenant(tenant), nil
}

func (t *tenantBusiness) CreateTenant(
	ctx context.Context,
	request *partitionv1.CreateTenantRequest,
) (*partitionv1.TenantObject, error) {
	jsonMap := make(frame.JSONMap)
	for k, v := range request.GetProperties() {
		jsonMap[k] = v
	}

	tenantModel := &models.Tenant{
		Name:        request.GetName(),
		Description: request.GetDescription(),
		Properties:  jsonMap,
	}

	err := t.tenantRepo.Save(ctx, tenantModel)
	if err != nil {
		return nil, err
	}

	return ToAPITenant(tenantModel), nil
}

func (t *tenantBusiness) ListTenant(
	ctx context.Context,
	request *partitionv1.ListTenantRequest,
	stream partitionv1.PartitionService_ListTenantServer,
) error {
	tenantList, err := t.tenantRepo.GetByQuery(
		ctx,
		request.GetQuery(),
		getUint32FromInt32(request.GetCount()),
		getUint32FromInt64(request.GetPage()),
	)
	if err != nil {
		return err
	}

	var responseList []*partitionv1.TenantObject
	for _, tenant := range tenantList {
		responseList = append(responseList, ToAPITenant(tenant))
	}

	return stream.Send(&partitionv1.ListTenantResponse{Data: responseList})
}
