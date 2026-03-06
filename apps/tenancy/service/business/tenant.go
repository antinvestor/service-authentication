package business

import (
	"context"
	"fmt"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/data"
)

type TenantBusiness interface {
	GetTenant(ctx context.Context, tenantID string) (*partitionv1.TenantObject, error)
	CreateTenant(ctx context.Context, request *partitionv1.CreateTenantRequest) (*partitionv1.TenantObject, error)
	UpdateTenant(ctx context.Context, request *partitionv1.UpdateTenantRequest) (*partitionv1.TenantObject, error)
	RemoveTenant(ctx context.Context, id string) error
	ListTenant(
		ctx context.Context,
		request *partitionv1.ListTenantRequest) ([]*partitionv1.TenantObject, error)
}

func NewTenantBusiness(
	service *frame.Service,
	tenantRepo repository.TenantRepository,
	partitionRepo repository.PartitionRepository,
) TenantBusiness {
	return &tenantBusiness{
		service:       service,
		tenantRepo:    tenantRepo,
		partitionRepo: partitionRepo,
	}
}

type tenantBusiness struct {
	service       *frame.Service
	tenantRepo    repository.TenantRepository
	partitionRepo repository.PartitionRepository
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

	err := t.tenantRepo.Create(ctx, tenantModel)
	if err != nil {
		return nil, err
	}

	return tenantModel.ToAPI(), nil
}

func (t *tenantBusiness) UpdateTenant(ctx context.Context, request *partitionv1.UpdateTenantRequest) (*partitionv1.TenantObject, error) {

	tenant, err := t.tenantRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, err
	}

	jsonMap := tenant.Properties
	if jsonMap == nil {
		jsonMap = make(data.JSONMap)
	}
	for k, v := range request.GetProperties().AsMap() {
		jsonMap[k] = v
	}

	if request.GetName() != "" {
		tenant.Name = request.GetName()
	}
	if request.GetDescription() != "" {
		tenant.Description = request.GetDescription()
	}

	tenant.Properties = jsonMap

	_, err = t.tenantRepo.Update(ctx, tenant, "name", "description", "properties")
	if err != nil {
		return nil, err
	}

	return tenant.ToAPI(), nil
}

func (t *tenantBusiness) RemoveTenant(ctx context.Context, id string) error {
	count, err := t.partitionRepo.CountByTenantID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to check tenant partitions: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("cannot remove tenant: %d partition(s) still exist", count)
	}
	return t.tenantRepo.Delete(ctx, id)
}

func (t *tenantBusiness) ListTenant(
	ctx context.Context,
	request *partitionv1.ListTenantRequest) ([]*partitionv1.TenantObject, error) {

	filterProperties := map[string]any{}

	for _, p := range request.GetProperties() {
		filterProperties[p+" = ?"] = request.GetQuery()
	}

	var limit, offset int
	if cursor := request.GetCursor(); cursor != nil {
		limit = int(cursor.GetLimit())
		if p := cursor.GetPage(); p != "" {
			_, _ = fmt.Sscanf(p, "%d", &offset)
		}
	}

	query := data.NewSearchQuery(
		data.WithSearchLimit(limit),
		data.WithSearchOffset(offset),
		data.WithSearchFiltersAndByValue(filterProperties),
	)

	jobResult, err := t.tenantRepo.Search(ctx, query)
	if err != nil {
		return nil, err
	}

	var responseObjects []*partitionv1.TenantObject
	for {
		result, ok := jobResult.ReadResult(ctx)

		if !ok {
			return responseObjects, nil
		}

		if result.IsError() {
			return responseObjects, result.Error()
		}

		for _, tenant := range result.Item() {
			responseObjects = append(responseObjects, tenant.ToAPI())
		}
	}
}
