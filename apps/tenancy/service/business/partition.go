package business

import (
	"context"
	"fmt"
	"strings"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"google.golang.org/protobuf/types/known/structpb"
)

type PartitionBusiness interface {
	GetPartition(ctx context.Context, request *partitionv1.GetPartitionRequest) (*partitionv1.PartitionObject, error)
	GetPartitionParents(ctx context.Context, request *partitionv1.GetPartitionParentsRequest) ([]*partitionv1.PartitionObject, error)
	CreatePartition(
		ctx context.Context,
		request *partitionv1.CreatePartitionRequest) (*partitionv1.PartitionObject, error)
	UpdatePartition(
		ctx context.Context,
		request *partitionv1.UpdatePartitionRequest) (*partitionv1.PartitionObject, error)
	ListPartition(
		ctx context.Context,
		request *partitionv1.ListPartitionRequest) ([]*partitionv1.PartitionObject, error)

	RemovePartitionRole(ctx context.Context, request *partitionv1.RemovePartitionRoleRequest) error
	ListPartitionRoles(
		ctx context.Context,
		request *partitionv1.ListPartitionRoleRequest) (*partitionv1.ListPartitionRoleResponse, error)
	CreatePartitionRole(
		ctx context.Context,
		request *partitionv1.CreatePartitionRoleRequest) (*partitionv1.PartitionRoleObject, error)
}

func NewPartitionBusiness(
	cfg config.AuthenticationConfig,
	eventsMan fevents.Manager,
	tenantRepo repository.TenantRepository,
	partitionRepo repository.PartitionRepository,
	partitionRoleRepo repository.PartitionRoleRepository,
) PartitionBusiness {
	return &partitionBusiness{
		cfg:               cfg,
		eventsMan:         eventsMan,
		partitionRepo:     partitionRepo,
		partitionRoleRepo: partitionRoleRepo,
		tenantRepo:        tenantRepo,
	}
}

type partitionBusiness struct {
	eventsMan         fevents.Manager
	cfg               config.AuthenticationConfig
	tenantRepo        repository.TenantRepository
	partitionRepo     repository.PartitionRepository
	partitionRoleRepo repository.PartitionRoleRepository
}

func toAPIPartitionRole(partitionModel *models.PartitionRole) *partitionv1.PartitionRoleObject {

	return &partitionv1.PartitionRoleObject{
		PartitionId: partitionModel.PartitionID,
		Name:        partitionModel.Name,
		Properties:  partitionModel.Properties.ToProtoStruct(),
	}
}

func (pb *partitionBusiness) ListPartition(
	ctx context.Context,
	request *partitionv1.ListPartitionRequest) ([]*partitionv1.PartitionObject, error) {

	query := pb.buildSearchQuery(ctx, request)
	jobResult, err := pb.partitionRepo.Search(ctx, query)
	if err != nil {
		return nil, err
	}

	var responseObjects []*partitionv1.PartitionObject
	for {
		result, ok := jobResult.ReadResult(ctx)

		if !ok {
			return responseObjects, nil
		}

		if result.IsError() {
			return responseObjects, result.Error()
		}

		for _, partition := range result.Item() {
			responseObjects = append(responseObjects, partition.ToAPI())
		}

	}
}

// buildSearchQuery creates the search query from the request.
func (pb *partitionBusiness) buildSearchQuery(ctx context.Context, query *partitionv1.ListPartitionRequest) *data.SearchQuery {
	profileID := ""
	claims := security.ClaimsFromContext(ctx)
	if claims != nil {
		profileID, _ = claims.GetSubject()
	}

	filterProperties := map[string]any{}
	searchProperties := map[string]any{}

	// Add additional properties from the request
	for _, p := range query.GetProperties() {
		filterProperties[fmt.Sprintf("%s = ? ", p)] = query.GetQuery()
	}

	// Build searchProperties map, only add profile_id if it's not empty
	if profileID != "" {
		searchProperties["profile_id"] = profileID
	}

	return data.NewSearchQuery(data.WithSearchLimit(int(query.GetCount())),
		data.WithSearchOffset(int(query.GetPage())), data.WithSearchFiltersAndByValue(filterProperties),
		data.WithSearchFiltersOrByValue(searchProperties))
}

func (pb *partitionBusiness) GetPartition(
	ctx context.Context,
	request *partitionv1.GetPartitionRequest) (*partitionv1.PartitionObject, error) {
	claims := security.ClaimsFromContext(ctx)
	if claims == nil {
		return nil, fmt.Errorf("partitions can only be pulled by known entities")
	}

	partition, err := pb.partitionRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, err
	}

	partitionObj := partition.ToAPI()

	subject, _ := claims.GetSubject()
	if strings.EqualFold(subject, "service_matrix") {
		props := partitionObj.GetProperties().AsMap()

		props["client_secret"] = partition.ClientSecret
		props["client_discovery_uri"] = pb.cfg.GetOauth2WellKnownOIDC()

		partitionObj.Properties, _ = structpb.NewStruct(props)
	}

	return partitionObj, nil
}

func (pb *partitionBusiness) GetPartitionParents(ctx context.Context, request *partitionv1.GetPartitionParentsRequest) ([]*partitionv1.PartitionObject, error) {

	parentList, err := pb.partitionRepo.GetParents(ctx, request.GetId())
	if err != nil {
		return nil, err
	}

	var parentPartitionList []*partitionv1.PartitionObject
	for _, parent := range parentList {
		parentObj := parent.ToAPI()
		parentPartitionList = append(parentPartitionList, parentObj)
	}
	return parentPartitionList, nil

}

func (pb *partitionBusiness) CreatePartition(
	ctx context.Context,
	request *partitionv1.CreatePartitionRequest) (*partitionv1.PartitionObject, error) {
	tenant, err := pb.tenantRepo.GetByID(ctx, request.GetTenantId())
	if err != nil {
		return nil, err
	}

	partition := &models.Partition{
		ParentID:    request.GetParentId(),
		Name:        request.GetName(),
		Description: request.GetDescription(),
		Properties:  request.GetProperties().AsMap(),
	}

	partition.GenID(ctx)
	partition.TenantID = tenant.GetID()
	partition.PartitionID = tenant.PartitionID

	err = pb.partitionRepo.Create(ctx, partition)
	if err != nil {
		return nil, err
	}

	err = pb.eventsMan.Emit(ctx, events.EventKeyPartitionSynchronization, data.JSONMap{"id": partition.GetID()})
	if err != nil {
		return nil, err
	}

	return partition.ToAPI(), nil
}

func (pb *partitionBusiness) UpdatePartition(
	ctx context.Context,
	request *partitionv1.UpdatePartitionRequest) (*partitionv1.PartitionObject, error) {
	partition, err := pb.partitionRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, err
	}

	jsonMap := partition.Properties
	for k, v := range request.GetProperties().AsMap() {
		jsonMap[k] = v
	}

	if request.GetName() != "" {
		partition.Name = request.GetName()
	}
	if request.GetDescription() != "" {
		partition.Description = request.GetDescription()
	}
	partition.Properties = jsonMap

	_, err = pb.partitionRepo.Update(ctx, partition, "name", "description", "properties")
	if err != nil {
		return nil, err
	}

	return partition.ToAPI(), nil
}

func (pb *partitionBusiness) ListPartitionRoles(
	ctx context.Context,
	request *partitionv1.ListPartitionRoleRequest,
) (*partitionv1.ListPartitionRoleResponse, error) {
	partitionRoleList, err := pb.partitionRoleRepo.GetByPartitionID(ctx, request.GetPartitionId())
	if err != nil {
		return nil, err
	}

	response := make([]*partitionv1.PartitionRoleObject, 0)

	for _, pat := range partitionRoleList {
		response = append(response, toAPIPartitionRole(pat))
	}

	return &partitionv1.ListPartitionRoleResponse{
		Role: response,
	}, nil
}

func (pb *partitionBusiness) RemovePartitionRole(
	ctx context.Context,
	request *partitionv1.RemovePartitionRoleRequest,
) error {
	err := pb.partitionRoleRepo.Delete(ctx, request.GetId())
	if err != nil {
		return err
	}

	return nil
}

func (pb *partitionBusiness) CreatePartitionRole(
	ctx context.Context,
	request *partitionv1.CreatePartitionRoleRequest) (
	*partitionv1.PartitionRoleObject, error) {
	partition, err := pb.partitionRepo.GetByID(ctx, request.GetPartitionId())
	if err != nil {
		return nil, err
	}

	jsonMap := request.GetProperties().AsMap()

	partitionRole := &models.PartitionRole{
		Name:       request.GetName(),
		Properties: jsonMap,
		BaseModel: data.BaseModel{
			PartitionID: partition.PartitionID,
			TenantID:    partition.TenantID,
		},
	}

	err = pb.partitionRoleRepo.Create(ctx, partitionRole)
	if err != nil {
		return nil, err
	}

	return toAPIPartitionRole(partitionRole), nil
}

func ReQueuePrimaryPartitionsForSync(ctx context.Context, partitionRepo repository.PartitionRepository, eventsMan fevents.Manager, query *data.SearchQuery) error {

	jobResult, err := partitionRepo.Search(ctx, query)
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

		for _, partition := range result.Item() {
			err = eventsMan.Emit(ctx, events.EventKeyPartitionSynchronization, data.JSONMap{"id": partition.GetID()})
			if err != nil {
				return err
			}
		}
	}
}
