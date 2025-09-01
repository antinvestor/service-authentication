package business

import (
	"context"
	"errors"
	"strings"

	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/framedata"
	"google.golang.org/protobuf/types/known/structpb"
)

type PartitionBusiness interface {
	GetPartition(ctx context.Context, request *partitionv1.GetPartitionRequest) (*partitionv1.PartitionObject, error)
	CreatePartition(
		ctx context.Context,
		request *partitionv1.CreatePartitionRequest) (*partitionv1.PartitionObject, error)
	UpdatePartition(
		ctx context.Context,
		request *partitionv1.UpdatePartitionRequest) (*partitionv1.PartitionObject, error)
	ListPartition(
		ctx context.Context,
		request *partitionv1.ListPartitionRequest,
		stream partitionv1.PartitionService_ListPartitionServer) error

	RemovePartitionRole(ctx context.Context, request *partitionv1.RemovePartitionRoleRequest) error
	ListPartitionRoles(
		ctx context.Context,
		request *partitionv1.ListPartitionRoleRequest) (*partitionv1.ListPartitionRoleResponse, error)
	CreatePartitionRole(
		ctx context.Context,
		request *partitionv1.CreatePartitionRoleRequest) (*partitionv1.PartitionRoleObject, error)
}

func NewPartitionBusiness(service *frame.Service) PartitionBusiness {
	tenantRepository := repository.NewTenantRepository(service)
	partitionRepository := repository.NewPartitionRepository(service)

	return &partitionBusiness{
		service:       service,
		partitionRepo: partitionRepository,
		tenantRepo:    tenantRepository,
	}
}

type partitionBusiness struct {
	service       *frame.Service
	tenantRepo    repository.TenantRepository
	partitionRepo repository.PartitionRepository
}

func toAPIPartitionRole(partitionModel *models.PartitionRole) *partitionv1.PartitionRoleObject {
	properties, _ := partitionModel.Properties.ToStructPB()

	return &partitionv1.PartitionRoleObject{
		PartitionId: partitionModel.PartitionID,
		Name:        partitionModel.Name,
		Properties:  properties,
	}
}

func (pb *partitionBusiness) ListPartition(
	ctx context.Context,
	request *partitionv1.ListPartitionRequest,
	stream partitionv1.PartitionService_ListPartitionServer,
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

	jobResult, err := pb.partitionRepo.Search(ctx, query)
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

		var responseObjects []*partitionv1.PartitionObject
		for _, partition := range result.Item() {
			responseObjects = append(responseObjects, partition.ToAPI())
		}

		err = stream.Send(&partitionv1.ListPartitionResponse{Data: responseObjects})
		if err != nil {
			return err
		}

	}
}

func (pb *partitionBusiness) GetPartition(
	ctx context.Context,
	request *partitionv1.GetPartitionRequest) (*partitionv1.PartitionObject, error) {
	claims := frame.ClaimsFromContext(ctx)

	partition, err := pb.partitionRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, err
	}

	partitionObj := partition.ToAPI()

	var cfg *config.PartitionConfig
	if c, ok := pb.service.Config().(*config.PartitionConfig); ok {
		cfg = c
	} else {
		return nil, errors.New("invalid configuration type")
	}

	if strings.EqualFold(claims.GetServiceName(), "service_matrix") {
		props := partitionObj.GetProperties().AsMap()

		props["client_secret"] = partition.ClientSecret
		props["client_discovery_uri"] = cfg.GetOauth2WellKnownOIDC()
		partitionObj.Properties, _ = structpb.NewStruct(props)
	}

	return partitionObj, nil
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

	err = pb.partitionRepo.Save(ctx, partition)
	if err != nil {
		return nil, err
	}

	err = pb.service.Emit(ctx, events.EventKeyPartitionSynchronization, partition.GetID())
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

	partition.Name = request.GetName()
	partition.Description = request.GetDescription()
	partition.Properties = jsonMap

	err = pb.partitionRepo.Save(ctx, partition)
	if err != nil {
		return nil, err
	}

	return partition.ToAPI(), nil
}

func (pb *partitionBusiness) ListPartitionRoles(
	ctx context.Context,
	request *partitionv1.ListPartitionRoleRequest,
) (*partitionv1.ListPartitionRoleResponse, error) {
	partitionRoleList, err := pb.partitionRepo.GetRoles(ctx, request.GetPartitionId())
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
	err := pb.partitionRepo.RemoveRole(ctx, request.GetId())
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
		BaseModel: frame.BaseModel{
			PartitionID: partition.PartitionID,
			TenantID:    partition.TenantID,
		},
	}

	err = pb.partitionRepo.SaveRole(ctx, partitionRole)
	if err != nil {
		return nil, err
	}

	return toAPIPartitionRole(partitionRole), nil
}

func ReQueuePrimaryPartitionsForSync(ctx context.Context, svc *frame.Service, query *framedata.SearchQuery) error {
	partitionRepository := repository.NewPartitionRepository(svc)

	jobResult, err := partitionRepository.Search(ctx, query)
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
			err = svc.Emit(ctx, events.EventKeyPartitionSynchronization, partition.GetID())
			if err != nil {
				return err
			}
		}
	}
}
