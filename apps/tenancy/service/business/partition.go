package business

import (
	"context"
	"fmt"
	"maps"
	"strings"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
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
	RemovePartition(ctx context.Context, id string) error
	ListPartition(
		ctx context.Context,
		request *partitionv1.ListPartitionRequest) ([]*partitionv1.PartitionObject, error)

	RemovePartitionRole(ctx context.Context, request *partitionv1.RemovePartitionRoleRequest) error
	UpdatePartitionRole(ctx context.Context, request *partitionv1.UpdatePartitionRoleRequest) (*partitionv1.PartitionRoleObject, error)
	ListPartitionRoles(
		ctx context.Context,
		request *partitionv1.ListPartitionRoleRequest) (*partitionv1.ListPartitionRoleResponse, error)
	CreatePartitionRole(
		ctx context.Context,
		request *partitionv1.CreatePartitionRoleRequest) (*partitionv1.PartitionRoleObject, error)
}

func NewPartitionBusiness(
	cfg config.PartitionConfig,
	eventsMan fevents.Manager,
	tenantRepo repository.TenantRepository,
	partitionRepo repository.PartitionRepository,
	partitionRoleRepo repository.PartitionRoleRepository,
	accessRepo repository.AccessRepository,
	clientRepo repository.ClientRepository,
	serviceAccountRepo repository.ServiceAccountRepository,
) PartitionBusiness {
	return &partitionBusiness{
		cfg:                cfg,
		eventsMan:          eventsMan,
		partitionRepo:      partitionRepo,
		partitionRoleRepo:  partitionRoleRepo,
		tenantRepo:         tenantRepo,
		accessRepo:         accessRepo,
		clientRepo:         clientRepo,
		serviceAccountRepo: serviceAccountRepo,
	}
}

type partitionBusiness struct {
	eventsMan          fevents.Manager
	cfg                config.PartitionConfig
	tenantRepo         repository.TenantRepository
	partitionRepo      repository.PartitionRepository
	partitionRoleRepo  repository.PartitionRoleRepository
	accessRepo         repository.AccessRepository
	clientRepo         repository.ClientRepository
	serviceAccountRepo repository.ServiceAccountRepository
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

	var limit, offset int
	if cursor := query.GetCursor(); cursor != nil {
		limit = int(cursor.GetLimit())
		if p := cursor.GetPage(); p != "" {
			_, _ = fmt.Sscanf(p, "%d", &offset)
		}
	}

	return data.NewSearchQuery(data.WithSearchLimit(limit),
		data.WithSearchOffset(offset), data.WithSearchFiltersAndByValue(filterProperties),
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

		if cs, ok := partition.Properties["client_secret"].(string); ok {
			props["client_secret"] = cs
		}
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

	reqProperties := request.GetProperties().AsMap()
	domain, _ := reqProperties["domain"].(string)
	delete(reqProperties, "domain")

	partition := &models.Partition{
		ParentID:    request.GetParentId(),
		Name:        request.GetName(),
		Description: request.GetDescription(),
		Domain:      domain,
		Properties:  reqProperties,
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

	// Emit authz partition sync to write inheritance tuples for partitions with parents.
	if emitErr := pb.eventsMan.Emit(ctx, events.EventKeyAuthzPartitionSync, data.JSONMap{"id": partition.GetID()}); emitErr != nil {
		util.Log(ctx).WithError(emitErr).Warn("failed to emit authz partition sync event")
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
	if jsonMap == nil {
		jsonMap = make(data.JSONMap)
	}
	reqProperties := request.GetProperties().AsMap()
	if domain, ok := reqProperties["domain"].(string); ok {
		partition.Domain = domain
		delete(reqProperties, "domain")
	}
	maps.Copy(jsonMap, reqProperties)

	if request.GetName() != "" {
		partition.Name = request.GetName()
	}
	if request.GetDescription() != "" {
		partition.Description = request.GetDescription()
	}
	partition.Properties = jsonMap

	_, err = pb.partitionRepo.Update(ctx, partition, "name", "description", "domain", "properties")
	if err != nil {
		return nil, err
	}

	return partition.ToAPI(), nil
}

func (pb *partitionBusiness) RemovePartition(ctx context.Context, id string) error {
	// Check for child partitions
	children, err := pb.partitionRepo.GetChildren(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to check child partitions: %w", err)
	}
	if len(children) > 0 {
		return fmt.Errorf("cannot remove partition: %d child partition(s) still exist", len(children))
	}

	// Check for access records
	accessCount, err := pb.accessRepo.CountByPartitionID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to check access records: %w", err)
	}
	if accessCount > 0 {
		return fmt.Errorf("cannot remove partition: %d access record(s) still exist", accessCount)
	}

	// Check for clients
	clientCount, err := pb.clientRepo.CountByPartitionID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to check clients: %w", err)
	}
	if clientCount > 0 {
		return fmt.Errorf("cannot remove partition: %d client(s) still exist", clientCount)
	}

	// Check for service accounts
	saCount, err := pb.serviceAccountRepo.CountByPartitionID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to check service accounts: %w", err)
	}
	if saCount > 0 {
		return fmt.Errorf("cannot remove partition: %d service account(s) still exist", saCount)
	}

	return pb.partitionRepo.Delete(ctx, id)
}

func (pb *partitionBusiness) UpdatePartitionRole(
	ctx context.Context,
	request *partitionv1.UpdatePartitionRoleRequest,
) (*partitionv1.PartitionRoleObject, error) {
	role, err := pb.partitionRoleRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, err
	}

	if request.GetName() != "" {
		role.Name = request.GetName()
	}

	if request.GetProperties() != nil {
		if role.Properties == nil {
			role.Properties = make(data.JSONMap)
		}
		reqProps := request.GetProperties().AsMap()
		isDefault, ok := reqProps["is_default"].(bool)
		if ok {
			role.IsDefault = isDefault
			delete(reqProps, "is_default")
		}
		maps.Copy(role.Properties, reqProps)
	}

	_, err = pb.partitionRoleRepo.Update(ctx, role, "name", "is_default", "properties")
	if err != nil {
		return nil, err
	}

	return toAPIPartitionRole(role), nil
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
		Data: response,
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

	isDefault, _ := jsonMap["is_default"].(bool)
	delete(jsonMap, "is_default")

	partitionRole := &models.PartitionRole{
		Name:       request.GetName(),
		IsDefault:  isDefault,
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

			if emitErr := eventsMan.Emit(ctx, events.EventKeyAuthzPartitionSync, data.JSONMap{"id": partition.GetID()}); emitErr != nil {
				util.Log(ctx).WithError(emitErr).Warn("failed to emit authz partition sync event")
			}
		}
	}
}
