// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package business

import (
	"context"
	"fmt"
	"maps"
	"strings"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/antinvestor/service-authentication/pkg/partitionpolicy"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

type PartitionBusiness interface {
	GetPartition(ctx context.Context, request *tenancyv1.GetPartitionRequest) (*tenancyv1.PartitionObject, error)
	GetPartitionParents(ctx context.Context, request *tenancyv1.GetPartitionParentsRequest) ([]*tenancyv1.PartitionObject, error)
	CreatePartition(
		ctx context.Context,
		request *tenancyv1.CreatePartitionRequest) (*tenancyv1.PartitionObject, error)
	UpdatePartition(
		ctx context.Context,
		request *tenancyv1.UpdatePartitionRequest) (*tenancyv1.PartitionObject, error)
	RemovePartition(ctx context.Context, id string) error
	ListPartition(
		ctx context.Context,
		request *tenancyv1.ListPartitionRequest) ([]*tenancyv1.PartitionObject, error)

	RemovePartitionRole(ctx context.Context, request *tenancyv1.RemovePartitionRoleRequest) error
	UpdatePartitionRole(ctx context.Context, request *tenancyv1.UpdatePartitionRoleRequest) (*tenancyv1.PartitionRoleObject, error)
	ListPartitionRoles(
		ctx context.Context,
		request *tenancyv1.ListPartitionRoleRequest) (*tenancyv1.ListPartitionRoleResponse, error)
	CreatePartitionRole(
		ctx context.Context,
		request *tenancyv1.CreatePartitionRoleRequest) (*tenancyv1.PartitionRoleObject, error)
}

func NewPartitionBusiness(
	cfg config.TenancyConfig,
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
	cfg                config.TenancyConfig
	tenantRepo         repository.TenantRepository
	partitionRepo      repository.PartitionRepository
	partitionRoleRepo  repository.PartitionRoleRepository
	accessRepo         repository.AccessRepository
	clientRepo         repository.ClientRepository
	serviceAccountRepo repository.ServiceAccountRepository
}

func toAPIPartitionRole(partitionModel *models.PartitionRole) *tenancyv1.PartitionRoleObject {
	return partitionModel.ToAPI()
}

func (pb *partitionBusiness) ListPartition(
	ctx context.Context,
	request *tenancyv1.ListPartitionRequest) ([]*tenancyv1.PartitionObject, error) {

	query := pb.buildSearchQuery(request)
	jobResult, err := pb.partitionRepo.Search(ctx, query)
	if err != nil {
		return nil, err
	}

	var responseObjects []*tenancyv1.PartitionObject
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
func (pb *partitionBusiness) buildSearchQuery(query *tenancyv1.ListPartitionRequest) *data.SearchQuery {
	filterProperties := map[string]any{}

	// Add additional properties from the request
	for _, p := range query.GetProperties() {
		filterProperties[fmt.Sprintf("%s = ? ", p)] = query.GetQuery()
	}

	var limit, offset int
	if cursor := query.GetCursor(); cursor != nil {
		limit = int(cursor.GetLimit())
		if p := cursor.GetPage(); p != "" {
			_, _ = fmt.Sscanf(p, "%d", &offset)
		}
	}

	return data.NewSearchQuery(data.WithSearchLimit(limit),
		data.WithSearchOffset(offset), data.WithSearchFiltersAndByValue(filterProperties))
}

func (pb *partitionBusiness) GetPartition(
	ctx context.Context,
	request *tenancyv1.GetPartitionRequest) (*tenancyv1.PartitionObject, error) {
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

func (pb *partitionBusiness) GetPartitionParents(ctx context.Context, request *tenancyv1.GetPartitionParentsRequest) ([]*tenancyv1.PartitionObject, error) {

	parentList, err := pb.partitionRepo.GetParents(ctx, request.GetId())
	if err != nil {
		return nil, err
	}

	var parentPartitionList []*tenancyv1.PartitionObject
	for _, parent := range parentList {
		parentObj := parent.ToAPI()
		parentPartitionList = append(parentPartitionList, parentObj)
	}
	return parentPartitionList, nil

}

func (pb *partitionBusiness) CreatePartition(
	ctx context.Context,
	request *tenancyv1.CreatePartitionRequest) (*tenancyv1.PartitionObject, error) {
	tenant, err := pb.tenantRepo.GetByID(ctx, request.GetTenantId())
	if err != nil {
		return nil, err
	}

	reqProperties := request.GetProperties().AsMap()
	domain, _ := reqProperties["domain"].(string)
	delete(reqProperties, "domain")
	allowAutoAccess := partitionpolicy.AllowAutoAccess(reqProperties, true)
	reqProperties[partitionpolicy.PropertyAllowAutoAccess] = allowAutoAccess
	delete(reqProperties, partitionpolicy.PropertyAllowAutoAccessSetup)

	partition := &models.Partition{
		ParentID:    request.GetParentId(),
		Name:        request.GetName(),
		Description: request.GetDescription(),
		Domain:      domain,
		Properties:  reqProperties,
	}
	partition.SetAllowAutoAccess(allowAutoAccess)

	partition.GenID(ctx)
	partition.TenantID = tenant.GetID()
	partition.PartitionID = tenant.PartitionID

	err = pb.partitionRepo.Create(ctx, partition)
	if err != nil {
		return nil, err
	}

	err = pb.eventsMan.Emit(ctx, events.EventKeyPartitionHydraSync, data.JSONMap{"id": partition.GetID()})
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
	request *tenancyv1.UpdatePartitionRequest) (*tenancyv1.PartitionObject, error) {
	partition, err := pb.partitionRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, err
	}

	jsonMap := partition.Properties
	if jsonMap == nil {
		jsonMap = make(data.JSONMap)
	}
	delete(jsonMap, partitionpolicy.PropertyAllowAutoAccess)
	delete(jsonMap, partitionpolicy.PropertyAllowAutoAccessSetup)
	reqProperties := request.GetProperties().AsMap()
	if domain, ok := reqProperties["domain"].(string); ok {
		partition.Domain = domain
		delete(reqProperties, "domain")
	}
	if _, ok := reqProperties[partitionpolicy.PropertyAllowAutoAccess]; ok {
		partition.SetAllowAutoAccess(partitionpolicy.AllowAutoAccess(reqProperties, partition.AutoAccessAllowed()))
		delete(reqProperties, partitionpolicy.PropertyAllowAutoAccess)
	}
	if _, ok := reqProperties[partitionpolicy.PropertyAllowAutoAccessSetup]; ok {
		partition.SetAllowAutoAccess(partitionpolicy.AllowAutoAccess(reqProperties, partition.AutoAccessAllowed()))
		delete(reqProperties, partitionpolicy.PropertyAllowAutoAccessSetup)
	}
	maps.Copy(jsonMap, reqProperties)
	jsonMap[partitionpolicy.PropertyAllowAutoAccess] = partition.AutoAccessAllowed()

	if request.GetName() != "" {
		partition.Name = request.GetName()
	}
	if request.GetDescription() != "" {
		partition.Description = request.GetDescription()
	}
	partition.Properties = jsonMap

	_, err = pb.partitionRepo.Update(ctx, partition, "name", "description", "domain", "allow_auto_access", "properties")
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
	request *tenancyv1.UpdatePartitionRoleRequest,
) (*tenancyv1.PartitionRoleObject, error) {
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
	request *tenancyv1.ListPartitionRoleRequest,
) (*tenancyv1.ListPartitionRoleResponse, error) {
	partitionRoleList, err := pb.partitionRoleRepo.GetByPartitionID(ctx, request.GetPartitionId())
	if err != nil {
		return nil, err
	}

	response := make([]*tenancyv1.PartitionRoleObject, 0)

	for _, pat := range partitionRoleList {
		response = append(response, toAPIPartitionRole(pat))
	}

	return &tenancyv1.ListPartitionRoleResponse{
		Data: response,
	}, nil
}

func (pb *partitionBusiness) RemovePartitionRole(
	ctx context.Context,
	request *tenancyv1.RemovePartitionRoleRequest,
) error {
	err := pb.partitionRoleRepo.Delete(ctx, request.GetId())
	if err != nil {
		return err
	}

	return nil
}

func (pb *partitionBusiness) CreatePartitionRole(
	ctx context.Context,
	request *tenancyv1.CreatePartitionRoleRequest) (
	*tenancyv1.PartitionRoleObject, error) {
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
			PartitionID: partition.GetID(),
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
			err = eventsMan.Emit(ctx, events.EventKeyPartitionHydraSync, data.JSONMap{"id": partition.GetID()})
			if err != nil {
				return err
			}

			if emitErr := eventsMan.Emit(ctx, events.EventKeyAuthzPartitionSync, data.JSONMap{"id": partition.GetID()}); emitErr != nil {
				util.Log(ctx).WithError(emitErr).Warn("failed to emit authz partition sync event")
			}
		}
	}
}
