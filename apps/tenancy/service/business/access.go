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

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

type AccessBusiness interface {
	GetAccess(ctx context.Context, request *tenancyv1.GetAccessRequest) (*tenancyv1.AccessObject, error)
	ListAccess(ctx context.Context, request *tenancyv1.ListAccessRequest) ([]*tenancyv1.AccessObject, error)
	RemoveAccess(ctx context.Context, request *tenancyv1.RemoveAccessRequest) error
	CreateAccess(ctx context.Context, request *tenancyv1.CreateAccessRequest) (*tenancyv1.AccessObject, error)

	RemoveAccessRole(ctx context.Context, request *tenancyv1.RemoveAccessRoleRequest) error
	ListAccessRoles(
		ctx context.Context,
		request *tenancyv1.ListAccessRoleRequest) (*tenancyv1.ListAccessRoleResponse, error)
	CreateAccessRole(
		ctx context.Context,
		request *tenancyv1.CreateAccessRoleRequest) (*tenancyv1.AccessRoleObject, error)
}

func NewAccessBusiness(
	service *frame.Service,
	eventsMan fevents.Manager,
	accessRepo repository.AccessRepository,
	accessRoleRepo repository.AccessRoleRepository,
	partitionRepo repository.PartitionRepository,
	partitionRoleRepo repository.PartitionRoleRepository,
	clientRepo repository.ClientRepository,
) AccessBusiness {
	return &accessBusiness{
		service:           service,
		eventsMan:         eventsMan,
		accessRepo:        accessRepo,
		accessRoleRepo:    accessRoleRepo,
		partitionRepo:     partitionRepo,
		partitionRoleRepo: partitionRoleRepo,
		clientRepo:        clientRepo,
	}
}

type accessBusiness struct {
	service           *frame.Service
	eventsMan         fevents.Manager
	accessRepo        repository.AccessRepository
	accessRoleRepo    repository.AccessRoleRepository
	partitionRepo     repository.PartitionRepository
	partitionRoleRepo repository.PartitionRoleRepository
	clientRepo        repository.ClientRepository
}

// resolvePartition finds a partition by partition ID or by looking up the Client's
// partition when a Hydra client_id is provided.
func (ab *accessBusiness) resolvePartition(ctx context.Context, partitionID, clientID string) (*models.Partition, error) {
	if partitionID != "" {
		return ab.partitionRepo.GetByID(ctx, partitionID)
	}
	if clientID == "" {
		return nil, fmt.Errorf("partition_id or client_id is required")
	}

	// First try as a partition ID (backward compatibility)
	partition, err := ab.partitionRepo.GetByID(ctx, clientID)
	if err == nil {
		return partition, nil
	}

	// Fall back to looking up the Client record by its Hydra client_id
	if ab.clientRepo != nil {
		client, clientErr := ab.clientRepo.GetByClientID(ctx, clientID)
		if clientErr != nil {
			return nil, fmt.Errorf("no partition or client found for id %q: %w", clientID, clientErr)
		}
		return ab.partitionRepo.GetByID(ctx, client.PartitionID)
	}

	return nil, err
}

func (ab *accessBusiness) GetAccess(
	ctx context.Context,
	request *tenancyv1.GetAccessRequest) (*tenancyv1.AccessObject, error) {
	var err error
	var access *models.Access

	if request.GetAccessId() != "" {
		access, err = ab.accessRepo.GetByID(ctx, request.GetAccessId())
		if err != nil {
			return nil, err
		}

		partition, partitionErr := ab.partitionRepo.GetByID(ctx, access.PartitionID)
		if partitionErr != nil {
			return nil, partitionErr
		}

		partitionObject := partition.ToAPI()

		return access.ToAPI(partitionObject)
	}

	partition, err := ab.resolvePartition(ctx, request.GetPartitionId(), request.GetClientId())
	if err != nil {
		return nil, err
	}

	access, err = ab.accessRepo.GetByPartitionAndProfile(ctx, partition.GetID(), request.GetProfileId())
	if err != nil {
		return nil, err
	}

	partitionObject := partition.ToAPI()

	return access.ToAPI(partitionObject)
}

func (ab *accessBusiness) ListAccess(
	ctx context.Context,
	request *tenancyv1.ListAccessRequest,
) ([]*tenancyv1.AccessObject, error) {
	var accesses []*models.Access
	var err error

	if request.GetPartitionId() != "" {
		accesses, err = ab.accessRepo.ListByPartition(ctx, request.GetPartitionId())
	} else if request.GetProfileId() != "" {
		accesses, err = ab.accessRepo.ListByProfileID(ctx, request.GetProfileId())
	} else {
		return nil, fmt.Errorf("partition_id or profile_id is required")
	}
	if err != nil {
		return nil, err
	}

	result := make([]*tenancyv1.AccessObject, 0, len(accesses))
	for _, access := range accesses {
		partition, partitionErr := ab.partitionRepo.GetByID(ctx, access.PartitionID)
		if partitionErr != nil {
			continue
		}
		obj, apiErr := access.ToAPI(partition.ToAPI())
		if apiErr != nil {
			continue
		}
		result = append(result, obj)
	}

	return result, nil
}

func (ab *accessBusiness) RemoveAccess(
	ctx context.Context,
	request *tenancyv1.RemoveAccessRequest) error {
	logger := ab.service.Log(ctx)

	// Look up the access record before deleting to get tenant/partition info
	access, err := ab.accessRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return err
	}

	// Collect all role tuples before deleting so we can clean up Keto fully.
	tenancyPath := fmt.Sprintf("%s/%s", access.TenantID, access.PartitionID)
	var roleTuples []security.RelationTuple

	accessRoles, roleErr := ab.accessRoleRepo.GetByAccessID(ctx, request.GetId())
	if roleErr != nil {
		logger.WithError(roleErr).Warn("failed to list access roles for cleanup")
	} else if len(accessRoles) > 0 {
		roleIDs := make([]string, 0, len(accessRoles))
		for _, ar := range accessRoles {
			roleIDs = append(roleIDs, ar.PartitionRoleID)
		}

		roles, resolveErr := ab.partitionRoleRepo.GetRolesByID(ctx, roleIDs...)
		if resolveErr != nil {
			logger.WithError(resolveErr).Warn("failed to resolve role names for cleanup")
		} else {
			for _, role := range roles {
				roleTuples = append(roleTuples, authz.BuildRoleTuples(tenancyPath, access.ProfileID, role.Name)...)
			}
		}
	}

	err = ab.accessRepo.Delete(ctx, request.GetId())
	if err != nil {
		return err
	}

	// Delete all Keto tuples: member, service (if root), and all role tuples
	if ab.eventsMan != nil {
		tuples := []security.RelationTuple{
			authz.BuildAccessTuple(tenancyPath, access.ProfileID),
		}

		if authz.IsRootPartition(access.PartitionID) {
			tuples = append(tuples, authz.BuildServiceAccessTuple(tenancyPath, access.ProfileID))
		}

		tuples = append(tuples, roleTuples...)

		payload := events.TuplesToPayload(tuples)
		if emitErr := ab.eventsMan.Emit(ctx, events.EventKeyAuthzTupleDelete, payload); emitErr != nil {
			logger.WithError(emitErr).Warn("failed to emit authorization tuple delete event")
		}
	}

	return nil
}

func (ab *accessBusiness) CreateAccess(
	ctx context.Context,
	request *tenancyv1.CreateAccessRequest) (*tenancyv1.AccessObject, error) {
	logger := ab.service.Log(ctx)

	logger.Debug("creating access record")

	partition, err := ab.resolvePartition(ctx, request.GetPartitionId(), request.GetClientId())
	if err != nil {
		return nil, err
	}

	access, err := ab.accessRepo.GetByPartitionAndProfile(ctx, partition.GetID(), request.GetProfileId())
	if err != nil {
		if !data.ErrorIsNoRows(err) {
			return nil, err
		}
	} else {
		partitionObject := partition.ToAPI()
		return access.ToAPI(partitionObject)
	}

	access = &models.Access{
		ProfileID: request.GetProfileId(),
		BaseModel: data.BaseModel{
			TenantID:    partition.TenantID,
			PartitionID: partition.GetID(),
		},
	}

	err = ab.accessRepo.Create(ctx, access)
	if err != nil {
		return nil, err
	}

	// Emit event to write tenancy_access#member tuple asynchronously
	if ab.eventsMan != nil {
		tenancyPath := fmt.Sprintf("%s/%s", partition.TenantID, partition.GetID())
		accessTuple := authz.BuildAccessTuple(tenancyPath, request.GetProfileId())
		payload := events.TuplesToPayload([]security.RelationTuple{accessTuple})
		if emitErr := ab.eventsMan.Emit(ctx, events.EventKeyAuthzTupleWrite, payload); emitErr != nil {
			util.Log(ctx).WithError(emitErr).Warn("failed to emit tenancy_access tuple write event")
		}
	}

	// Auto-assign default partition roles
	defaultRoles, defaultErr := ab.partitionRoleRepo.GetDefaultByPartitionID(ctx, partition.GetID())
	if defaultErr != nil {
		logger.WithError(defaultErr).Warn("failed to query default partition roles")
	}
	if len(defaultRoles) > 0 {
		tenancyPath := fmt.Sprintf("%s/%s", partition.TenantID, partition.GetID())
		for _, role := range defaultRoles {
			accessRole := &models.AccessRole{
				AccessID:        access.GetID(),
				PartitionRoleID: role.GetID(),
			}
			if createErr := ab.accessRoleRepo.Create(ctx, accessRole); createErr != nil {
				logger.WithError(createErr).Warn("failed to create default access role")
				continue
			}
			if ab.eventsMan != nil {
				tuples := authz.BuildRoleTuples(tenancyPath, request.GetProfileId(), role.Name)
				payload := events.TuplesToPayload(tuples)
				if emitErr := ab.eventsMan.Emit(ctx, events.EventKeyAuthzTupleWrite, payload); emitErr != nil {
					logger.WithError(emitErr).Warn("failed to emit default role tuple write")
				}
			}
		}
	}

	logger.WithField("access_id", access.GetID()).Debug("access created")
	partitionObject := partition.ToAPI()

	return access.ToAPI(partitionObject)
}

func (ab *accessBusiness) ListAccessRoles(
	ctx context.Context,
	request *tenancyv1.ListAccessRoleRequest) (*tenancyv1.ListAccessRoleResponse, error) {
	accessRoleList, err := ab.accessRoleRepo.GetByAccessID(ctx, request.GetAccessId())
	if err != nil {
		return nil, err
	}

	parititionRoleIDs := make([]string, 0)

	for _, accessR := range accessRoleList {
		parititionRoleIDs = append(parititionRoleIDs, accessR.PartitionRoleID)
	}

	partitionRoles, err := ab.partitionRoleRepo.GetRolesByID(ctx, parititionRoleIDs...)
	if err != nil {
		return nil, err
	}

	partitionRoleIDMap := make(map[string]*tenancyv1.PartitionRoleObject)
	for _, partitionRole := range partitionRoles {
		partitionRoleIDMap[partitionRole.ID] = toAPIPartitionRole(partitionRole)
	}

	response := make([]*tenancyv1.AccessRoleObject, 0)

	for _, acc := range accessRoleList {
		response = append(response, acc.ToAPI(partitionRoleIDMap[acc.PartitionRoleID]))
	}

	return &tenancyv1.ListAccessRoleResponse{
		Data: response,
	}, nil
}

func (ab *accessBusiness) RemoveAccessRole(
	ctx context.Context,
	request *tenancyv1.RemoveAccessRoleRequest) error {
	// Look up the access role to get the profile and role info before deleting
	accessRole, err := ab.accessRoleRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return err
	}

	access, accessErr := ab.accessRepo.GetByID(ctx, accessRole.AccessID)
	if accessErr != nil {
		return accessErr
	}

	partitionRoles, roleErr := ab.partitionRoleRepo.GetRolesByID(ctx, accessRole.PartitionRoleID)
	if roleErr != nil {
		return roleErr
	}

	err = ab.accessRoleRepo.Delete(ctx, request.GetId())
	if err != nil {
		return err
	}

	// Emit event to delete cross-service Keto tuples asynchronously
	if ab.eventsMan != nil && len(partitionRoles) > 0 {
		roleName := partitionRoles[0].Name
		tenancyPath := fmt.Sprintf("%s/%s", access.TenantID, access.PartitionID)
		tuples := authz.BuildRoleTuples(tenancyPath, access.ProfileID, roleName)

		// Also remove the service tuple if removing owner/admin from root partition
		if authz.IsRootPartition(access.PartitionID) &&
			(roleName == authz.RoleOwner || roleName == authz.RoleAdmin) {
			tuples = append(tuples, authz.BuildServiceAccessTuple(tenancyPath, access.ProfileID))
		}

		payload := events.TuplesToPayload(tuples)
		if emitErr := ab.eventsMan.Emit(ctx, events.EventKeyAuthzTupleDelete, payload); emitErr != nil {
			util.Log(ctx).WithError(emitErr).Warn("failed to emit authorization tuple delete event")
		}
	}

	return nil
}

func (ab *accessBusiness) CreateAccessRole(
	ctx context.Context,
	request *tenancyv1.CreateAccessRoleRequest) (*tenancyv1.AccessRoleObject, error) {
	access, err := ab.accessRepo.GetByID(ctx, request.GetAccessId())
	if err != nil {
		return nil, err
	}

	partitionRoles, err := ab.partitionRoleRepo.GetRolesByID(ctx, request.GetPartitionRoleId())
	if err != nil {
		return nil, err
	}

	accessRole := &models.AccessRole{
		AccessID:        access.GetID(),
		PartitionRoleID: partitionRoles[0].GetID(),
	}

	err = ab.accessRoleRepo.Create(ctx, accessRole)
	if err != nil {
		return nil, err
	}

	// Emit event to write Keto tuples asynchronously.
	// Tuples are written to both service_tenancy and tenancy_access.
	// OPL bridge tuples (written during partition sync) propagate the role
	// from tenancy_access to all service namespaces — no per-namespace
	// code needed here.
	if ab.eventsMan != nil {
		roleName := partitionRoles[0].Name
		tenancyPath := fmt.Sprintf("%s/%s", access.TenantID, access.PartitionID)
		tuples := authz.BuildRoleTuples(tenancyPath, access.ProfileID, roleName)

		// Root partition owner/admin users receive the "internal" JWT role
		// at login. Frame's TenancyAccessChecker checks the "service"
		// relation for internal callers, so they need this tuple.
		if authz.IsRootPartition(access.PartitionID) &&
			(roleName == authz.RoleOwner || roleName == authz.RoleAdmin) {
			tuples = append(tuples, authz.BuildServiceAccessTuple(tenancyPath, access.ProfileID))
		}

		payload := events.TuplesToPayload(tuples)
		if emitErr := ab.eventsMan.Emit(ctx, events.EventKeyAuthzTupleWrite, payload); emitErr != nil {
			util.Log(ctx).WithError(emitErr).Warn("failed to emit authorization tuple write event")
		}
	}

	partitionRoleObj := toAPIPartitionRole(partitionRoles[0])
	return accessRole.ToAPI(partitionRoleObj), nil
}

// ReQueueAccessesForSync re-queues all access records for authorization tuple sync.
// This ensures that access records created outside the normal RPC flow (e.g. via
// SQL migrations) get their tenancy_access tuples written to Keto.
func ReQueueAccessesForSync(ctx context.Context, accessRepo repository.AccessRepository, eventsMan fevents.Manager, query *data.SearchQuery) error {
	jobResult, err := accessRepo.Search(ctx, query)
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
		for _, access := range result.Item() {
			if emitErr := eventsMan.Emit(ctx, events.EventKeyAuthzAccessSync, data.JSONMap{"id": access.GetID()}); emitErr != nil {
				util.Log(ctx).WithError(emitErr).WithField("access_id", access.GetID()).
					Warn("failed to emit access authz sync event")
			}
		}
	}
}
