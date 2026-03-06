package business

import (
	"context"
	"fmt"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
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
	GetAccess(ctx context.Context, request *partitionv1.GetAccessRequest) (*partitionv1.AccessObject, error)
	ListAccess(ctx context.Context, request *partitionv1.ListAccessRequest) ([]*partitionv1.AccessObject, error)
	RemoveAccess(ctx context.Context, request *partitionv1.RemoveAccessRequest) error
	CreateAccess(ctx context.Context, request *partitionv1.CreateAccessRequest) (*partitionv1.AccessObject, error)

	RemoveAccessRole(ctx context.Context, request *partitionv1.RemoveAccessRoleRequest) error
	ListAccessRoles(
		ctx context.Context,
		request *partitionv1.ListAccessRoleRequest) (*partitionv1.ListAccessRoleResponse, error)
	CreateAccessRole(
		ctx context.Context,
		request *partitionv1.CreateAccessRoleRequest) (*partitionv1.AccessRoleObject, error)
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
	request *partitionv1.GetAccessRequest) (*partitionv1.AccessObject, error) {
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
	request *partitionv1.ListAccessRequest,
) ([]*partitionv1.AccessObject, error) {
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

	result := make([]*partitionv1.AccessObject, 0, len(accesses))
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
	request *partitionv1.RemoveAccessRequest) error {
	// Look up the access record before deleting to get tenant/partition info
	access, err := ab.accessRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return err
	}

	err = ab.accessRepo.Delete(ctx, request.GetId())
	if err != nil {
		return err
	}

	// Emit event to delete the tenancy_access tuple asynchronously
	if ab.eventsMan != nil {
		tenancyPath := fmt.Sprintf("%s/%s", access.TenantID, access.PartitionID)
		accessTuple := authz.BuildAccessTuple(tenancyPath, access.ProfileID)
		payload := events.TuplesToPayload([]security.RelationTuple{accessTuple})
		if emitErr := ab.eventsMan.Emit(ctx, events.EventKeyAuthzTupleDelete, payload); emitErr != nil {
			util.Log(ctx).WithError(emitErr).Warn("failed to emit tenancy_access tuple delete event")
		}
	}

	return nil
}

func (ab *accessBusiness) CreateAccess(
	ctx context.Context,
	request *partitionv1.CreateAccessRequest) (*partitionv1.AccessObject, error) {
	logger := ab.service.Log(ctx)

	logger.WithField("request", request).Debug(" supplied request")

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

	// Emit event to write tenancy_access tuple asynchronously
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

	logger.WithField("access", access).Debug(" access created")
	partitionObject := partition.ToAPI()

	return access.ToAPI(partitionObject)
}

func (ab *accessBusiness) ListAccessRoles(
	ctx context.Context,
	request *partitionv1.ListAccessRoleRequest) (*partitionv1.ListAccessRoleResponse, error) {
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

	partitionRoleIDMap := make(map[string]*partitionv1.PartitionRoleObject)
	for _, partitionRole := range partitionRoles {
		partitionRoleIDMap[partitionRole.ID] = toAPIPartitionRole(partitionRole)
	}

	response := make([]*partitionv1.AccessRoleObject, 0)

	for _, acc := range accessRoleList {
		response = append(response, acc.ToAPI(partitionRoleIDMap[acc.PartitionRoleID]))
	}

	return &partitionv1.ListAccessRoleResponse{
		Data: response,
	}, nil
}

func (ab *accessBusiness) RemoveAccessRole(
	ctx context.Context,
	request *partitionv1.RemoveAccessRoleRequest) error {
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
		payload := events.TuplesToPayload(tuples)
		if emitErr := ab.eventsMan.Emit(ctx, events.EventKeyAuthzTupleDelete, payload); emitErr != nil {
			util.Log(ctx).WithError(emitErr).Warn("failed to emit authorization tuple delete event")
		}
	}

	return nil
}

func (ab *accessBusiness) CreateAccessRole(
	ctx context.Context,
	request *partitionv1.CreateAccessRoleRequest) (*partitionv1.AccessRoleObject, error) {
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

	// Emit event to write cross-service Keto tuples asynchronously
	if ab.eventsMan != nil {
		roleName := partitionRoles[0].Name
		tenancyPath := fmt.Sprintf("%s/%s", access.TenantID, access.PartitionID)
		tuples := authz.BuildRoleTuples(tenancyPath, access.ProfileID, roleName)
		payload := events.TuplesToPayload(tuples)
		if emitErr := ab.eventsMan.Emit(ctx, events.EventKeyAuthzTupleWrite, payload); emitErr != nil {
			util.Log(ctx).WithError(emitErr).Warn("failed to emit authorization tuple write event")
		}
	}

	partitionRoleObj := toAPIPartitionRole(partitionRoles[0])
	return accessRole.ToAPI(partitionRoleObj), nil
}
