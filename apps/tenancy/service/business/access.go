package business

import (
	"context"

	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
)

type AccessBusiness interface {
	GetAccess(ctx context.Context, request *partitionv1.GetAccessRequest) (*partitionv1.AccessObject, error)
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

func NewAccessBusiness(_ context.Context, service *frame.Service) AccessBusiness {
	accessRepo := repository.NewAccessRepository(service)
	partitionRepo := repository.NewPartitionRepository(service)

	return &accessBusiness{
		service:       service,
		accessRepo:    accessRepo,
		partitionRepo: partitionRepo,
	}
}

type accessBusiness struct {
	service       *frame.Service
	accessRepo    repository.AccessRepository
	partitionRepo repository.PartitionRepository
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

	var partition *models.Partition
	partitionID := request.GetPartitionId()
	if partitionID == "" {
		partitionID = request.GetClientId()
	}

	partition, err = ab.partitionRepo.GetByID(ctx, partitionID)
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

func (ab *accessBusiness) RemoveAccess(
	ctx context.Context,
	request *partitionv1.RemoveAccessRequest) error {
	err := ab.accessRepo.Delete(ctx, request.GetId())
	if err != nil {
		return err
	}

	return nil
}

func (ab *accessBusiness) CreateAccess(
	ctx context.Context,
	request *partitionv1.CreateAccessRequest) (*partitionv1.AccessObject, error) {
	logger := ab.service.Log(ctx)

	logger.WithField("request", request).Debug(" supplied request")

	var err error
	var partition *models.Partition
	partitionID := request.GetPartitionId()
	if partitionID == "" {
		partitionID = request.GetClientId()
	}

	partition, err = ab.partitionRepo.GetByID(ctx, partitionID)
	if err != nil {
		return nil, err
	}

	access, err := ab.accessRepo.GetByPartitionAndProfile(ctx, partition.GetID(), request.GetProfileId())
	if err != nil {
		if !frame.ErrorIsNoRows(err) {
			return nil, err
		}
	} else {
		partitionObject := partition.ToAPI()
		return access.ToAPI(partitionObject)
	}

	access = &models.Access{
		ProfileID: request.GetProfileId(),
		BaseModel: frame.BaseModel{
			TenantID:    partition.TenantID,
			PartitionID: partition.GetID(),
		},
	}

	err = ab.accessRepo.Save(ctx, access)
	if err != nil {
		return nil, err
	}

	logger.WithField("access", access).Debug(" access created")
	partitionObject := partition.ToAPI()

	return access.ToAPI(partitionObject)
}

func (ab *accessBusiness) ListAccessRoles(
	ctx context.Context,
	request *partitionv1.ListAccessRoleRequest) (*partitionv1.ListAccessRoleResponse, error) {
	accessRoleList, err := ab.accessRepo.GetRoles(ctx, request.GetAccessId())
	if err != nil {
		return nil, err
	}

	parititionRoleIDs := make([]string, 0)

	for _, accessR := range accessRoleList {
		parititionRoleIDs = append(parititionRoleIDs, accessR.PartitionRoleID)
	}

	partitionRoles, err := ab.partitionRepo.GetRolesByID(ctx, parititionRoleIDs...)
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
		Role: response,
	}, nil
}

func (ab *accessBusiness) RemoveAccessRole(
	ctx context.Context,
	request *partitionv1.RemoveAccessRoleRequest) error {
	err := ab.accessRepo.RemoveRole(ctx, request.GetId())
	if err != nil {
		return err
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

	partitionRoles, err := ab.partitionRepo.GetRolesByID(ctx, request.GetPartitionRoleId())
	if err != nil {
		return nil, err
	}

	accessRole := &models.AccessRole{
		AccessID:        access.GetID(),
		PartitionRoleID: partitionRoles[0].GetID(),
	}

	err = ab.accessRepo.SaveRole(ctx, accessRole)
	if err != nil {
		return nil, err
	}

	partitionRoleObj := toAPIPartitionRole(partitionRoles[0])
	return accessRole.ToAPI(partitionRoleObj), nil
}
