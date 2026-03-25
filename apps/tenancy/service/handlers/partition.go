package handlers

import (
	"context"

	"buf.build/gen/go/antinvestor/partition/connectrpc/go/partition/v1/partitionv1connect"
	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

type PartitionServer struct {
	svc       *frame.Service
	eventsMan events.Manager

	ProfileCli         profilev1connect.ProfileServiceClient
	PartitionRepo      repository.PartitionRepository
	ClientRepo         repository.ClientRepository
	ServiceAccountRepo repository.ServiceAccountRepository

	PartitionBusiness      business.PartitionBusiness
	TenantBusiness         business.TenantBusiness
	AccessBusiness         business.AccessBusiness
	PageBusiness           business.PageBusiness
	ClientBusiness         business.ClientBusiness
	ServiceAccountBusiness business.ServiceAccountBusiness
	partitionv1connect.UnimplementedPartitionServiceHandler
}

// NewPartitionServer creates a new PartitionServer with injected dependencies
func NewPartitionServer(ctx context.Context, service *frame.Service, auth security.Authorizer, profileCli profilev1connect.ProfileServiceClient) *PartitionServer {
	// Create all repositories once
	dbPool := service.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName)
	workMan := service.WorkManager()

	tenantRepo := repository.NewTenantRepository(ctx, dbPool, workMan)
	partitionRepo := repository.NewPartitionRepository(ctx, dbPool, workMan)
	partitionRoleRepo := repository.NewPartitionRoleRepository(ctx, dbPool, workMan)
	accessRepo := repository.NewAccessRepository(ctx, dbPool, workMan)
	accessRoleRepo := repository.NewAccessRoleRepository(ctx, dbPool, workMan)
	pageRepo := repository.NewPageRepository(ctx, dbPool, workMan)
	clientRepo := repository.NewClientRepository(ctx, dbPool, workMan)
	serviceAccountRepo := repository.NewServiceAccountRepository(ctx, dbPool, workMan)

	cfg := service.Config().(*config.PartitionConfig)
	eventsMan := service.EventsManager()

	// Create business layers with repository dependencies
	return &PartitionServer{
		svc:                    service,
		eventsMan:              eventsMan,
		ProfileCli:             profileCli,
		PartitionRepo:          partitionRepo,
		ClientRepo:             clientRepo,
		ServiceAccountRepo:     serviceAccountRepo,
		PartitionBusiness:      business.NewPartitionBusiness(*cfg, eventsMan, tenantRepo, partitionRepo, partitionRoleRepo, accessRepo, clientRepo, serviceAccountRepo),
		TenantBusiness:         business.NewTenantBusiness(service, tenantRepo, partitionRepo),
		AccessBusiness:         business.NewAccessBusiness(service, eventsMan, accessRepo, accessRoleRepo, partitionRepo, partitionRoleRepo, clientRepo),
		PageBusiness:           business.NewPageBusiness(service, pageRepo, partitionRepo),
		ClientBusiness:         business.NewClientBusiness(eventsMan, partitionRepo, clientRepo),
		ServiceAccountBusiness: business.NewServiceAccountBusiness(eventsMan, auth, partitionRepo, partitionRoleRepo, clientRepo, serviceAccountRepo, accessRepo, accessRoleRepo),
	}
}

func (prtSrv *PartitionServer) ListPartition(
	ctx context.Context,
	req *connect.Request[partitionv1.ListPartitionRequest],
	stream *connect.ServerStream[partitionv1.ListPartitionResponse]) error {
	logger := util.Log(ctx)
	partitions, err := prtSrv.PartitionBusiness.ListPartition(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not list partition")
		return prtSrv.toAPIError(err)
	}
	return stream.Send(&partitionv1.ListPartitionResponse{Data: partitions})
}

func (prtSrv *PartitionServer) CreatePartition(
	ctx context.Context,
	req *connect.Request[partitionv1.CreatePartitionRequest]) (*connect.Response[partitionv1.CreatePartitionResponse], error) {
	logger := util.Log(ctx)
	partition, err := prtSrv.PartitionBusiness.CreatePartition(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not create a new partition")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.CreatePartitionResponse{Data: partition}), nil
}

func (prtSrv *PartitionServer) GetPartition(
	ctx context.Context,
	req *connect.Request[partitionv1.GetPartitionRequest]) (*connect.Response[partitionv1.GetPartitionResponse], error) {
	logger := util.Log(ctx)
	partition, err := prtSrv.PartitionBusiness.GetPartition(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not obtain the specified partition")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.GetPartitionResponse{Data: partition}), nil
}

func (prtSrv *PartitionServer) GetPartitionParents(
	ctx context.Context,
	req *connect.Request[partitionv1.GetPartitionParentsRequest]) (*connect.Response[partitionv1.GetPartitionParentsResponse], error) {
	logger := util.Log(ctx)
	partition, err := prtSrv.PartitionBusiness.GetPartitionParents(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not obtain the specified partition")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.GetPartitionParentsResponse{Data: partition}), nil
}

func (prtSrv *PartitionServer) UpdatePartition(
	ctx context.Context,
	req *connect.Request[partitionv1.UpdatePartitionRequest]) (*connect.Response[partitionv1.UpdatePartitionResponse], error) {
	logger := util.Log(ctx)
	partition, err := prtSrv.PartitionBusiness.UpdatePartition(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not update existing partition")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.UpdatePartitionResponse{Data: partition}), nil
}

func (prtSrv *PartitionServer) CreatePartitionRole(
	ctx context.Context,
	req *connect.Request[partitionv1.CreatePartitionRoleRequest]) (*connect.Response[partitionv1.CreatePartitionRoleResponse], error) {
	logger := util.Log(ctx)
	partition, err := prtSrv.PartitionBusiness.CreatePartitionRole(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug("could not create a new partition role")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.CreatePartitionRoleResponse{Data: partition}), nil
}

func (prtSrv *PartitionServer) ListPartitionRole(
	ctx context.Context,
	req *connect.Request[partitionv1.ListPartitionRoleRequest],
	stream *connect.ServerStream[partitionv1.ListPartitionRoleResponse]) error {
	logger := util.Log(ctx)
	resp, err := prtSrv.PartitionBusiness.ListPartitionRoles(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not obtain the list of partition roles")
		return prtSrv.toAPIError(err)
	}
	return stream.Send(resp)
}

func (prtSrv *PartitionServer) UpdatePartitionRole(
	ctx context.Context,
	req *connect.Request[partitionv1.UpdatePartitionRoleRequest]) (*connect.Response[partitionv1.UpdatePartitionRoleResponse], error) {
	logger := util.Log(ctx)
	role, err := prtSrv.PartitionBusiness.UpdatePartitionRole(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug("could not update partition role")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.UpdatePartitionRoleResponse{Data: role}), nil
}

func (prtSrv *PartitionServer) RemovePartition(
	ctx context.Context,
	req *connect.Request[partitionv1.RemovePartitionRequest]) (*connect.Response[partitionv1.RemovePartitionResponse], error) {
	logger := util.Log(ctx)
	err := prtSrv.PartitionBusiness.RemovePartition(ctx, req.Msg.GetId())
	if err != nil {
		logger.WithError(err).Debug("could not remove partition")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.RemovePartitionResponse{Succeeded: true}), nil
}

func (prtSrv *PartitionServer) RemovePartitionRole(
	ctx context.Context,
	req *connect.Request[partitionv1.RemovePartitionRoleRequest]) (*connect.Response[partitionv1.RemovePartitionRoleResponse], error) {
	logger := util.Log(ctx)
	err := prtSrv.PartitionBusiness.RemovePartitionRole(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not remove the specified partition role")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.RemovePartitionRoleResponse{
		Succeeded: true,
	}), nil
}
