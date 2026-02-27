package handlers

import (
	"context"

	"buf.build/gen/go/antinvestor/partition/connectrpc/go/partition/v1/partitionv1connect"
	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security/authorizer"
	"github.com/pitabwire/util"
)

type PartitionServer struct {
	svc       *frame.Service
	eventsMan events.Manager
	authz     authz.Middleware

	PartitionRepo repository.PartitionRepository

	PartitionBusiness business.PartitionBusiness
	TenantBusiness    business.TenantBusiness
	AccessBusiness    business.AccessBusiness
	PageBusiness      business.PageBusiness
	partitionv1connect.UnimplementedPartitionServiceHandler
}

// NewPartitionServer creates a new PartitionServer with injected dependencies
func NewPartitionServer(ctx context.Context, service *frame.Service, authzMiddleware authz.Middleware) *PartitionServer {
	// Create all repositories once
	dbPool := service.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName)
	workMan := service.WorkManager()

	tenantRepo := repository.NewTenantRepository(ctx, dbPool, workMan)
	partitionRepo := repository.NewPartitionRepository(ctx, dbPool, workMan)
	partitionRoleRepo := repository.NewPartitionRoleRepository(ctx, dbPool, workMan)
	accessRepo := repository.NewAccessRepository(ctx, dbPool, workMan)
	accessRoleRepo := repository.NewAccessRoleRepository(ctx, dbPool, workMan)
	pageRepo := repository.NewPageRepository(ctx, dbPool, workMan)

	cfg := service.Config().(*config.PartitionConfig)
	eventsMan := service.EventsManager()

	// Create business layers with repository dependencies
	return &PartitionServer{
		svc:               service,
		eventsMan:         eventsMan,
		authz:             authzMiddleware,
		PartitionRepo:     partitionRepo,
		PartitionBusiness: business.NewPartitionBusiness(*cfg, eventsMan, tenantRepo, partitionRepo, partitionRoleRepo),
		TenantBusiness:    business.NewTenantBusiness(service, tenantRepo),
		AccessBusiness:    business.NewAccessBusiness(service, eventsMan, accessRepo, accessRoleRepo, partitionRepo, partitionRoleRepo),
		PageBusiness:      business.NewPageBusiness(service, pageRepo, partitionRepo),
	}
}

func (prtSrv *PartitionServer) ListPartition(
	ctx context.Context,
	req *connect.Request[partitionv1.ListPartitionRequest],
	stream *connect.ServerStream[partitionv1.ListPartitionResponse]) error {
	if err := prtSrv.authz.CanViewPartition(ctx); err != nil {
		return authorizer.ToConnectError(err)
	}
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
	if err := prtSrv.authz.CanManagePartition(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
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
	if err := prtSrv.authz.CanViewPartition(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
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
	if err := prtSrv.authz.CanViewPartition(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
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
	if err := prtSrv.authz.CanManagePartition(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
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
	if err := prtSrv.authz.CanManageRoles(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
	logger := util.Log(ctx)
	partition, err := prtSrv.PartitionBusiness.CreatePartitionRole(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug("could not create a new partition role")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.CreatePartitionRoleResponse{Data: partition}), nil
}

func (prtSrv *PartitionServer) ListPartitionRoles(
	ctx context.Context,
	req *connect.Request[partitionv1.ListPartitionRoleRequest]) (*connect.Response[partitionv1.ListPartitionRoleResponse], error) {
	if err := prtSrv.authz.CanManageRoles(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
	logger := util.Log(ctx)
	partition, err := prtSrv.PartitionBusiness.ListPartitionRoles(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not obtain the list of partition roles")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(partition), nil
}

func (prtSrv *PartitionServer) RemovePartitionRole(
	ctx context.Context,
	req *connect.Request[partitionv1.RemovePartitionRoleRequest]) (*connect.Response[partitionv1.RemovePartitionRoleResponse], error) {
	if err := prtSrv.authz.CanManageRoles(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
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
