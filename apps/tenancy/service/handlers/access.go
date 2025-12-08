package handlers

import (
	"context"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (prtSrv *PartitionServer) toAPIError(err error) error {
	grpcError, ok := status.FromError(err)

	if ok {
		return grpcError.Err()
	}

	if data.ErrorIsNoRows(err) {
		return status.Error(codes.NotFound, err.Error())
	}

	return grpcError.Err()
}

func (prtSrv *PartitionServer) CreateAccess(
	ctx context.Context,
	req *connect.Request[partitionv1.CreateAccessRequest],
) (*connect.Response[partitionv1.CreateAccessResponse], error) {
	logger := util.Log(ctx)
	access, err := prtSrv.AccessBusiness.CreateAccess(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not create new access")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.CreateAccessResponse{Data: access}), nil
}

func (prtSrv *PartitionServer) GetAccess(
	ctx context.Context,
	req *connect.Request[partitionv1.GetAccessRequest],
) (*connect.Response[partitionv1.GetAccessResponse], error) {
	logger := util.Log(ctx)
	access, err := prtSrv.AccessBusiness.GetAccess(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not get access")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.GetAccessResponse{Data: access}), nil
}

func (prtSrv *PartitionServer) RemoveAccess(
	ctx context.Context,
	req *connect.Request[partitionv1.RemoveAccessRequest],
) (*connect.Response[partitionv1.RemoveAccessResponse], error) {
	logger := util.Log(ctx)
	err := prtSrv.AccessBusiness.RemoveAccess(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not remove access")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.RemoveAccessResponse{
		Succeeded: true,
	}), nil
}

func (prtSrv *PartitionServer) CreateAccessRole(
	ctx context.Context,
	req *connect.Request[partitionv1.CreateAccessRoleRequest],
) (*connect.Response[partitionv1.CreateAccessRoleResponse], error) {
	logger := util.Log(ctx)
	accessRole, err := prtSrv.AccessBusiness.CreateAccessRole(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not create new access roles")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.CreateAccessRoleResponse{Data: accessRole}), nil
}

func (prtSrv *PartitionServer) ListAccessRoles(
	ctx context.Context,
	req *connect.Request[partitionv1.ListAccessRoleRequest],
) (*connect.Response[partitionv1.ListAccessRoleResponse], error) {
	logger := util.Log(ctx)
	accessRoleList, err := prtSrv.AccessBusiness.ListAccessRoles(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not get list of access roles")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(accessRoleList), nil
}

func (prtSrv *PartitionServer) RemoveAccessRole(
	ctx context.Context,
	req *connect.Request[partitionv1.RemoveAccessRoleRequest],
) (*connect.Response[partitionv1.RemoveAccessRoleResponse], error) {
	logger := util.Log(ctx)
	err := prtSrv.AccessBusiness.RemoveAccessRole(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" could not remove access role")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.RemoveAccessRoleResponse{
		Succeeded: true,
	}), nil
}
