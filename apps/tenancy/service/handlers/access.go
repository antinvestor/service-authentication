package handlers

import (
	"context"
	"errors"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/security/authorizer"
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

// toConnectError translates authorization errors into ConnectRPC error codes.
func toConnectError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, authorizer.ErrInvalidSubject) || errors.Is(err, authorizer.ErrInvalidObject) {
		return connect.NewError(connect.CodeUnauthenticated, err)
	}

	var permErr *authorizer.PermissionDeniedError
	if errors.As(err, &permErr) {
		return connect.NewError(connect.CodePermissionDenied, err)
	}

	return connect.NewError(connect.CodeInternal, err)
}

func (prtSrv *PartitionServer) CreateAccess(
	ctx context.Context,
	req *connect.Request[partitionv1.CreateAccessRequest],
) (*connect.Response[partitionv1.CreateAccessResponse], error) {
	if err := prtSrv.authz.CanManageAccess(ctx); err != nil {
		return nil, toConnectError(err)
	}
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
	if err := prtSrv.authz.CanManageAccess(ctx); err != nil {
		return nil, toConnectError(err)
	}
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
	if err := prtSrv.authz.CanManageAccess(ctx); err != nil {
		return nil, toConnectError(err)
	}
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
	if err := prtSrv.authz.CanManageRoles(ctx); err != nil {
		return nil, toConnectError(err)
	}
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
	if err := prtSrv.authz.CanManageRoles(ctx); err != nil {
		return nil, toConnectError(err)
	}
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
	if err := prtSrv.authz.CanManageRoles(ctx); err != nil {
		return nil, toConnectError(err)
	}
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
