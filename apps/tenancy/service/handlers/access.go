package handlers

import (
	"context"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"

	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pitabwire/frame"
)

func (prtSrv *PartitionServer) toAPIError(err error) error {
	grpcError, ok := status.FromError(err)

	if ok {
		return grpcError.Err()
	}

	if frame.ErrorIsNoRows(err) {
		return status.Error(codes.NotFound, err.Error())
	}

	return grpcError.Err()
}

func (prtSrv *PartitionServer) CreateAccess(
	ctx context.Context,
	req *partitionv1.CreateAccessRequest,
) (*partitionv1.CreateAccessResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	accessBusiness := business.NewAccessBusiness(ctx, prtSrv.Service)
	access, err := accessBusiness.CreateAccess(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" could not create new access")
		return nil, prtSrv.toAPIError(err)
	}
	return &partitionv1.CreateAccessResponse{Data: access}, nil
}

func (prtSrv *PartitionServer) GetAccess(
	ctx context.Context,
	req *partitionv1.GetAccessRequest,
) (*partitionv1.GetAccessResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	accessBusiness := business.NewAccessBusiness(ctx, prtSrv.Service)
	access, err := accessBusiness.GetAccess(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" could not get access")
		return nil, prtSrv.toAPIError(err)
	}
	return &partitionv1.GetAccessResponse{Data: access}, nil
}

func (prtSrv *PartitionServer) RemoveAccess(
	ctx context.Context,
	req *partitionv1.RemoveAccessRequest,
) (*partitionv1.RemoveAccessResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	accessBusiness := business.NewAccessBusiness(ctx, prtSrv.Service)
	err := accessBusiness.RemoveAccess(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" could not remove access")
		return &partitionv1.RemoveAccessResponse{
			Succeeded: false,
		}, prtSrv.toAPIError(err)
	}
	return &partitionv1.RemoveAccessResponse{
		Succeeded: true,
	}, nil
}

func (prtSrv *PartitionServer) CreateAccessRole(
	ctx context.Context,
	req *partitionv1.CreateAccessRoleRequest,
) (*partitionv1.CreateAccessRoleResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	accessBusiness := business.NewAccessBusiness(ctx, prtSrv.Service)
	accessRole, err := accessBusiness.CreateAccessRole(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" could not create new access roles")
		return nil, prtSrv.toAPIError(err)
	}
	return &partitionv1.CreateAccessRoleResponse{Data: accessRole}, nil
}

func (prtSrv *PartitionServer) ListAccessRoles(
	ctx context.Context,
	req *partitionv1.ListAccessRoleRequest,
) (*partitionv1.ListAccessRoleResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	accessBusiness := business.NewAccessBusiness(ctx, prtSrv.Service)
	accessRoleList, err := accessBusiness.ListAccessRoles(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" could not get list of access roles")
		return nil, prtSrv.toAPIError(err)
	}
	return accessRoleList, nil
}

func (prtSrv *PartitionServer) RemoveAccessRole(
	ctx context.Context,
	req *partitionv1.RemoveAccessRoleRequest,
) (*partitionv1.RemoveAccessRoleResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	accessBusiness := business.NewAccessBusiness(ctx, prtSrv.Service)
	err := accessBusiness.RemoveAccessRole(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" could not remove access role")
		return &partitionv1.RemoveAccessRoleResponse{
			Succeeded: false,
		}, prtSrv.toAPIError(err)
	}
	return &partitionv1.RemoveAccessRoleResponse{
		Succeeded: true,
	}, nil
}
