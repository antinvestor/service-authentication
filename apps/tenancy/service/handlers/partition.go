package handlers

import (
	"context"

	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/pitabwire/frame"
)

type PartitionServer struct {
	Service           *frame.Service
	partitionBusiness business.PartitionBusiness
	tenantBusiness    business.TenantBusiness
	accessBusiness    business.AccessBusiness
	pageBusiness      business.PageBusiness
	partitionv1.UnimplementedPartitionServiceServer
}

// NewPartitionServer creates a new PartitionServer with injected dependencies
func NewPartitionServer(ctx context.Context, service *frame.Service) *PartitionServer {
	return &PartitionServer{
		Service:           service,
		partitionBusiness: business.NewPartitionBusiness(service),
		tenantBusiness:    business.NewTenantBusiness(ctx, service),
		accessBusiness:    business.NewAccessBusiness(service),
		pageBusiness:      business.NewPageBusiness(service),
	}
}

func (prtSrv *PartitionServer) ListPartition(
	req *partitionv1.ListPartitionRequest,
	stream partitionv1.PartitionService_ListPartitionServer) error {
	ctx := stream.Context()
	logger := prtSrv.Service.Log(ctx)
	err := prtSrv.partitionBusiness.ListPartition(stream.Context(), req, stream)
	if err != nil {
		logger.WithError(err).Debug(" could not list partition")
		return prtSrv.toAPIError(err)
	}
	return nil
}

func (prtSrv *PartitionServer) CreatePartition(
	ctx context.Context,
	req *partitionv1.CreatePartitionRequest) (*partitionv1.CreatePartitionResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	partition, err := prtSrv.partitionBusiness.CreatePartition(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" could not create a new partition")
		return nil, prtSrv.toAPIError(err)
	}
	return &partitionv1.CreatePartitionResponse{Data: partition}, nil
}

func (prtSrv *PartitionServer) GetPartition(
	ctx context.Context,
	req *partitionv1.GetPartitionRequest) (*partitionv1.GetPartitionResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	partition, err := prtSrv.partitionBusiness.GetPartition(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" could not obtain the specified partition")
		return nil, prtSrv.toAPIError(err)
	}
	return &partitionv1.GetPartitionResponse{Data: partition}, nil
}

func (prtSrv *PartitionServer) UpdatePartition(
	ctx context.Context,
	req *partitionv1.UpdatePartitionRequest) (*partitionv1.UpdatePartitionResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	partition, err := prtSrv.partitionBusiness.UpdatePartition(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" could not update existing partition")
		return nil, prtSrv.toAPIError(err)
	}
	return &partitionv1.UpdatePartitionResponse{Data: partition}, nil
}

func (prtSrv *PartitionServer) CreatePartitionRole(
	ctx context.Context,
	req *partitionv1.CreatePartitionRoleRequest) (*partitionv1.CreatePartitionRoleResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	partition, err := prtSrv.partitionBusiness.CreatePartitionRole(ctx, req)
	if err != nil {
		logger.WithError(err).Debug("could not create a new partition role")
		return nil, prtSrv.toAPIError(err)
	}
	return &partitionv1.CreatePartitionRoleResponse{Data: partition}, nil
}

func (prtSrv *PartitionServer) ListPartitionRoles(
	ctx context.Context,
	req *partitionv1.ListPartitionRoleRequest) (*partitionv1.ListPartitionRoleResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	partition, err := prtSrv.partitionBusiness.ListPartitionRoles(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" could not obtain the list of partition roles")
		return nil, prtSrv.toAPIError(err)
	}
	return partition, nil
}

func (prtSrv *PartitionServer) RemovePartitionRole(
	ctx context.Context,
	req *partitionv1.RemovePartitionRoleRequest) (*partitionv1.RemovePartitionRoleResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	err := prtSrv.partitionBusiness.RemovePartitionRole(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" could not remove the specified partition role")
		return &partitionv1.RemovePartitionRoleResponse{
			Succeeded: false,
		}, prtSrv.toAPIError(err)
	}
	return &partitionv1.RemovePartitionRoleResponse{
		Succeeded: true,
	}, nil
}
