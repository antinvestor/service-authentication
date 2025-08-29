package handlers

import (
	"context"

	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
)

func (prtSrv *PartitionServer) GetTenant(
	ctx context.Context,
	req *partitionv1.GetTenantRequest) (*partitionv1.GetTenantResponse, error) {
	logger := prtSrv.svc.Log(ctx)
	tenant, err := prtSrv.tenantBusiness.GetTenant(ctx, req.GetId())
	if err != nil {
		logger.Debug("could not obtain the specified tenant")
		return nil, prtSrv.toAPIError(err)
	}
	return &partitionv1.GetTenantResponse{Data: tenant}, nil
}

func (prtSrv *PartitionServer) ListTenant(
	req *partitionv1.ListTenantRequest,
	stream partitionv1.PartitionService_ListTenantServer,
) error {
	ctx := stream.Context()
	logger := prtSrv.svc.Log(ctx)
	err := prtSrv.tenantBusiness.ListTenant(ctx, req, stream)
	if err != nil {
		logger.Debug("could not list tenants")
		return prtSrv.toAPIError(err)
	}
	return nil
}

func (prtSrv *PartitionServer) CreateTenant(
	ctx context.Context,
	req *partitionv1.CreateTenantRequest,
) (*partitionv1.CreateTenantResponse, error) {
	logger := prtSrv.svc.Log(ctx)
	tenant, err := prtSrv.tenantBusiness.CreateTenant(ctx, req)
	if err != nil {
		logger.Debug("could not create a new tenant")
		return nil, prtSrv.toAPIError(err)
	}
	return &partitionv1.CreateTenantResponse{Data: tenant}, nil
}
