package handlers

import (
	"context"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
)

func (prtSrv *PartitionServer) GetTenant(
	ctx context.Context,
	req *connect.Request[partitionv1.GetTenantRequest]) (*connect.Response[partitionv1.GetTenantResponse], error) {
	logger := prtSrv.svc.Log(ctx)
	tenant, err := prtSrv.TenantBusiness.GetTenant(ctx, req.Msg.GetId())
	if err != nil {
		logger.Debug("could not obtain the specified tenant")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.GetTenantResponse{Data: tenant}), nil
}

func (prtSrv *PartitionServer) ListTenant(
	ctx context.Context,
	req *connect.Request[partitionv1.ListTenantRequest],
	stream *connect.ServerStream[partitionv1.ListTenantResponse]) error {
	logger := prtSrv.svc.Log(ctx)
	tenants, err := prtSrv.TenantBusiness.ListTenant(ctx, req.Msg)
	if err != nil {
		logger.Debug("could not list tenants")
		return prtSrv.toAPIError(err)
	}
	return stream.Send(&partitionv1.ListTenantResponse{Data: tenants})
}

func (prtSrv *PartitionServer) CreateTenant(
	ctx context.Context,
	req *connect.Request[partitionv1.CreateTenantRequest],
) (*connect.Response[partitionv1.CreateTenantResponse], error) {
	logger := prtSrv.svc.Log(ctx)
	tenant, err := prtSrv.TenantBusiness.CreateTenant(ctx, req.Msg)
	if err != nil {
		logger.Debug("could not create a new tenant")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.CreateTenantResponse{Data: tenant}), nil
}

func (prtSrv *PartitionServer) UpdateTenant(
	ctx context.Context,
	req *connect.Request[partitionv1.UpdateTenantRequest],
) (*connect.Response[partitionv1.UpdateTenantResponse], error) {
	logger := prtSrv.svc.Log(ctx)
	tenant, err := prtSrv.TenantBusiness.UpdateTenant(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug("could not update our tenant")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.UpdateTenantResponse{Data: tenant}), nil
}
