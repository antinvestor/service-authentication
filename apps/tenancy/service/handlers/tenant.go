package handlers

import (
	"context"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"connectrpc.com/connect"
	"github.com/pitabwire/util"
)

func (prtSrv *TenancyServer) GetTenant(
	ctx context.Context,
	req *connect.Request[tenancyv1.GetTenantRequest]) (*connect.Response[tenancyv1.GetTenantResponse], error) {
	logger := util.Log(ctx)
	tenant, err := prtSrv.TenantBusiness.GetTenant(ctx, req.Msg.GetId())
	if err != nil {
		logger.Debug("could not obtain the specified tenant")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.GetTenantResponse{Data: tenant}), nil
}

func (prtSrv *TenancyServer) ListTenant(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListTenantRequest],
	stream *connect.ServerStream[tenancyv1.ListTenantResponse]) error {
	logger := util.Log(ctx)
	tenants, err := prtSrv.TenantBusiness.ListTenant(ctx, req.Msg)
	if err != nil {
		logger.Debug("could not list tenants")
		return prtSrv.toAPIError(err)
	}
	return stream.Send(&tenancyv1.ListTenantResponse{Data: tenants})
}

func (prtSrv *TenancyServer) CreateTenant(
	ctx context.Context,
	req *connect.Request[tenancyv1.CreateTenantRequest],
) (*connect.Response[tenancyv1.CreateTenantResponse], error) {
	logger := util.Log(ctx)
	tenant, err := prtSrv.TenantBusiness.CreateTenant(ctx, req.Msg)
	if err != nil {
		logger.Debug("could not create a new tenant")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.CreateTenantResponse{Data: tenant}), nil
}

func (prtSrv *TenancyServer) RemoveTenant(
	ctx context.Context,
	req *connect.Request[tenancyv1.RemoveTenantRequest],
) (*connect.Response[tenancyv1.RemoveTenantResponse], error) {
	logger := util.Log(ctx)
	err := prtSrv.TenantBusiness.RemoveTenant(ctx, req.Msg.GetId())
	if err != nil {
		logger.WithError(err).Debug("could not remove tenant")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.RemoveTenantResponse{Succeeded: true}), nil
}

func (prtSrv *TenancyServer) UpdateTenant(
	ctx context.Context,
	req *connect.Request[tenancyv1.UpdateTenantRequest],
) (*connect.Response[tenancyv1.UpdateTenantResponse], error) {
	logger := util.Log(ctx)
	tenant, err := prtSrv.TenantBusiness.UpdateTenant(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug("could not update our tenant")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.UpdateTenantResponse{Data: tenant}), nil
}
