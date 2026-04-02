// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	"context"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"connectrpc.com/connect"
)

func (prtSrv *TenancyServer) GetTenant(
	ctx context.Context,
	req *connect.Request[tenancyv1.GetTenantRequest]) (*connect.Response[tenancyv1.GetTenantResponse], error) {
	tenant, err := prtSrv.TenantBusiness.GetTenant(ctx, req.Msg.GetId())
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.GetTenantResponse{Data: tenant}), nil
}

func (prtSrv *TenancyServer) ListTenant(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListTenantRequest],
	stream *connect.ServerStream[tenancyv1.ListTenantResponse]) error {
	tenants, err := prtSrv.TenantBusiness.ListTenant(ctx, req.Msg)
	if err != nil {
		return prtSrv.toAPIError(err)
	}
	return stream.Send(&tenancyv1.ListTenantResponse{Data: tenants})
}

func (prtSrv *TenancyServer) CreateTenant(
	ctx context.Context,
	req *connect.Request[tenancyv1.CreateTenantRequest],
) (*connect.Response[tenancyv1.CreateTenantResponse], error) {
	tenant, err := prtSrv.TenantBusiness.CreateTenant(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.CreateTenantResponse{Data: tenant}), nil
}

func (prtSrv *TenancyServer) RemoveTenant(
	ctx context.Context,
	req *connect.Request[tenancyv1.RemoveTenantRequest],
) (*connect.Response[tenancyv1.RemoveTenantResponse], error) {
	err := prtSrv.TenantBusiness.RemoveTenant(ctx, req.Msg.GetId())
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.RemoveTenantResponse{Succeeded: true}), nil
}

func (prtSrv *TenancyServer) UpdateTenant(
	ctx context.Context,
	req *connect.Request[tenancyv1.UpdateTenantRequest],
) (*connect.Response[tenancyv1.UpdateTenantResponse], error) {
	tenant, err := prtSrv.TenantBusiness.UpdateTenant(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.UpdateTenantResponse{Data: tenant}), nil
}
