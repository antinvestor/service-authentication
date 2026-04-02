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
	"github.com/pitabwire/frame/data"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (prtSrv *TenancyServer) toAPIError(err error) error {
	grpcError, ok := status.FromError(err)

	if ok {
		return grpcError.Err()
	}

	if data.ErrorIsNoRows(err) {
		return status.Error(codes.NotFound, err.Error())
	}

	return grpcError.Err()
}

func (prtSrv *TenancyServer) CreateAccess(
	ctx context.Context,
	req *connect.Request[tenancyv1.CreateAccessRequest],
) (*connect.Response[tenancyv1.CreateAccessResponse], error) {
	access, err := prtSrv.AccessBusiness.CreateAccess(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.CreateAccessResponse{Data: access}), nil
}

func (prtSrv *TenancyServer) GetAccess(
	ctx context.Context,
	req *connect.Request[tenancyv1.GetAccessRequest],
) (*connect.Response[tenancyv1.GetAccessResponse], error) {
	access, err := prtSrv.AccessBusiness.GetAccess(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.GetAccessResponse{Data: access}), nil
}

func (prtSrv *TenancyServer) RemoveAccess(
	ctx context.Context,
	req *connect.Request[tenancyv1.RemoveAccessRequest],
) (*connect.Response[tenancyv1.RemoveAccessResponse], error) {
	err := prtSrv.AccessBusiness.RemoveAccess(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.RemoveAccessResponse{
		Succeeded: true,
	}), nil
}

func (prtSrv *TenancyServer) ListAccess(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListAccessRequest],
	stream *connect.ServerStream[tenancyv1.ListAccessResponse],
) error {
	accesses, err := prtSrv.AccessBusiness.ListAccess(ctx, req.Msg)
	if err != nil {
		return prtSrv.toAPIError(err)
	}
	return stream.Send(&tenancyv1.ListAccessResponse{Data: accesses})
}

func (prtSrv *TenancyServer) CreateAccessRole(
	ctx context.Context,
	req *connect.Request[tenancyv1.CreateAccessRoleRequest],
) (*connect.Response[tenancyv1.CreateAccessRoleResponse], error) {
	accessRole, err := prtSrv.AccessBusiness.CreateAccessRole(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.CreateAccessRoleResponse{Data: accessRole}), nil
}

func (prtSrv *TenancyServer) ListAccessRole(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListAccessRoleRequest],
	stream *connect.ServerStream[tenancyv1.ListAccessRoleResponse],
) error {
	accessRoleList, err := prtSrv.AccessBusiness.ListAccessRoles(ctx, req.Msg)
	if err != nil {
		return prtSrv.toAPIError(err)
	}
	return stream.Send(accessRoleList)
}

func (prtSrv *TenancyServer) RemoveAccessRole(
	ctx context.Context,
	req *connect.Request[tenancyv1.RemoveAccessRoleRequest],
) (*connect.Response[tenancyv1.RemoveAccessRoleResponse], error) {
	err := prtSrv.AccessBusiness.RemoveAccessRole(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.RemoveAccessRoleResponse{
		Succeeded: true,
	}), nil
}
