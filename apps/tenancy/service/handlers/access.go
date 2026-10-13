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
	"errors"

	"buf.build/gen/go/antinvestor/tenancy/connectrpc/go/v2/tenancy/v1/tenancyv1connect"
	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"connectrpc.com/connect/v2"
	"github.com/pitabwire/frame/v3/data"
	"github.com/pitabwire/frame/v3/security/authorizer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// toAPIError maps business, authorization and storage errors to Connect
// errors. connect v2 sends only a *connect.Error's message to the client.
func (prtSrv *TenancyServer) toAPIError(err error) error {
	if err == nil {
		return nil
	}
	if cerr := (*connect.Error)(nil); errors.As(err, &cerr) {
		return cerr
	}
	var permErr *authorizer.PermissionDeniedError
	if errors.As(err, &permErr) ||
		errors.Is(err, authorizer.ErrInvalidSubject) || errors.Is(err, authorizer.ErrInvalidObject) {
		return authorizer.ToConnectError(err)
	}
	if data.ErrorIsNoRows(err) {
		return connect.NewError(connect.CodeNotFound, err.Error()).WithCause(err)
	}
	// Downstream gRPC failures (Keto, for one) keep their code; gRPC and
	// Connect share the numbering.
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return connect.NewError(connect.Code(st.Code()), err.Error()).WithCause(err)
	}
	return data.ErrorConvertToAPI(err)
}

func (prtSrv *TenancyServer) CreateAccess(
	ctx context.Context,
	req *tenancyv1.CreateAccessRequest,
) (*tenancyv1.CreateAccessResponse, error) {
	access, err := prtSrv.AccessBusiness.CreateAccess(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.CreateAccessResponse{Data: access}, nil
}

func (prtSrv *TenancyServer) GetAccess(
	ctx context.Context,
	req *tenancyv1.GetAccessRequest,
) (*tenancyv1.GetAccessResponse, error) {
	access, err := prtSrv.AccessBusiness.GetAccess(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.GetAccessResponse{Data: access}, nil
}

func (prtSrv *TenancyServer) RemoveAccess(
	ctx context.Context,
	req *tenancyv1.RemoveAccessRequest,
) (*tenancyv1.RemoveAccessResponse, error) {
	err := prtSrv.AccessBusiness.RemoveAccess(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.RemoveAccessResponse{
		Succeeded: true,
	}, nil
}

func (prtSrv *TenancyServer) ListAccess(
	ctx context.Context,
	req *tenancyv1.ListAccessRequest,
	stream tenancyv1connect.TenancyServiceListAccessServerStream,
) error {
	accesses, err := prtSrv.AccessBusiness.ListAccess(ctx, req)
	if err != nil {
		return prtSrv.toAPIError(err)
	}
	return stream.Send(&tenancyv1.ListAccessResponse{Data: accesses})
}

func (prtSrv *TenancyServer) CreateAccessRole(
	ctx context.Context,
	req *tenancyv1.CreateAccessRoleRequest,
) (*tenancyv1.CreateAccessRoleResponse, error) {
	accessRole, err := prtSrv.AccessBusiness.CreateAccessRole(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.CreateAccessRoleResponse{Data: accessRole}, nil
}

func (prtSrv *TenancyServer) ListAccessRole(
	ctx context.Context,
	req *tenancyv1.ListAccessRoleRequest,
	stream tenancyv1connect.TenancyServiceListAccessRoleServerStream,
) error {
	accessRoleList, err := prtSrv.AccessBusiness.ListAccessRoles(ctx, req)
	if err != nil {
		return prtSrv.toAPIError(err)
	}
	return stream.Send(accessRoleList)
}

func (prtSrv *TenancyServer) RemoveAccessRole(
	ctx context.Context,
	req *tenancyv1.RemoveAccessRoleRequest,
) (*tenancyv1.RemoveAccessRoleResponse, error) {
	err := prtSrv.AccessBusiness.RemoveAccessRole(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.RemoveAccessRoleResponse{
		Succeeded: true,
	}, nil
}
