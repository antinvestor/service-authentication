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

// CreateServiceAccount registers a new service account for a partition.
func (prtSrv *TenancyServer) CreateServiceAccount(
	ctx context.Context,
	req *connect.Request[tenancyv1.CreateServiceAccountRequest],
) (*connect.Response[tenancyv1.CreateServiceAccountResponse], error) {
	msg := req.Msg

	var audiences []string
	if msg.GetAudiences() != nil {
		audiences = msg.GetAudiences()
	}

	var properties map[string]any
	if msg.GetProperties() != nil {
		properties = msg.GetProperties().AsMap()
	}

	saType := msg.GetType()
	roles := msg.GetRoles()

	var publicKeys map[string]any
	if msg.GetPublicKeys() != nil {
		publicKeys = msg.GetPublicKeys().AsMap()
	}

	result, err := prtSrv.ServiceAccountBusiness.CreateServiceAccount(
		ctx,
		msg.GetPartitionId(),
		msg.GetProfileId(),
		msg.GetName(),
		saType,
		audiences,
		roles,
		publicKeys,
		properties,
	)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}

	sa := result.ServiceAccount
	return connect.NewResponse(&tenancyv1.CreateServiceAccountResponse{
		Data:         sa.ToAPI(),
		ClientSecret: result.ClientSecret,
	}), nil
}

// GetServiceAccount retrieves a service account by ID, client_id, or client_id+profile_id.
func (prtSrv *TenancyServer) GetServiceAccount(
	ctx context.Context,
	req *connect.Request[tenancyv1.GetServiceAccountRequest],
) (*connect.Response[tenancyv1.GetServiceAccountResponse], error) {
	msg := req.Msg

	sa, err := prtSrv.ServiceAccountBusiness.GetServiceAccount(ctx, msg.GetId(), msg.GetClientId(), msg.GetProfileId())
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}

	return connect.NewResponse(&tenancyv1.GetServiceAccountResponse{
		Data: sa.ToAPI(),
	}), nil
}

// ListServiceAccount streams service accounts for a partition.
func (prtSrv *TenancyServer) ListServiceAccount(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListServiceAccountRequest],
	stream *connect.ServerStream[tenancyv1.ListServiceAccountResponse],
) error {
	accounts, err := prtSrv.ServiceAccountBusiness.ListServiceAccounts(ctx, req.Msg.GetPartitionId())
	if err != nil {
		return prtSrv.toAPIError(err)
	}

	protoAccounts := make([]*tenancyv1.ServiceAccountObject, 0, len(accounts))
	for _, sa := range accounts {
		protoAccounts = append(protoAccounts, sa.ToAPI())
	}

	if err := stream.Send(&tenancyv1.ListServiceAccountResponse{
		Data: protoAccounts,
	}); err != nil {
		return err
	}

	return nil
}

// UpdateServiceAccount updates a service account's configuration.
func (prtSrv *TenancyServer) UpdateServiceAccount(
	ctx context.Context,
	req *connect.Request[tenancyv1.UpdateServiceAccountRequest],
) (*connect.Response[tenancyv1.UpdateServiceAccountResponse], error) {
	sa, err := prtSrv.ServiceAccountBusiness.UpdateServiceAccount(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}

	return connect.NewResponse(&tenancyv1.UpdateServiceAccountResponse{
		Data: sa,
	}), nil
}

// RemoveServiceAccount deregisters a service account.
func (prtSrv *TenancyServer) RemoveServiceAccount(
	ctx context.Context,
	req *connect.Request[tenancyv1.RemoveServiceAccountRequest],
) (*connect.Response[tenancyv1.RemoveServiceAccountResponse], error) {
	if err := prtSrv.ServiceAccountBusiness.RemoveServiceAccount(ctx, req.Msg.GetId()); err != nil {
		return nil, prtSrv.toAPIError(err)
	}

	return connect.NewResponse(&tenancyv1.RemoveServiceAccountResponse{
		Succeeded: true,
	}), nil
}
