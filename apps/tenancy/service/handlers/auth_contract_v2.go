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

	tenancyv2connect "buf.build/gen/go/antinvestor/tenancy/connectrpc/go/tenancy/v2/tenancyv2connect"
	tenancyv2 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v2"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
)

type AuthContractServer struct {
	business business.AuthContractBusiness
	parent   *TenancyServer
	tenancyv2connect.UnimplementedAuthContractServiceHandler
}

func NewAuthContractServer(parent *TenancyServer, audienceBaseURL string) (*AuthContractServer, error) {
	businessLayer, err := business.NewAuthContractBusiness(
		audienceBaseURL,
		parent.eventsMan,
		parent.PartitionRepo,
		parent.ClientRepo,
		parent.OAuthRecipientRepo,
		parent.ServiceAccountRepo,
		parent.AuthorizationPolicyRepo,
		parent.AuthContractRepo,
	)
	if err != nil {
		return nil, err
	}
	return &AuthContractServer{business: businessLayer, parent: parent}, nil
}

func (s *AuthContractServer) CreateOAuthClient(
	ctx context.Context,
	request *connect.Request[tenancyv2.CreateOAuthClientRequest],
) (*connect.Response[tenancyv2.CreateOAuthClientResponse], error) {
	response, err := s.business.CreateOAuthClient(ctx, request.Msg)
	if err != nil {
		return nil, s.parent.toAPIError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *AuthContractServer) GetOAuthClient(
	ctx context.Context,
	request *connect.Request[tenancyv2.GetOAuthClientRequest],
) (*connect.Response[tenancyv2.GetOAuthClientResponse], error) {
	client, err := s.business.GetOAuthClient(ctx, request.Msg)
	if err != nil {
		return nil, s.parent.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv2.GetOAuthClientResponse{Data: client}), nil
}

func (s *AuthContractServer) ListOAuthClients(
	ctx context.Context,
	request *connect.Request[tenancyv2.ListOAuthClientsRequest],
) (*connect.Response[tenancyv2.ListOAuthClientsResponse], error) {
	clients, err := s.business.ListOAuthClients(ctx, request.Msg)
	if err != nil {
		return nil, s.parent.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv2.ListOAuthClientsResponse{Data: clients}), nil
}

func (s *AuthContractServer) UpdateOAuthClient(
	ctx context.Context,
	request *connect.Request[tenancyv2.UpdateOAuthClientRequest],
) (*connect.Response[tenancyv2.UpdateOAuthClientResponse], error) {
	client, err := s.business.UpdateOAuthClient(ctx, request.Msg)
	if err != nil {
		return nil, s.parent.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv2.UpdateOAuthClientResponse{Data: client}), nil
}

func (s *AuthContractServer) RemoveOAuthClient(
	ctx context.Context,
	request *connect.Request[tenancyv2.RemoveOAuthClientRequest],
) (*connect.Response[tenancyv2.RemoveOAuthClientResponse], error) {
	if err := s.business.RemoveOAuthClient(ctx, request.Msg.GetId()); err != nil {
		return nil, s.parent.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv2.RemoveOAuthClientResponse{Succeeded: true}), nil
}

func (s *AuthContractServer) CreateServiceAccount(
	ctx context.Context,
	request *connect.Request[tenancyv2.CreateServiceAccountRequest],
) (*connect.Response[tenancyv2.CreateServiceAccountResponse], error) {
	response, err := s.business.CreateServiceAccount(ctx, request.Msg)
	if err != nil {
		return nil, s.parent.toAPIError(err)
	}
	return connect.NewResponse(response), nil
}

func (s *AuthContractServer) GetServiceAccount(
	ctx context.Context,
	request *connect.Request[tenancyv2.GetServiceAccountRequest],
) (*connect.Response[tenancyv2.GetServiceAccountResponse], error) {
	serviceAccount, err := s.business.GetServiceAccount(ctx, request.Msg)
	if err != nil {
		return nil, s.parent.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv2.GetServiceAccountResponse{Data: serviceAccount}), nil
}

func (s *AuthContractServer) ListServiceAccounts(
	ctx context.Context,
	request *connect.Request[tenancyv2.ListServiceAccountsRequest],
) (*connect.Response[tenancyv2.ListServiceAccountsResponse], error) {
	serviceAccounts, err := s.business.ListServiceAccounts(ctx, request.Msg)
	if err != nil {
		return nil, s.parent.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv2.ListServiceAccountsResponse{Data: serviceAccounts}), nil
}

func (s *AuthContractServer) UpdateServiceAccount(
	ctx context.Context,
	request *connect.Request[tenancyv2.UpdateServiceAccountRequest],
) (*connect.Response[tenancyv2.UpdateServiceAccountResponse], error) {
	serviceAccount, err := s.business.UpdateServiceAccount(ctx, request.Msg)
	if err != nil {
		return nil, s.parent.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv2.UpdateServiceAccountResponse{Data: serviceAccount}), nil
}

func (s *AuthContractServer) RemoveServiceAccount(
	ctx context.Context,
	request *connect.Request[tenancyv2.RemoveServiceAccountRequest],
) (*connect.Response[tenancyv2.RemoveServiceAccountResponse], error) {
	if err := s.business.RemoveServiceAccount(ctx, request.Msg.GetId()); err != nil {
		return nil, s.parent.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv2.RemoveServiceAccountResponse{Succeeded: true}), nil
}

func (s *AuthContractServer) ReconcileServiceAccountAuthorization(
	ctx context.Context,
	request *connect.Request[tenancyv2.ReconcileServiceAccountAuthorizationRequest],
) (*connect.Response[tenancyv2.ReconcileServiceAccountAuthorizationResponse], error) {
	generation, err := s.business.ReconcileServiceAccountAuthorization(ctx, request.Msg.GetId())
	if err != nil {
		return nil, s.parent.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv2.ReconcileServiceAccountAuthorizationResponse{Generation: generation}), nil
}
