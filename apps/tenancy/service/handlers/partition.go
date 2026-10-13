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

	"buf.build/gen/go/antinvestor/profile/connectrpc/go/v2/profile/v1/profilev1connect"
	"buf.build/gen/go/antinvestor/tenancy/connectrpc/go/v2/tenancy/v1/tenancyv1connect"
	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/v3"
	"github.com/pitabwire/frame/v3/datastore"
	"github.com/pitabwire/frame/v3/events"
)

type TenancyServer struct {
	svc       *frame.Service
	eventsMan events.Manager

	ProfileCli              profilev1connect.ProfileServiceClient
	PartitionRepo           repository.PartitionRepository
	ClientRepo              repository.ClientRepository
	OAuthRecipientRepo      repository.OAuthClientRecipientRepository
	ServiceAccountRepo      repository.ServiceAccountRepository
	AuthorizationPolicyRepo repository.ServiceAccountAuthorizationPolicyRepository
	AuthContractRepo        repository.AuthContractRepository
	AccessRepo              repository.AccessRepository
	AccessRoleRepo          repository.AccessRoleRepository
	PartitionRoleRepo       repository.PartitionRoleRepository
	ServiceNamespaceRepo    repository.ServiceNamespaceRepository

	PartitionBusiness business.PartitionBusiness
	TenantBusiness    business.TenantBusiness
	AccessBusiness    business.AccessBusiness
	PageBusiness      business.PageBusiness
	tenancyv1connect.UnimplementedTenancyServiceHandler
}

// NewTenancyServer creates a new TenancyServer with injected dependencies.
func NewTenancyServer(ctx context.Context, service *frame.Service, profileCli profilev1connect.ProfileServiceClient) *TenancyServer {
	// Create all repositories once
	dbPool := service.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName)
	workMan := service.WorkManager()

	tenantRepo := repository.NewTenantRepository(ctx, dbPool, workMan)
	partitionRepo := repository.NewPartitionRepository(ctx, dbPool, workMan)
	partitionRoleRepo := repository.NewPartitionRoleRepository(ctx, dbPool, workMan)
	accessRepo := repository.NewAccessRepository(ctx, dbPool, workMan)
	accessRoleRepo := repository.NewAccessRoleRepository(ctx, dbPool, workMan)
	pageRepo := repository.NewPageRepository(ctx, dbPool, workMan)
	clientRepo := repository.NewClientRepository(ctx, dbPool, workMan)
	oauthRecipientRepo := repository.NewOAuthClientRecipientRepository(ctx, dbPool, workMan)
	serviceAccountRepo := repository.NewServiceAccountRepository(ctx, dbPool, workMan)
	authorizationPolicyRepo := repository.NewServiceAccountAuthorizationPolicyRepository(ctx, dbPool, workMan)
	authContractRepo := repository.NewAuthContractRepository(dbPool)
	serviceNamespaceRepo := repository.NewServiceNamespaceRepository(ctx, dbPool, workMan)

	cfg := service.Config().(*config.TenancyConfig)
	eventsMan := service.EventsManager()

	// Create business layers with repository dependencies
	return &TenancyServer{
		svc:                     service,
		eventsMan:               eventsMan,
		ProfileCli:              profileCli,
		PartitionRepo:           partitionRepo,
		ClientRepo:              clientRepo,
		OAuthRecipientRepo:      oauthRecipientRepo,
		ServiceAccountRepo:      serviceAccountRepo,
		AuthorizationPolicyRepo: authorizationPolicyRepo,
		AuthContractRepo:        authContractRepo,
		AccessRepo:              accessRepo,
		AccessRoleRepo:          accessRoleRepo,
		PartitionRoleRepo:       partitionRoleRepo,
		ServiceNamespaceRepo:    serviceNamespaceRepo,
		PartitionBusiness:       business.NewPartitionBusiness(*cfg, eventsMan, tenantRepo, partitionRepo, partitionRoleRepo, accessRepo, clientRepo, serviceAccountRepo),
		TenantBusiness:          business.NewTenantBusiness(service, tenantRepo, partitionRepo),
		AccessBusiness:          business.NewAccessBusiness(service, eventsMan, accessRepo, accessRoleRepo, partitionRepo, partitionRoleRepo, serviceNamespaceRepo),
		PageBusiness:            business.NewPageBusiness(service, pageRepo, partitionRepo),
	}
}

func (prtSrv *TenancyServer) ListPartition(
	ctx context.Context,
	req *tenancyv1.ListPartitionRequest,
	stream tenancyv1connect.TenancyServiceListPartitionServerStream) error {
	partitions, err := prtSrv.PartitionBusiness.ListPartition(ctx, req)
	if err != nil {
		return prtSrv.toAPIError(err)
	}
	return stream.Send(&tenancyv1.ListPartitionResponse{Data: partitions})
}

func (prtSrv *TenancyServer) CreatePartition(
	ctx context.Context,
	req *tenancyv1.CreatePartitionRequest) (*tenancyv1.CreatePartitionResponse, error) {
	partition, err := prtSrv.PartitionBusiness.CreatePartition(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.CreatePartitionResponse{Data: partition}, nil
}

func (prtSrv *TenancyServer) GetPartition(
	ctx context.Context,
	req *tenancyv1.GetPartitionRequest) (*tenancyv1.GetPartitionResponse, error) {
	partition, err := prtSrv.PartitionBusiness.GetPartition(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.GetPartitionResponse{Data: partition}, nil
}

func (prtSrv *TenancyServer) GetPartitionParents(
	ctx context.Context,
	req *tenancyv1.GetPartitionParentsRequest) (*tenancyv1.GetPartitionParentsResponse, error) {
	partition, err := prtSrv.PartitionBusiness.GetPartitionParents(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.GetPartitionParentsResponse{Data: partition}, nil
}

func (prtSrv *TenancyServer) UpdatePartition(
	ctx context.Context,
	req *tenancyv1.UpdatePartitionRequest) (*tenancyv1.UpdatePartitionResponse, error) {
	partition, err := prtSrv.PartitionBusiness.UpdatePartition(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.UpdatePartitionResponse{Data: partition}, nil
}

func (prtSrv *TenancyServer) CreatePartitionRole(
	ctx context.Context,
	req *tenancyv1.CreatePartitionRoleRequest) (*tenancyv1.CreatePartitionRoleResponse, error) {
	partition, err := prtSrv.PartitionBusiness.CreatePartitionRole(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.CreatePartitionRoleResponse{Data: partition}, nil
}

func (prtSrv *TenancyServer) ListPartitionRole(
	ctx context.Context,
	req *tenancyv1.ListPartitionRoleRequest,
	stream tenancyv1connect.TenancyServiceListPartitionRoleServerStream) error {
	resp, err := prtSrv.PartitionBusiness.ListPartitionRoles(ctx, req)
	if err != nil {
		return prtSrv.toAPIError(err)
	}
	return stream.Send(resp)
}

func (prtSrv *TenancyServer) UpdatePartitionRole(
	ctx context.Context,
	req *tenancyv1.UpdatePartitionRoleRequest) (*tenancyv1.UpdatePartitionRoleResponse, error) {
	role, err := prtSrv.PartitionBusiness.UpdatePartitionRole(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.UpdatePartitionRoleResponse{Data: role}, nil
}

func (prtSrv *TenancyServer) RemovePartition(
	ctx context.Context,
	req *tenancyv1.RemovePartitionRequest) (*tenancyv1.RemovePartitionResponse, error) {
	err := prtSrv.PartitionBusiness.RemovePartition(ctx, req.GetId())
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.RemovePartitionResponse{Succeeded: true}, nil
}

func (prtSrv *TenancyServer) RemovePartitionRole(
	ctx context.Context,
	req *tenancyv1.RemovePartitionRoleRequest) (*tenancyv1.RemovePartitionRoleResponse, error) {
	err := prtSrv.PartitionBusiness.RemovePartitionRole(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.RemovePartitionRoleResponse{
		Succeeded: true,
	}, nil
}
