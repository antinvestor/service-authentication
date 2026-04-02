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
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/util"
)

// CreateClient registers a new OAuth2 client for a partition.
func (prtSrv *TenancyServer) CreateClient(
	ctx context.Context,
	req *connect.Request[tenancyv1.CreateClientRequest],
) (*connect.Response[tenancyv1.CreateClientResponse], error) {
	msg := req.Msg

	var properties map[string]any
	if msg.GetProperties() != nil {
		properties = msg.GetProperties().AsMap()
	}

	result, err := prtSrv.ClientBusiness.CreateClient(
		ctx,
		msg.GetPartitionId(),
		msg.GetName(),
		msg.GetType(),
		msg.GetGrantTypes(),
		msg.GetResponseTypes(),
		msg.GetRedirectUris(),
		msg.GetScopes(),
		msg.GetAudiences(),
		msg.GetRoles(),
		properties,
	)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}

	return connect.NewResponse(&tenancyv1.CreateClientResponse{
		Data:         result.Client.ToAPI(),
		ClientSecret: result.ClientSecret,
	}), nil
}

// GetClient retrieves a client by ID or client_id.
// For service-account clients (internal/external), the response includes the
// associated ServiceAccountObject in the owner oneof field.
func (prtSrv *TenancyServer) GetClient(
	ctx context.Context,
	req *connect.Request[tenancyv1.GetClientRequest],
) (*connect.Response[tenancyv1.GetClientResponse], error) {
	msg := req.Msg

	var cl *models.Client
	var err error
	if msg.GetId() != "" {
		cl, err = prtSrv.ClientBusiness.GetClient(ctx, msg.GetId())
		if err != nil {
			return nil, prtSrv.toAPIError(err)
		}
	} else if msg.GetClientId() != "" {
		cl, err = prtSrv.ClientBusiness.GetClientByClientID(ctx, msg.GetClientId())
		if err != nil {
			return nil, prtSrv.toAPIError(err)
		}
	} else {
		return nil, connect.NewError(connect.CodeInvalidArgument, nil)
	}

	client := cl.ToAPI()

	// For SA-type clients, populate the service_account owner field.
	if cl.Type == "internal" || cl.Type == "external" {
		sa, saErr := prtSrv.ServiceAccountBusiness.GetServiceAccountByClientID(ctx, cl.ClientID)
		if saErr != nil {
			util.Log(ctx).WithFields(map[string]any{
				"client_id":    cl.ClientID,
				"client_db_id": cl.GetID(),
			}).WithError(saErr).Debug("no service account found for SA-type client")
		} else {
			client.SetServiceAccount(sa.ToAPI())
		}
	}

	// Always populate the partition owner so callers can resolve
	// tenant/partition context from a Hydra client_id without extra RPCs.
	if client.GetPartition() == nil && cl.PartitionID != "" {
		part, partErr := prtSrv.PartitionBusiness.GetPartition(ctx, &tenancyv1.GetPartitionRequest{Id: cl.PartitionID})
		if partErr != nil {
			util.Log(ctx).WithField("partition_id", cl.PartitionID).
				WithError(partErr).Debug("could not populate partition owner on client")
		} else {
			client.SetPartition(part)
		}
	}

	return connect.NewResponse(&tenancyv1.GetClientResponse{Data: client}), nil
}

// ListClient streams clients for a partition.
func (prtSrv *TenancyServer) ListClient(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListClientRequest],
	stream *connect.ServerStream[tenancyv1.ListClientResponse],
) error {
	clients, err := prtSrv.ClientBusiness.ListClients(ctx, req.Msg.GetPartitionId())
	if err != nil {
		return prtSrv.toAPIError(err)
	}

	protoClients := make([]*tenancyv1.ClientObject, 0, len(clients))
	for _, cl := range clients {
		protoClients = append(protoClients, cl.ToAPI())
	}

	return stream.Send(&tenancyv1.ListClientResponse{Data: protoClients})
}

// UpdateClient updates an existing OAuth2 client.
func (prtSrv *TenancyServer) UpdateClient(
	ctx context.Context,
	req *connect.Request[tenancyv1.UpdateClientRequest],
) (*connect.Response[tenancyv1.UpdateClientResponse], error) {
	client, err := prtSrv.ClientBusiness.UpdateClient(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.UpdateClientResponse{Data: client}), nil
}

// RemoveClient deletes a client.
func (prtSrv *TenancyServer) RemoveClient(
	ctx context.Context,
	req *connect.Request[tenancyv1.RemoveClientRequest],
) (*connect.Response[tenancyv1.RemoveClientResponse], error) {
	err := prtSrv.ClientBusiness.RemoveClient(ctx, req.Msg.GetId())
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.RemoveClientResponse{Succeeded: true}), nil
}
