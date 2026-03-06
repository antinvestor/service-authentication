package handlers

import (
	"context"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/security/authorizer"
	"github.com/pitabwire/util"
)

// CreateClient registers a new OAuth2 client for a partition.
func (prtSrv *PartitionServer) CreateClient(
	ctx context.Context,
	req *connect.Request[partitionv1.CreateClientRequest],
) (*connect.Response[partitionv1.CreateClientResponse], error) {
	if err := prtSrv.authz.CanPartitionManage(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
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

	return connect.NewResponse(&partitionv1.CreateClientResponse{
		Data:         result.Client.ToAPI(),
		ClientSecret: result.ClientSecret,
	}), nil
}

// GetClient retrieves a client by ID or client_id.
// For service-account clients (internal/external), the response includes the
// associated ServiceAccountObject in the owner oneof field.
func (prtSrv *PartitionServer) GetClient(
	ctx context.Context,
	req *connect.Request[partitionv1.GetClientRequest],
) (*connect.Response[partitionv1.GetClientResponse], error) {
	if err := prtSrv.authz.CanPartitionView(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
	logger := util.Log(ctx)
	msg := req.Msg

	var cl *models.Client
	var err error
	if msg.GetId() != "" {
		cl, err = prtSrv.ClientBusiness.GetClient(ctx, msg.GetId())
		if err != nil {
			logger.WithError(err).Debug("could not get client by id")
			return nil, prtSrv.toAPIError(err)
		}
	} else if msg.GetClientId() != "" {
		cl, err = prtSrv.ClientBusiness.GetClientByClientID(ctx, msg.GetClientId())
		if err != nil {
			logger.WithError(err).Debug("could not get client by client_id")
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
			logger.WithError(saErr).Debug("no service account found for SA-type client")
		} else {
			client.SetServiceAccount(sa.ToAPI())
		}
	}

	// Always populate the partition owner so callers can resolve
	// tenant/partition context from a Hydra client_id without extra RPCs.
	if client.GetPartition() == nil && cl.PartitionID != "" {
		part, partErr := prtSrv.PartitionBusiness.GetPartition(ctx, &partitionv1.GetPartitionRequest{Id: cl.PartitionID})
		if partErr != nil {
			logger.WithError(partErr).Debug("could not populate partition owner on client")
		} else {
			client.SetPartition(part)
		}
	}

	return connect.NewResponse(&partitionv1.GetClientResponse{Data: client}), nil
}

// ListClient streams clients for a partition.
func (prtSrv *PartitionServer) ListClient(
	ctx context.Context,
	req *connect.Request[partitionv1.ListClientRequest],
	stream *connect.ServerStream[partitionv1.ListClientResponse],
) error {
	if err := prtSrv.authz.CanPartitionView(ctx); err != nil {
		return authorizer.ToConnectError(err)
	}
	logger := util.Log(ctx)
	clients, err := prtSrv.ClientBusiness.ListClients(ctx, req.Msg.GetPartitionId())
	if err != nil {
		logger.WithError(err).Debug("could not list clients")
		return prtSrv.toAPIError(err)
	}

	protoClients := make([]*partitionv1.ClientObject, 0, len(clients))
	for _, cl := range clients {
		protoClients = append(protoClients, cl.ToAPI())
	}

	return stream.Send(&partitionv1.ListClientResponse{Data: protoClients})
}

// UpdateClient updates an existing OAuth2 client.
func (prtSrv *PartitionServer) UpdateClient(
	ctx context.Context,
	req *connect.Request[partitionv1.UpdateClientRequest],
) (*connect.Response[partitionv1.UpdateClientResponse], error) {
	if err := prtSrv.authz.CanPartitionManage(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
	logger := util.Log(ctx)
	client, err := prtSrv.ClientBusiness.UpdateClient(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug("could not update client")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.UpdateClientResponse{Data: client}), nil
}

// RemoveClient deletes a client.
func (prtSrv *PartitionServer) RemoveClient(
	ctx context.Context,
	req *connect.Request[partitionv1.RemoveClientRequest],
) (*connect.Response[partitionv1.RemoveClientResponse], error) {
	if err := prtSrv.authz.CanPartitionManage(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
	logger := util.Log(ctx)
	err := prtSrv.ClientBusiness.RemoveClient(ctx, req.Msg.GetId())
	if err != nil {
		logger.WithError(err).Debug("could not remove client")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.RemoveClientResponse{Succeeded: true}), nil
}
