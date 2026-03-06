package handlers

import (
	"context"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/pitabwire/frame/security/authorizer"
)

// CreateServiceAccount registers a new service account for a partition.
func (prtSrv *PartitionServer) CreateServiceAccount(
	ctx context.Context,
	req *connect.Request[partitionv1.CreateServiceAccountRequest],
) (*connect.Response[partitionv1.CreateServiceAccountResponse], error) {
	if err := prtSrv.authz.CanPermissionGrant(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
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
	return connect.NewResponse(&partitionv1.CreateServiceAccountResponse{
		Data:         sa.ToAPI(),
		ClientSecret: result.ClientSecret,
	}), nil
}

// GetServiceAccount retrieves a service account by ID, client_id, or client_id+profile_id.
func (prtSrv *PartitionServer) GetServiceAccount(
	ctx context.Context,
	req *connect.Request[partitionv1.GetServiceAccountRequest],
) (*connect.Response[partitionv1.GetServiceAccountResponse], error) {
	if err := prtSrv.authz.CanPartitionView(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
	msg := req.Msg

	sa, err := prtSrv.ServiceAccountBusiness.GetServiceAccount(ctx, msg.GetId(), msg.GetClientId(), msg.GetProfileId())
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}

	return connect.NewResponse(&partitionv1.GetServiceAccountResponse{
		Data: sa.ToAPI(),
	}), nil
}

// ListServiceAccount streams service accounts for a partition.
func (prtSrv *PartitionServer) ListServiceAccount(
	ctx context.Context,
	req *connect.Request[partitionv1.ListServiceAccountRequest],
	stream *connect.ServerStream[partitionv1.ListServiceAccountResponse],
) error {
	if err := prtSrv.authz.CanPartitionView(ctx); err != nil {
		return authorizer.ToConnectError(err)
	}
	accounts, err := prtSrv.ServiceAccountBusiness.ListServiceAccounts(ctx, req.Msg.GetPartitionId())
	if err != nil {
		return prtSrv.toAPIError(err)
	}

	protoAccounts := make([]*partitionv1.ServiceAccountObject, 0, len(accounts))
	for _, sa := range accounts {
		protoAccounts = append(protoAccounts, sa.ToAPI())
	}

	if err := stream.Send(&partitionv1.ListServiceAccountResponse{
		Data: protoAccounts,
	}); err != nil {
		return err
	}

	return nil
}

// UpdateServiceAccount updates a service account's configuration.
func (prtSrv *PartitionServer) UpdateServiceAccount(
	ctx context.Context,
	req *connect.Request[partitionv1.UpdateServiceAccountRequest],
) (*connect.Response[partitionv1.UpdateServiceAccountResponse], error) {
	if err := prtSrv.authz.CanPermissionGrant(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
	sa, err := prtSrv.ServiceAccountBusiness.UpdateServiceAccount(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}

	return connect.NewResponse(&partitionv1.UpdateServiceAccountResponse{
		Data: sa,
	}), nil
}

// RemoveServiceAccount deregisters a service account.
func (prtSrv *PartitionServer) RemoveServiceAccount(
	ctx context.Context,
	req *connect.Request[partitionv1.RemoveServiceAccountRequest],
) (*connect.Response[partitionv1.RemoveServiceAccountResponse], error) {
	if err := prtSrv.authz.CanPermissionGrant(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
	if err := prtSrv.ServiceAccountBusiness.RemoveServiceAccount(ctx, req.Msg.GetId()); err != nil {
		return nil, prtSrv.toAPIError(err)
	}

	return connect.NewResponse(&partitionv1.RemoveServiceAccountResponse{
		Succeeded: true,
	}), nil
}
