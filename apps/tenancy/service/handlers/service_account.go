package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/encoding/protojson"
)

const ServiceAccountByClientIDPath = "/_system/service-account/by-client-id/{clientID}"

// CreateServiceAccount registers a new service account for a partition.
func (prtSrv *PartitionServer) CreateServiceAccount(
	ctx context.Context,
	req *connect.Request[partitionv1.CreateServiceAccountRequest],
) (*connect.Response[partitionv1.CreateServiceAccountResponse], error) {
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
	if err := prtSrv.ServiceAccountBusiness.RemoveServiceAccount(ctx, req.Msg.GetId()); err != nil {
		return nil, prtSrv.toAPIError(err)
	}

	return connect.NewResponse(&partitionv1.RemoveServiceAccountResponse{
		Succeeded: true,
	}), nil
}

// GetServiceAccountByClientID returns a service account by its OAuth2 client ID.
// This is an internal service-to-service endpoint. It requires the caller to have
// a system_internal role (i.e. be an internal service account) to prevent
// arbitrary authenticated users from looking up any SA by client_id.
func (prtSrv *PartitionServer) GetServiceAccountByClientID(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	log := util.Log(ctx)

	// Verify the caller has system_internal role
	claims := security.ClaimsFromContext(ctx)
	if claims == nil || !slices.Contains(claims.GetRoles(), "system_internal") {
		rw.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(rw).Encode(map[string]string{"error": "system_internal role required"})
		return
	}

	ctx = security.SkipTenancyChecksOnClaims(ctx)

	clientID := req.PathValue("clientID")
	if clientID == "" {
		rw.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(rw).Encode(map[string]string{"error": "clientID is required"})
		return
	}

	sa, err := prtSrv.ServiceAccountBusiness.GetServiceAccountByClientID(ctx, clientID)
	if err != nil {
		log.WithError(err).WithField("client_id", clientID).Warn("service account lookup failed")
		rw.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(rw).Encode(map[string]string{"error": "service account not found"})
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)

	protoObj := sa.ToAPI()
	respBytes, mErr := protojson.Marshal(protoObj)
	if mErr != nil {
		log.WithError(mErr).Error("failed to marshal service account")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, _ = rw.Write(respBytes)
}
