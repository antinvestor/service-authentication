package handlers

import (
	"context"
	"fmt"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/util"
)

// resolvePartitionByClientID resolves a partition from a Hydra client_id.
// It first tries treating the client_id as a partition ID (backward compat),
// then falls back to looking up the Client record to get the partition.
func (h *AuthServer) resolvePartitionByClientID(ctx context.Context, clientID string) (*partitionv1.PartitionObject, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	// Try direct partition lookup (backward compat: client_id == partition_id)
	partitionResp, err := h.partitionCli.GetPartition(ctx, connect.NewRequest(&partitionv1.GetPartitionRequest{Id: clientID}))
	if err == nil {
		if obj := partitionResp.Msg.GetData(); obj != nil {
			return obj, nil
		}
	}

	// Fall back to looking up the Client record by its Hydra client_id
	clientResp, clientErr := h.partitionCli.GetClient(ctx, connect.NewRequest(&partitionv1.GetClientRequest{ClientId: clientID}))
	if clientErr != nil {
		return nil, fmt.Errorf("no partition or client found for id %q: %w", clientID, clientErr)
	}

	// Try the owner.partition field (populated by newer tenancy service)
	if partObj := clientResp.Msg.GetData().GetPartition(); partObj != nil && partObj.GetId() != "" {
		return partObj, nil
	}

	// Fall back to metadata in properties (populated by Hydra sync)
	if props := clientResp.Msg.GetData().GetProperties(); props != nil {
		propsMap := props.AsMap()
		if meta, ok := propsMap["metadata"].(map[string]any); ok {
			partitionID, _ := meta["partition_id"].(string)
			tenantID, _ := meta["tenant_id"].(string)
			if partitionID != "" {
				return &partitionv1.PartitionObject{
					Id:       partitionID,
					TenantId: tenantID,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("could not resolve partition from client %q", clientID)
}

// fetchAccessRoleNames calls ListAccessRole for the given access ID and collects role names.
// Always includes "user" as a base role. Non-fatal: falls back to ["user"] on error.
func (h *AuthServer) fetchAccessRoleNames(ctx context.Context, accessID string) []string {
	roles := []string{"user"}
	if accessID == "" || h.partitionCli == nil {
		return roles
	}

	stream, err := h.partitionCli.ListAccessRole(ctx, connect.NewRequest(
		&partitionv1.ListAccessRoleRequest{AccessId: accessID}))
	if err != nil {
		util.Log(ctx).WithError(err).Warn("failed to list access roles")
		return roles
	}

	seen := map[string]bool{"user": true}
	for stream.Receive() {
		for _, ar := range stream.Msg().GetData() {
			if r := ar.GetRole(); r != nil && r.GetName() != "" && !seen[r.GetName()] {
				seen[r.GetName()] = true
				roles = append(roles, r.GetName())
			}
		}
	}
	if err := stream.Err(); err != nil {
		util.Log(ctx).WithError(err).Warn("error reading access role stream")
	}
	return roles
}

// getOrCreateTenancyAccess resolves a tenancy access object for the given profile/client.
// If no access exists, it creates one via the partition service.
func (h *AuthServer) getOrCreateTenancyAccessByClientID(ctx context.Context, clientID, profileID string) (*partitionv1.AccessObject, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if profileID == "" {
		return nil, fmt.Errorf("profile_id is required")
	}

	getReq := &partitionv1.GetAccessRequest{
		Partition: &partitionv1.GetAccessRequest_ClientId{ClientId: clientID},
		ProfileId: profileID,
	}

	getResp, err := h.partitionCli.GetAccess(ctx, connect.NewRequest(getReq))
	if err == nil {
		access := getResp.Msg.GetData()
		if access == nil {
			return nil, fmt.Errorf("partition service returned empty access object")
		}
		return access, nil
	}

	if !frame.ErrorIsNotFound(err) {
		return nil, fmt.Errorf("failed to resolve access from partition service: %w", err)
	}

	createReq := &partitionv1.CreateAccessRequest{
		Partition: &partitionv1.CreateAccessRequest_ClientId{ClientId: clientID},
		ProfileId: profileID,
	}
	createResp, createErr := h.partitionCli.CreateAccess(ctx, connect.NewRequest(createReq))
	if createErr != nil {
		return nil, fmt.Errorf("failed to create access in partition service: %w", createErr)
	}

	access := createResp.Msg.GetData()
	if access == nil {
		return nil, fmt.Errorf("partition service returned empty create-access response")
	}

	return access, nil
}

// getOrCreateTenancyAccess resolves a tenancy access object for the given profile/client.
// If no access exists, it creates one via the partition service.
func (h *AuthServer) getOrCreateTenancyAccessByPartitionID(ctx context.Context, partitionID, profileID string) (*partitionv1.AccessObject, error) {
	if partitionID == "" {
		return nil, fmt.Errorf("partition_id is required")
	}
	if profileID == "" {
		return nil, fmt.Errorf("profile_id is required")
	}

	getReq := &partitionv1.GetAccessRequest{
		Partition: &partitionv1.GetAccessRequest_PartitionId{PartitionId: partitionID},
		ProfileId: profileID,
	}

	getResp, err := h.partitionCli.GetAccess(ctx, connect.NewRequest(getReq))
	if err == nil {
		access := getResp.Msg.GetData()
		if access == nil {
			return nil, fmt.Errorf("partition service returned empty access object")
		}
		return access, nil
	}

	if !frame.ErrorIsNotFound(err) {
		return nil, fmt.Errorf("failed to resolve access from partition service: %w", err)
	}

	createReq := &partitionv1.CreateAccessRequest{
		Partition: &partitionv1.CreateAccessRequest_PartitionId{PartitionId: partitionID},
		ProfileId: profileID,
	}
	createResp, createErr := h.partitionCli.CreateAccess(ctx, connect.NewRequest(createReq))
	if createErr != nil {
		return nil, fmt.Errorf("failed to create access in partition service: %w", createErr)
	}

	access := createResp.Msg.GetData()
	if access == nil {
		return nil, fmt.Errorf("partition service returned empty create-access response")
	}

	return access, nil
}

// ensureLoginEventTenancyAccess guarantees that login_event has tenant/partition/access context.
// It persists any missing values so downstream token issuance remains auditable.
func (h *AuthServer) ensureLoginEventTenancyAccess(
	ctx context.Context,
	loginEvent *models.LoginEvent,
	clientID string,
	profileID string,
) (*models.LoginEvent, error) {
	if loginEvent == nil {
		return nil, fmt.Errorf("login event is required")
	}
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if profileID == "" {
		return nil, fmt.Errorf("profile_id is required")
	}

	log := util.Log(ctx).WithField("login_event_id", loginEvent.GetID())

	// Resolve the partition first, then use partition_id for access operations.
	// This handles the case where Hydra client_id != partition_id (new Client model).
	partitionObj, resolveErr := h.resolvePartitionByClientID(ctx, clientID)
	var accessObj *partitionv1.AccessObject
	var err error
	if resolveErr == nil && partitionObj.GetId() != "" {
		accessObj, err = h.getOrCreateTenancyAccessByPartitionID(ctx, partitionObj.GetId(), profileID)
	} else {
		// Fall back to client_id based access (backward compat with old tenancy service)
		accessObj, err = h.getOrCreateTenancyAccessByClientID(ctx, clientID, profileID)
	}
	if err != nil {
		return nil, err
	}

	accessPartition := accessObj.GetPartition()
	if accessPartition == nil {
		return nil, fmt.Errorf("partition service returned access without partition")
	}
	if accessObj.GetId() == "" {
		return nil, fmt.Errorf("partition service returned access without id")
	}
	if accessPartition.GetId() == "" || accessPartition.GetTenantId() == "" {
		return nil, fmt.Errorf("partition service returned incomplete partition context")
	}

	changed := make(map[string]struct{}, 6)
	if loginEvent.ClientID != clientID {
		loginEvent.ClientID = clientID
		changed["client_id"] = struct{}{}
	}

	if loginEvent.ProfileID == "" {
		loginEvent.ProfileID = profileID
		changed["profile_id"] = struct{}{}
	} else if loginEvent.ProfileID != profileID {
		return nil, fmt.Errorf("login event profile mismatch")
	}

	if loginEvent.AccessID != accessObj.GetId() {
		loginEvent.AccessID = accessObj.GetId()
		changed["access_id"] = struct{}{}
	}
	if loginEvent.PartitionID != accessPartition.GetId() {
		loginEvent.PartitionID = accessPartition.GetId()
		changed["partition_id"] = struct{}{}
	}
	if loginEvent.TenantID != accessPartition.GetTenantId() {
		loginEvent.TenantID = accessPartition.GetTenantId()
		changed["tenant_id"] = struct{}{}
	}

	if len(changed) == 0 {
		return loginEvent, nil
	}

	fields := make([]string, 0, len(changed))
	for field := range changed {
		fields = append(fields, field)
	}
	if _, err = h.loginEventRepo.Update(ctx, loginEvent, fields...); err != nil {
		return nil, fmt.Errorf("failed to persist login event tenancy context: %w", err)
	}

	if cacheErr := h.setLoginEventToCache(ctx, loginEvent); cacheErr != nil {
		log.WithError(cacheErr).Debug("failed to cache login event after tenancy access update")
	}

	return loginEvent, nil
}
