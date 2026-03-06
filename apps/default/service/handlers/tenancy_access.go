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
	accessObj, err := h.getOrCreateTenancyAccessByClientID(ctx, clientID, profileID)
	if err != nil {
		return nil, err
	}

	partitionObj := accessObj.GetPartition()
	if partitionObj == nil {
		return nil, fmt.Errorf("partition service returned access without partition")
	}
	if accessObj.GetId() == "" {
		return nil, fmt.Errorf("partition service returned access without id")
	}
	if partitionObj.GetId() == "" || partitionObj.GetTenantId() == "" {
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
	if loginEvent.PartitionID != partitionObj.GetId() {
		loginEvent.PartitionID = partitionObj.GetId()
		changed["partition_id"] = struct{}{}
	}
	if loginEvent.TenantID != partitionObj.GetTenantId() {
		loginEvent.TenantID = partitionObj.GetTenantId()
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
