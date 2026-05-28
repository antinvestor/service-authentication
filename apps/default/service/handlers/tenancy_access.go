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
	"fmt"
	"slices"
	"strings"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/pkg/partitionpolicy"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/util"
)

type loginEventContextKey string

const (
	loginEventContextKeyID loginEventContextKey = "login_event_id"
)

const (
	loginEventPropertySelectedPartitionID = "selected_partition_id"
	loginEventPropertyLoginSource         = "login_source"
)

type accessInstructionsRedirectError struct {
	URI                  string
	LoginEventID         string
	PartitionName        string
	SupportContacts      map[string]string
	AccessiblePartitions []*tenancyv1.AccessObject // Partitions the user CAN access (for workspace selection)
}

func (e *accessInstructionsRedirectError) Error() string {
	if e.URI == "" {
		return "partition access requires manual approval"
	}
	return fmt.Sprintf("partition access requires manual approval: %s", e.URI)
}

func (e *accessInstructionsRedirectError) RedirectURI() string {
	if e == nil {
		return ""
	}
	return e.URI
}

func partitionAllowsAutoAccess(partition *tenancyv1.PartitionObject) bool {
	if partition == nil || partition.GetProperties() == nil {
		return true
	}

	return partitionpolicy.AllowAutoAccess(partition.GetProperties().AsMap(), true)
}

func partitionAccessRequestURI(partition *tenancyv1.PartitionObject) string {
	if partition == nil || partition.GetProperties() == nil {
		return ""
	}

	return partitionpolicy.AccessRequestURI(partition.GetProperties().AsMap())
}

func partitionSupportContacts(partition *tenancyv1.PartitionObject) map[string]string {
	if partition == nil || partition.GetProperties() == nil {
		return map[string]string{}
	}

	return partitionpolicy.SupportContacts(partition.GetProperties().AsMap())
}

func loginEventIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	loginEventID, _ := ctx.Value(loginEventContextKeyID).(string)
	return strings.TrimSpace(loginEventID)
}

func withLoginEventID(ctx context.Context, loginEventID string) context.Context {
	if ctx == nil || strings.TrimSpace(loginEventID) == "" {
		return ctx
	}

	return context.WithValue(ctx, loginEventContextKeyID, strings.TrimSpace(loginEventID))
}

func selectedPartitionIDFromLoginEvent(loginEvent *models.LoginEvent) string {
	if loginEvent == nil || loginEvent.Properties == nil {
		return ""
	}

	selectedPartitionID, _ := loginEvent.Properties[loginEventPropertySelectedPartitionID].(string)
	return strings.TrimSpace(selectedPartitionID)
}

func setSelectedPartitionID(loginEvent *models.LoginEvent, partitionID string) {
	if loginEvent == nil {
		return
	}

	if loginEvent.Properties == nil {
		loginEvent.Properties = data.JSONMap{}
	}

	trimmed := strings.TrimSpace(partitionID)
	if trimmed == "" {
		delete(loginEvent.Properties, loginEventPropertySelectedPartitionID)
		return
	}

	loginEvent.Properties[loginEventPropertySelectedPartitionID] = trimmed
}

func copyWorkspaceProperties(source data.JSONMap) data.JSONMap {
	selectedPartitionID, _ := source[loginEventPropertySelectedPartitionID].(string)
	selectedPartitionID = strings.TrimSpace(selectedPartitionID)
	if selectedPartitionID == "" {
		return nil
	}

	return data.JSONMap{
		loginEventPropertySelectedPartitionID: selectedPartitionID,
	}
}

func mergeLoginEventProperties(base data.JSONMap, extra map[string]any) data.JSONMap {
	merged := data.JSONMap{}
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extra {
		merged[key] = value
	}

	if len(merged) == 0 {
		return nil
	}

	return merged
}

func loginEventAuthSource(loginEvent *models.LoginEvent) string {
	if loginEvent == nil || loginEvent.Properties == nil {
		return ""
	}

	loginSource, _ := loginEvent.Properties[loginEventPropertyLoginSource].(string)
	return strings.TrimSpace(loginSource)
}

// resolvePartitionByClientID resolves a partition from a Hydra client_id.
// It first tries treating the client_id as a partition ID (backward compat),
// then falls back to looking up the Client record to get the partition.
func (h *AuthServer) resolvePartitionByClientID(ctx context.Context, clientID string) (*tenancyv1.PartitionObject, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	// Try direct partition lookup (backward compat: client_id == partition_id)
	partitionResp, err := h.partitionCli.GetPartition(ctx, connect.NewRequest(&tenancyv1.GetPartitionRequest{Id: clientID}))
	if err == nil {
		if obj := partitionResp.Msg.GetData(); obj != nil {
			return obj, nil
		}
	}

	// Fall back to looking up the Client record by its Hydra client_id
	clientResp, clientErr := h.partitionCli.GetClient(ctx, connect.NewRequest(&tenancyv1.GetClientRequest{ClientId: clientID}))
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
				return &tenancyv1.PartitionObject{
					Id:       partitionID,
					TenantId: tenantID,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("could not resolve partition from client %q", clientID)
}

func (h *AuthServer) isSameOrDescendantPartition(ctx context.Context, ancestorPartitionID, partitionID string) (bool, error) {
	if strings.TrimSpace(ancestorPartitionID) == "" || strings.TrimSpace(partitionID) == "" {
		return false, fmt.Errorf("partition ids are required")
	}

	if ancestorPartitionID == partitionID {
		return true, nil
	}

	parentReq := &tenancyv1.GetPartitionParentsRequest{Id: partitionID}
	parentResp, err := h.partitionCli.GetPartitionParents(ctx, connect.NewRequest(parentReq))
	if err != nil {
		return false, fmt.Errorf("failed to fetch partition parents for %s: %w", partitionID, err)
	}

	for _, parent := range parentResp.Msg.GetData() {
		if parent.GetId() == ancestorPartitionID {
			return true, nil
		}
	}

	return false, nil
}

func (h *AuthServer) filterAccessibleChildPartitions(
	ctx context.Context,
	requestedPartitionID string,
	accesses []*tenancyv1.AccessObject,
) ([]*tenancyv1.AccessObject, error) {
	if strings.TrimSpace(requestedPartitionID) == "" {
		return nil, fmt.Errorf("requested partition id is required")
	}

	result := make([]*tenancyv1.AccessObject, 0, len(accesses))
	for _, access := range accesses {
		if access == nil || access.GetPartition() == nil {
			continue
		}

		partitionID := strings.TrimSpace(access.GetPartition().GetId())
		if partitionID == "" {
			continue
		}

		isDescendant, err := h.isSameOrDescendantPartition(ctx, requestedPartitionID, partitionID)
		if err != nil || !isDescendant {
			continue
		}

		result = append(result, access)
	}

	slices.SortFunc(result, func(a, b *tenancyv1.AccessObject) int {
		aName := strings.ToLower(strings.TrimSpace(a.GetPartition().GetName()))
		bName := strings.ToLower(strings.TrimSpace(b.GetPartition().GetName()))
		if aName == bName {
			return strings.Compare(a.GetPartition().GetId(), b.GetPartition().GetId())
		}
		return strings.Compare(aName, bName)
	})

	return result, nil
}

func (h *AuthServer) resolveEffectivePartitionForLoginEvent(
	ctx context.Context,
	loginEvent *models.LoginEvent,
	clientID string,
	profileID string,
) (*tenancyv1.PartitionObject, error) {
	selectedPartitionID := selectedPartitionIDFromLoginEvent(loginEvent)
	if selectedPartitionID == "" {
		return h.resolvePartitionByClientID(ctx, clientID)
	}

	selectedPartitionResp, err := h.partitionCli.GetPartition(ctx, connect.NewRequest(&tenancyv1.GetPartitionRequest{Id: selectedPartitionID}))
	if err != nil {
		util.Log(ctx).WithError(err).WithFields(map[string]any{
			"login_event_id": loginEvent.GetID(),
			"partition_id":   selectedPartitionID,
		}).Warn("selected partition could not be resolved; falling back to client partition")
		return h.resolvePartitionByClientID(ctx, clientID)
	}

	selectedPartition := selectedPartitionResp.Msg.GetData()
	if selectedPartition == nil || selectedPartition.GetId() == "" {
		return h.resolvePartitionByClientID(ctx, clientID)
	}

	requestedPartition, err := h.resolvePartitionByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	isAllowed, err := h.isSameOrDescendantPartition(ctx, requestedPartition.GetId(), selectedPartition.GetId())
	if err != nil || !isAllowed {
		util.Log(ctx).WithError(err).WithFields(map[string]any{
			"login_event_id":         loginEvent.GetID(),
			"requested_partition_id": requestedPartition.GetId(),
			"selected_partition_id":  selectedPartition.GetId(),
		}).Warn("selected partition is no longer within the requested partition hierarchy")
		return requestedPartition, nil
	}

	accesses, err := h.listTenancyAccessByProfileID(ctx, profileID)
	if err != nil {
		return nil, err
	}

	allowedAccesses, err := h.filterAccessibleChildPartitions(ctx, requestedPartition.GetId(), accesses)
	if err != nil {
		return nil, err
	}

	for _, access := range allowedAccesses {
		if access.GetPartition().GetId() == selectedPartition.GetId() {
			return selectedPartition, nil
		}
	}

	util.Log(ctx).WithFields(map[string]any{
		"login_event_id":         loginEvent.GetID(),
		"requested_partition_id": requestedPartition.GetId(),
		"selected_partition_id":  selectedPartition.GetId(),
		"profile_id":             profileID,
	}).Warn("selected partition is no longer accessible to the profile")

	return requestedPartition, nil
}

func (h *AuthServer) resolvePartitionForLoginEventClaims(
	ctx context.Context,
	loginEvent *models.LoginEvent,
	clientObj *tenancyv1.ClientObject,
) *tenancyv1.PartitionObject {
	if loginEvent != nil && strings.TrimSpace(loginEvent.PartitionID) != "" {
		if clientObj != nil {
			if partition := clientObj.GetPartition(); partition != nil && partition.GetId() == loginEvent.PartitionID {
				return partition
			}
		}

		resp, err := h.partitionCli.GetPartition(ctx, connect.NewRequest(&tenancyv1.GetPartitionRequest{Id: loginEvent.PartitionID}))
		if err == nil && resp.Msg.GetData() != nil {
			return resp.Msg.GetData()
		}
	}

	if clientObj != nil {
		return clientObj.GetPartition()
	}

	return nil
}

// fetchAccessRoleNames calls ListAccessRole for the given access ID and collects role names.
// The defaultRole is read from partition properties ("default_role"); falls back to "user" if unset.
// Non-fatal: falls back to [defaultRole] on error.
func (h *AuthServer) fetchAccessRoleNames(ctx context.Context, accessID string, defaultRole string) []string {
	if defaultRole == "" {
		defaultRole = "user"
	}

	roles := []string{defaultRole}
	if accessID == "" || h.partitionCli == nil {
		return roles
	}

	stream, err := h.partitionCli.ListAccessRole(ctx, connect.NewRequest(
		&tenancyv1.ListAccessRoleRequest{AccessId: accessID}))
	if err != nil {
		util.Log(ctx).WithError(err).Warn("failed to list access roles")
		return roles
	}

	seen := map[string]bool{defaultRole: true}
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

// partitionDefaultRole extracts the "default_role" property from a partition object.
// Returns an empty string if unset, letting callers fall back to "user".
func partitionDefaultRole(partition *tenancyv1.PartitionObject) string {
	if partition == nil {
		return ""
	}
	props := partition.GetProperties()
	if props == nil {
		return ""
	}
	if role, ok := props.AsMap()["default_role"].(string); ok {
		return role
	}
	return ""
}

func (h *AuthServer) getTenancyAccessByClientID(ctx context.Context, clientID, profileID string) (*tenancyv1.AccessObject, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if profileID == "" {
		return nil, fmt.Errorf("profile_id is required")
	}

	getReq := &tenancyv1.GetAccessRequest{
		Partition: &tenancyv1.GetAccessRequest_ClientId{ClientId: clientID},
		ProfileId: profileID,
	}

	getResp, err := h.partitionCli.GetAccess(ctx, connect.NewRequest(getReq))
	if err == nil {
		return accessFromResponse(getResp.Msg.GetData())
	}

	return nil, err
}

func (h *AuthServer) createTenancyAccessByClientID(ctx context.Context, clientID, profileID string) (*tenancyv1.AccessObject, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if profileID == "" {
		return nil, fmt.Errorf("profile_id is required")
	}

	createReq := &tenancyv1.CreateAccessRequest{
		Partition: &tenancyv1.CreateAccessRequest_ClientId{ClientId: clientID},
		ProfileId: profileID,
	}
	createResp, createErr := h.partitionCli.CreateAccess(ctx, connect.NewRequest(createReq))
	if createErr != nil {
		return nil, fmt.Errorf("failed to create access in partition service: %w", createErr)
	}

	return accessFromResponse(createResp.Msg.GetData())
}

// getOrCreateTenancyAccess resolves a tenancy access object for the given profile/client.
// If no access exists, it creates one via the partition service.
func (h *AuthServer) getOrCreateTenancyAccessByClientID(ctx context.Context, clientID, profileID string) (*tenancyv1.AccessObject, error) {
	access, err := h.getTenancyAccessByClientID(ctx, clientID, profileID)
	if err == nil {
		return access, nil
	}
	if !frame.ErrorIsNotFound(err) {
		return nil, fmt.Errorf("failed to resolve access from partition service: %w", err)
	}

	return h.createTenancyAccessByClientID(ctx, clientID, profileID)
}

func (h *AuthServer) getTenancyAccessByPartitionID(ctx context.Context, partitionID, profileID string) (*tenancyv1.AccessObject, error) {
	if partitionID == "" {
		return nil, fmt.Errorf("partition_id is required")
	}
	if profileID == "" {
		return nil, fmt.Errorf("profile_id is required")
	}

	getReq := &tenancyv1.GetAccessRequest{
		Partition: &tenancyv1.GetAccessRequest_PartitionId{PartitionId: partitionID},
		ProfileId: profileID,
	}

	getResp, err := h.partitionCli.GetAccess(ctx, connect.NewRequest(getReq))
	if err == nil {
		return accessFromResponse(getResp.Msg.GetData())
	}

	return nil, err
}

func (h *AuthServer) createTenancyAccessByPartitionID(ctx context.Context, partitionID, profileID string) (*tenancyv1.AccessObject, error) {
	if partitionID == "" {
		return nil, fmt.Errorf("partition_id is required")
	}
	if profileID == "" {
		return nil, fmt.Errorf("profile_id is required")
	}

	createReq := &tenancyv1.CreateAccessRequest{
		Partition: &tenancyv1.CreateAccessRequest_PartitionId{PartitionId: partitionID},
		ProfileId: profileID,
	}
	createResp, createErr := h.partitionCli.CreateAccess(ctx, connect.NewRequest(createReq))
	if createErr != nil {
		return nil, fmt.Errorf("failed to create access in partition service: %w", createErr)
	}

	return accessFromResponse(createResp.Msg.GetData())
}

// listTenancyAccessByProfileID returns all partitions a user has access to.
// Used to offer workspace selection when the user can't access the current partition.
func (h *AuthServer) listTenancyAccessByProfileID(ctx context.Context, profileID string) ([]*tenancyv1.AccessObject, error) {
	if profileID == "" {
		return nil, fmt.Errorf("profile_id is required")
	}

	listReq := &tenancyv1.ListAccessRequest{}
	listReq.SetProfileId(profileID)
	stream, err := h.partitionCli.ListAccess(ctx, connect.NewRequest(listReq))
	if err != nil {
		return nil, fmt.Errorf("failed to list access from partition service: %w", err)
	}

	var result []*tenancyv1.AccessObject
	for stream.Receive() {
		result = append(result, stream.Msg().GetData()...)
	}
	if stream.Err() != nil {
		return nil, stream.Err()
	}

	return result, nil
}

func accessFromResponse(access *tenancyv1.AccessObject) (*tenancyv1.AccessObject, error) {
	if access == nil {
		return nil, fmt.Errorf("partition service returned empty access object")
	}

	return access, nil
}

// getOrCreateTenancyAccess resolves a tenancy access object for the given profile/client.
// If no access exists, it creates one via the partition service.
func (h *AuthServer) getOrCreateTenancyAccessByPartitionID(ctx context.Context, partition *tenancyv1.PartitionObject, profileID string) (*tenancyv1.AccessObject, error) {
	if partition == nil || partition.GetId() == "" {
		return nil, fmt.Errorf("partition is required")
	}

	access, err := h.getTenancyAccessByPartitionID(ctx, partition.GetId(), profileID)
	if err == nil {
		return access, nil
	}
	if !frame.ErrorIsNotFound(err) {
		return nil, fmt.Errorf("failed to resolve access from partition service: %w", err)
	}

	if !partitionAllowsAutoAccess(partition) {
		// Before denying, check if the user has access to any child partitions.
		// This enables the "select your workspace" flow when a user logs in
		// at root but has access to specific organisations/branches.
		var accessiblePartitions []*tenancyv1.AccessObject
		if h.partitionCli != nil {
			accesses, listErr := h.listTenancyAccessByProfileID(ctx, profileID)
			if listErr == nil && len(accesses) > 0 {
				accessiblePartitions, _ = h.filterAccessibleChildPartitions(ctx, partition.GetId(), accesses)
			}
		}

		return nil, &accessInstructionsRedirectError{
			URI:                  partitionAccessRequestURI(partition),
			LoginEventID:         loginEventIDFromContext(ctx),
			PartitionName:        partition.GetName(),
			SupportContacts:      partitionSupportContacts(partition),
			AccessiblePartitions: accessiblePartitions,
		}
	}

	return h.createTenancyAccessByPartitionID(ctx, partition.GetId(), profileID)
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

	ctx = withLoginEventID(ctx, loginEvent.GetID())
	log := util.Log(ctx).WithField("login_event_id", loginEvent.GetID())

	// Resolve the partition first, then use partition_id for access operations.
	// This handles the case where Hydra client_id != partition_id (new Client model).
	partitionObj, resolveErr := h.resolveEffectivePartitionForLoginEvent(ctx, loginEvent, clientID, profileID)
	var accessObj *tenancyv1.AccessObject
	var err error
	if resolveErr == nil && partitionObj.GetId() != "" {
		accessObj, err = h.getOrCreateTenancyAccessByPartitionID(ctx, partitionObj, profileID)
	} else {
		// Fall back to client_id based access (backward compat with old tenancy service)
		accessObj, err = h.getOrCreateTenancyAccessByClientID(ctx, clientID, profileID)
	}
	if err != nil {
		var redirectErr *accessInstructionsRedirectError
		if errors.As(err, &redirectErr) {
			return nil, err
		}
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
