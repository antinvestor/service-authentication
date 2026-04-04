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

package events

import (
	"context"
	"errors"
	"fmt"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/data"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

const EventKeyAuthzAccessSync = "authorization.access.sync"

// AuthzAccessSyncEvent writes Keto tuples for a user access record during
// bulk sync. This ensures that access records created outside the normal
// RPC flow (e.g. via SQL migrations) get their tenancy_access tuples
// written to Keto.
//
// For each access record and its roles it writes:
//   - tenancy_access:tenancyPath#member ← profile_user:profileID  (base data access)
//   - For each assigned role:
//   - service_tenancy:tenancyPath#role ← profile_user:profileID
//   - tenancy_access:tenancyPath#role ← profile_user:profileID
type AuthzAccessSyncEvent struct {
	accessRepo     repository.AccessRepository
	accessRoleRepo repository.AccessRoleRepository
	roleRepo       repository.PartitionRoleRepository
	authorizer     security.Authorizer
}

func NewAuthzAccessSyncEventHandler(
	accessRepo repository.AccessRepository,
	accessRoleRepo repository.AccessRoleRepository,
	roleRepo repository.PartitionRoleRepository,
	auth security.Authorizer,
) fevents.EventI {
	return &AuthzAccessSyncEvent{
		accessRepo:     accessRepo,
		accessRoleRepo: accessRoleRepo,
		roleRepo:       roleRepo,
		authorizer:     auth,
	}
}

func (e *AuthzAccessSyncEvent) Name() string {
	return EventKeyAuthzAccessSync
}

func (e *AuthzAccessSyncEvent) PayloadType() any {
	var payloadT map[string]any
	return &payloadT
}

func (e *AuthzAccessSyncEvent) Validate(_ context.Context, payload any) error {
	d, ok := payload.(*map[string]any)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *map[string]any got %T", payload)
	}
	m := data.JSONMap(*d)
	if m.GetString("id") == "" {
		return errors.New("access id is required")
	}
	return nil
}

func (e *AuthzAccessSyncEvent) Execute(ictx context.Context, payload any) error {
	d, ok := payload.(*map[string]any)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *map[string]any got %T", payload)
	}

	jsonPayload := data.JSONMap(*d)
	ctx := security.SkipTenancyChecksOnClaims(ictx)

	accessID := jsonPayload.GetString("id")
	logger := util.Log(ctx).WithFields(map[string]any{
		"access_id": accessID,
		"type":      e.Name(),
	})

	access, err := e.accessRepo.GetByID(ctx, accessID)
	if err != nil {
		return fmt.Errorf("failed to get access %s: %w", accessID, err)
	}

	tenancyPath := fmt.Sprintf("%s/%s", access.TenantID, access.PartitionID)
	profileID := access.ProfileID

	// Base data-access tuple: tenancy_access#member
	tuples := []security.RelationTuple{
		authz.BuildAccessTuple(tenancyPath, profileID),
	}

	// Role tuples for each assigned access role
	accessRoles, err := e.accessRoleRepo.GetByAccessID(ctx, accessID)
	if err != nil {
		logger.WithError(err).Warn("failed to list access roles, writing member tuple only")
	} else {
		roleIDs := make([]string, 0, len(accessRoles))
		for _, ar := range accessRoles {
			roleIDs = append(roleIDs, ar.PartitionRoleID)
		}

		if len(roleIDs) > 0 {
			roles, roleErr := e.roleRepo.GetRolesByID(ctx, roleIDs...)
			if roleErr != nil {
				logger.WithError(roleErr).Warn("failed to resolve role names")
			} else {
				for _, role := range roles {
					tuples = append(tuples, authz.BuildRoleTuples(tenancyPath, profileID, role.Name)...)
				}
			}
		}
	}

	if writeErr := e.authorizer.WriteTuples(ctx, tuples); writeErr != nil {
		logger.WithError(writeErr).WithFields(map[string]any{
			"tenancy_path": tenancyPath,
			"profile_id":   profileID,
			"tuple_count":  len(tuples),
			"tuples":       formatTuples(tuples),
		}).Error("failed to write access authorization tuples")
		return fmt.Errorf("failed to write access authorization tuples: %w", writeErr)
	}

	logger.WithFields(map[string]any{
		"tenancy_path": tenancyPath,
		"profile_id":   profileID,
		"tuple_count":  len(tuples),
	}).Debug("wrote access authorization tuples")

	return nil
}
