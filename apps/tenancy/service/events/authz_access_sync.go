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
	"github.com/pitabwire/frame/v2/data"
	fevents "github.com/pitabwire/frame/v2/events"
	"github.com/pitabwire/frame/v2/security"
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
//   - <registered_namespace>:tenancyPath#role ← profile_user:profileID
//   - tenancy_access:tenancyPath#role ← profile_user:profileID
type AuthzAccessSyncEvent struct {
	accessRepo           repository.AccessRepository
	accessRoleRepo       repository.AccessRoleRepository
	roleRepo             repository.PartitionRoleRepository
	serviceNamespaceRepo repository.ServiceNamespaceRepository
	authorizer           security.Authorizer
}

func NewAuthzAccessSyncEventHandler(
	accessRepo repository.AccessRepository,
	accessRoleRepo repository.AccessRoleRepository,
	roleRepo repository.PartitionRoleRepository,
	serviceNamespaceRepo repository.ServiceNamespaceRepository,
	auth security.Authorizer,
) fevents.EventI {
	return &AuthzAccessSyncEvent{
		accessRepo:           accessRepo,
		accessRoleRepo:       accessRoleRepo,
		roleRepo:             roleRepo,
		serviceNamespaceRepo: serviceNamespaceRepo,
		authorizer:           auth,
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
	ctx, cancel := withEventTimeout(ctx)
	defer cancel()

	accessID := jsonPayload.GetString("id")
	logger := util.Log(ctx).WithFields(map[string]any{
		"access_id": accessID,
		"type":      e.Name(),
	})

	access, err := e.accessRepo.GetByID(ctx, accessID)
	if err != nil {
		if isPermanentError(err) {
			logger.WithError(err).Warn("access record not found — skipping sync")
			return nil
		}
		return fmt.Errorf("failed to get access %s: %w", accessID, err)
	}

	tenancyPath := fmt.Sprintf("%s/%s", access.TenantID, access.PartitionID)
	profileID := access.ProfileID

	// Base data-access tuple: tenancy_access#member
	tuples := []security.RelationTuple{
		authz.BuildAccessTuple(tenancyPath, profileID),
	}

	// Role tuples for each assigned access role
	hasPrivilegedRole := false
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
				registeredNS, nsErr := e.serviceNamespaceRepo.ListAll(ctx)
				if nsErr != nil {
					return fmt.Errorf("list registered service namespaces: %w", nsErr)
				}

				for _, role := range roles {
					tuples = append(tuples, authz.BuildRoleTuples(tenancyPath, profileID, role.Name, registeredNS)...)
					if role.Name == authz.RoleOwner || role.Name == authz.RoleAdmin {
						hasPrivilegedRole = true
					}
				}
			}
		}
	}

	// Root partition owner/admin users get the "internal" JWT role at login,
	// and Frame's TenancyAccessChecker checks the "service" relation for
	// internal callers. Only owner/admin need this — plain members never
	// receive the "internal" JWT role.
	if authz.IsRootPartition(access.PartitionID) && hasPrivilegedRole {
		tuples = append(tuples, authz.BuildServiceAccessTuple(tenancyPath, profileID))
	}

	return writeTuplesWithRetry(ctx, e.Name(), func(ctx context.Context) error {
		return e.authorizer.WriteTuples(ctx, tuples)
	})
}
