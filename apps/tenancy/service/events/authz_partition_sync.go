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

const EventKeyAuthzPartitionSync = "authorization.partition.sync"

// AuthzPartitionSyncEvent writes authorization tuples to Keto after a partition
// is created or synced. This is separate from the Hydra sync event so that
// authorization concerns are decoupled from OAuth2 client management.
//
// For every child partition it writes data-access inheritance, human-role
// inheritance, and explicit service-account grants validated against the OPL
// manifest registry.
type AuthzPartitionSyncEvent struct {
	partitionRepo        repository.PartitionRepository
	serviceAccountRepo   repository.ServiceAccountRepository
	serviceNamespaceRepo repository.ServiceNamespaceRepository
	policyRepo           repository.ServiceAccountAuthorizationPolicyRepository
	eventsMan            fevents.Manager
	authorizer           security.Authorizer
}

func NewAuthzPartitionSyncEventHandler(
	partitionRepo repository.PartitionRepository,
	serviceAccountRepo repository.ServiceAccountRepository,
	serviceNamespaceRepo repository.ServiceNamespaceRepository,
	policyRepo repository.ServiceAccountAuthorizationPolicyRepository,
	eventsMan fevents.Manager,
	auth security.Authorizer,
) fevents.EventI {
	return &AuthzPartitionSyncEvent{
		partitionRepo:        partitionRepo,
		serviceAccountRepo:   serviceAccountRepo,
		serviceNamespaceRepo: serviceNamespaceRepo,
		policyRepo:           policyRepo,
		eventsMan:            eventsMan,
		authorizer:           auth,
	}
}

func (e *AuthzPartitionSyncEvent) Name() string {
	return EventKeyAuthzPartitionSync
}

func (e *AuthzPartitionSyncEvent) PayloadType() any {
	var payloadT map[string]any
	return &payloadT
}

func (e *AuthzPartitionSyncEvent) Validate(_ context.Context, payload any) error {
	d, ok := payload.(*map[string]any)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *map[string]any got %T", payload)
	}
	m := data.JSONMap(*d)
	if m.GetString("id") == "" {
		return errors.New("partition id is required")
	}
	return nil
}

func (e *AuthzPartitionSyncEvent) Execute(ictx context.Context, payload any) error {
	d, ok := payload.(*map[string]any)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *map[string]any got %T", payload)
	}

	jsonPayload := data.JSONMap(*d)
	ctx := security.SkipTenancyChecksOnClaims(ictx)
	ctx, cancel := withEventTimeout(ctx)
	defer cancel()

	partitionID := jsonPayload.GetString("id")
	logger := util.Log(ctx).WithFields(map[string]any{
		"partition_id": partitionID,
		"type":         e.Name(),
	})

	partition, err := e.partitionRepo.GetByID(ctx, partitionID)
	if err != nil {
		if isPermanentError(err) {
			logger.WithError(err).Warn("partition not found — skipping sync")
			return nil
		}
		return fmt.Errorf("failed to get partition %s: %w", partitionID, err)
	}

	tenancyPath := fmt.Sprintf("%s/%s", partition.TenantID, partition.GetID())

	logger.WithField("tenancy_path", tenancyPath).
		Debug("partition authz sync processed")

	// Write partition inheritance tuple if this partition has a parent.
	// This creates a Keto subject set so members of the parent partition
	// automatically get access to the child partition.
	if partition.ParentID == "" {
		return nil
	}

	parentPartition, err := e.partitionRepo.GetByID(ctx, partition.ParentID)
	if err != nil {
		if isPermanentError(err) {
			logger.WithError(err).Warn("parent partition not found — skipping inheritance sync")
			return nil
		}
		return fmt.Errorf("failed to get parent partition %s: %w", partition.ParentID, err)
	}

	parentPath := fmt.Sprintf("%s/%s", parentPartition.TenantID, parentPartition.GetID())

	namespaces, err := e.serviceNamespaceRepo.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("failed to load registered authorization namespaces: %w", err)
	}
	// Human access retains subject-set inheritance. Service-account access is
	// materialised directly by each policy reconciler and never inherited via a
	// shared service relation.
	memberTuple := authz.BuildPartitionInheritanceTuple(parentPath, tenancyPath)

	if writeErr := writeTuplesWithRetry(ctx, e.Name()+".inheritance", func(ctx context.Context) error {
		return e.authorizer.WriteTuple(ctx, memberTuple)
	}); writeErr != nil {
		logger.WithError(writeErr).Error("failed to write partition inheritance tuples")
		return writeErr
	}

	logger.WithField("parent_path", parentPath).
		Debug("partition inheritance tuples written")

	// Materialise human-role inheritance only.
	var schemaTuples []security.RelationTuple
	for _, role := range authz.StandardRoles {
		supportedNamespaces := authz.FilterNamespacesForRole(namespaces, role)
		schemaTuples = append(schemaTuples,
			authz.BuildRoleInheritanceTuples(tenancyPath, supportedNamespaces, []string{role})...,
		)
	}
	if len(schemaTuples) > 0 {
		authz.SortRelationTuples(schemaTuples)
		if writeErr := writeTuplesWithRetry(ctx, e.Name()+".schema", func(ctx context.Context) error {
			return e.authorizer.WriteTuples(ctx, schemaTuples)
		}); writeErr != nil {
			return fmt.Errorf("failed to write schema-validated partition tuples: %w", writeErr)
		}
	}

	if err = e.requeueAncestorServiceAccountPolicies(ctx, partition); err != nil {
		return err
	}

	return nil
}

func (e *AuthzPartitionSyncEvent) requeueAncestorServiceAccountPolicies(
	ctx context.Context,
	partition interface{ GetID() string },
) error {
	ancestors, err := e.partitionRepo.GetParents(ctx, partition.GetID())
	if err != nil {
		return fmt.Errorf("load partition ancestors for policy reconciliation: %w", err)
	}
	for _, ancestor := range ancestors {
		serviceAccounts, listErr := e.serviceAccountRepo.ListByPartition(ctx, ancestor.GetID())
		if listErr != nil {
			return fmt.Errorf("list service accounts for ancestor %s: %w", ancestor.GetID(), listErr)
		}
		for _, serviceAccount := range serviceAccounts {
			policyState, policyErr := e.policyRepo.GetByServiceAccountID(ctx, serviceAccount.GetID())
			if policyErr != nil {
				return fmt.Errorf("load policy for service account %s: %w", serviceAccount.GetID(), policyErr)
			}
			usesPartitionTree := false
			for _, grant := range policyState.Grants {
				if grant.Scope == "partition_tree" {
					usesPartitionTree = true
					break
				}
			}
			if !usesPartitionTree {
				continue
			}
			if emitErr := e.eventsMan.Emit(ctx, EventKeyAuthzServiceAccountSync, data.JSONMap{
				"id":         serviceAccount.GetID(),
				"generation": policyState.Policy.Generation,
				"reason":     "partition_topology_changed",
			}); emitErr != nil {
				return fmt.Errorf("enqueue service account %s policy: %w", serviceAccount.GetID(), emitErr)
			}
		}
	}
	return nil
}
