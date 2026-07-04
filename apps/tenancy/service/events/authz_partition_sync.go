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
	authorizer           security.Authorizer
}

func NewAuthzPartitionSyncEventHandler(
	partitionRepo repository.PartitionRepository,
	serviceAccountRepo repository.ServiceAccountRepository,
	serviceNamespaceRepo repository.ServiceNamespaceRepository,
	auth security.Authorizer,
) fevents.EventI {
	return &AuthzPartitionSyncEvent{
		partitionRepo:        partitionRepo,
		serviceAccountRepo:   serviceAccountRepo,
		serviceNamespaceRepo: serviceNamespaceRepo,
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

	// Load parent service accounts and the exact schema registry that generated
	// Keto's OPL. Tuple construction below is limited to this registry.
	parentSAs, err := e.serviceAccountRepo.ListByPartition(ctx, partition.ParentID)
	if err != nil {
		logger.WithError(err).Warn("failed to list parent partition SAs, writing inheritance tuples only")
		parentSAs = nil
	}
	namespaces, err := e.serviceNamespaceRepo.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("failed to load registered authorization namespaces: %w", err)
	}
	namespaces = authz.SelectDeployedNamespaceRecords(namespaces)
	deployedNamespaces := authz.DeployedServiceNamespaceRecords()

	// Stage 1: Write the critical inheritance tuples (member + service).
	// These MUST succeed — they allow parent partition service accounts
	// and members to access this child partition via Keto graph traversal.
	memberTuple := authz.BuildPartitionInheritanceTuple(parentPath, tenancyPath)
	serviceTuple := authz.BuildServicePartitionInheritanceTuple(parentPath, tenancyPath)
	inheritanceTuples := []security.RelationTuple{memberTuple, serviceTuple}

	if writeErr := writeTuplesWithRetry(ctx, e.Name()+".inheritance", func(ctx context.Context) error {
		return e.authorizer.WriteTuples(ctx, inheritanceTuples)
	}); writeErr != nil {
		logger.WithError(writeErr).Error("failed to write partition inheritance tuples")
		return writeErr
	}

	logger.WithField("parent_path", parentPath).
		Debug("partition inheritance tuples written")

	// Stage 2: Materialise only relations declared by registered manifests.
	// Human roles retain subject-set inheritance. Service accounts receive
	// explicit grants, never a blanket #service bridge.
	var schemaTuples []security.RelationTuple
	for _, role := range authz.StandardRoles {
		supportedNamespaces := authz.FilterNamespacesForRole(namespaces, role)
		schemaTuples = append(schemaTuples,
			authz.BuildRoleInheritanceTuples(tenancyPath, supportedNamespaces, []string{role})...,
		)
	}
	for _, serviceAccount := range parentSAs {
		requestedGrants := authz.SelectRegisteredServiceGrants(
			authz.ParseAudiencePermissions(serviceAccount.Audiences),
			deployedNamespaces,
		)
		grants, resolveErr := authz.ResolveServiceGrants(
			requestedGrants,
			deployedNamespaces,
		)
		if resolveErr != nil {
			return fmt.Errorf(
				"invalid authorization grants for parent service account %s: %w",
				serviceAccount.GetID(),
				resolveErr,
			)
		}
		for namespace, permissions := range grants {
			schemaTuples = append(schemaTuples, authz.BuildServicePermissionTuples(
				tenancyPath,
				serviceAccount.ProfileID,
				namespace,
				permissions,
			)...)
		}
	}

	if len(schemaTuples) > 0 {
		authz.SortRelationTuples(schemaTuples)
		if writeErr := writeTuplesWithRetry(ctx, e.Name()+".schema", func(ctx context.Context) error {
			return e.authorizer.WriteTuples(ctx, schemaTuples)
		}); writeErr != nil {
			return fmt.Errorf("failed to write schema-validated partition tuples: %w", writeErr)
		}
	}

	return nil
}
