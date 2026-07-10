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

package business

import (
	"context"
	"fmt"
	"strings"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/util"
)

// ServiceBotTenancyDeps bundles repositories needed to provision Plane-1
// service access for internal service accounts.
type ServiceBotTenancyDeps struct {
	ServiceAccountRepo repository.ServiceAccountRepository
	PartitionRepo      repository.PartitionRepository
	Authorizer         security.Authorizer
}

// EnsureServiceBotTenancyAccess writes the Keto tuples that let internal
// service bots operate across every tenant/partition.
//
// Identity model (critical):
//
//	Ory Hydra cannot override the JWT "sub" claim for client_credentials tokens
//	(sub is always the OAuth2 client_id). Frame's TenancyAccessChecker checks
//	Keto with subject_id = JWT sub. Therefore SA Plane-1 subjects MUST be the
//	Hydra client_id (e.g. "service-authentication"), not the profile_id.
//
// Tuples written:
//
//  1. tenancy_access:<tenant>/<partition>#service ← <sa.client_id>
//     for every service account × every partition (including root)
//  2. tenancy_access:<child>#service ← tenancy_access:<parent>#service
//     for every parent→child partition edge (inheritance for future partitions)
//
// Profile_id is dual-written as a secondary subject when present so any
// caller that still checks profile identity continues to work.
//
// Cross-tenant product partitions (e.g. opportunities) are not descendants of
// the platform root path, so inheritance alone is insufficient — we grant
// explicit service access on each known partition.
//
// Without these grants, service-authentication fails Plane-1 checks:
//
//	permission_denied: service-authentication cannot service on tenancy_access:…
//
// Idempotent and safe to run on every tenancy pod start.
func EnsureServiceBotTenancyAccess(ctx context.Context, deps ServiceBotTenancyDeps) error {
	logger := util.Log(ctx).WithField("component", "service_bot_tenancy_bootstrap")

	if deps.Authorizer == nil {
		return fmt.Errorf("service bot bootstrap: authorizer is required")
	}
	if deps.ServiceAccountRepo == nil || deps.PartitionRepo == nil {
		return fmt.Errorf("service bot bootstrap: service account and partition repositories are required")
	}

	ctx = security.SkipTenancyChecksOnClaims(ctx)

	accounts, err := deps.ServiceAccountRepo.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("service bot bootstrap: list service accounts: %w", err)
	}
	partitions, err := deps.PartitionRepo.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("service bot bootstrap: list partitions: %w", err)
	}

	subjects, paths := collectServiceBotSubjectsAndPaths(accounts, partitions)
	tuples := buildServiceBotTenancyTuples(subjects, paths, partitions)

	if len(tuples) == 0 {
		logger.Warn("no service bot tenancy tuples to write")
		return nil
	}

	if writeErr := deps.Authorizer.WriteTuples(ctx, tuples); writeErr != nil {
		return fmt.Errorf("service bot bootstrap: write %d tuples: %w", len(tuples), writeErr)
	}

	logger.WithFields(map[string]any{
		"service_accounts": len(accounts),
		"bot_subjects":     len(subjects),
		"partition_paths":  len(paths),
		"tuples_written":   len(tuples),
	}).Info("service bot tenancy access bootstrap complete")
	return nil
}

// serviceAccountKetoSubject returns the identity used in Keto checks for a
// service account. Hydra sets JWT sub to the OAuth2 client_id for
// client_credentials grants and does not allow the token hook to override it,
// so client_id is the primary subject. Profile_id is a fallback when client_id
// has not been denormalised yet.
func serviceAccountKetoSubject(sa *models.ServiceAccount) string {
	if sa == nil {
		return ""
	}
	if clientID := strings.TrimSpace(sa.ClientID); clientID != "" {
		return clientID
	}
	return strings.TrimSpace(sa.ProfileID)
}

func collectServiceBotSubjectsAndPaths(
	accounts []*models.ServiceAccount,
	partitions []*models.Partition,
) (subjects map[string]struct{}, paths map[string]struct{}) {
	paths = map[string]struct{}{
		fmt.Sprintf("%s/%s", authz.RootTenantID, authz.RootPartitionID): {},
	}
	for _, p := range partitions {
		if p == nil || p.ID == "" {
			continue
		}
		tenantID := strings.TrimSpace(p.TenantID)
		if tenantID == "" {
			continue
		}
		paths[fmt.Sprintf("%s/%s", tenantID, p.ID)] = struct{}{}
	}

	subjects = make(map[string]struct{}, len(accounts)*2)
	for _, sa := range accounts {
		if sa == nil {
			continue
		}
		// Primary: JWT sub (client_id). Secondary: profile_id for dual-write.
		for _, subject := range []string{
			strings.TrimSpace(sa.ClientID),
			strings.TrimSpace(sa.ProfileID),
		} {
			if subject != "" {
				subjects[subject] = struct{}{}
			}
		}
		tenantID := strings.TrimSpace(sa.TenantID)
		partitionID := strings.TrimSpace(sa.PartitionID)
		if tenantID != "" && partitionID != "" {
			paths[fmt.Sprintf("%s/%s", tenantID, partitionID)] = struct{}{}
		}
	}
	return subjects, paths
}

func buildServiceBotTenancyTuples(
	subjects map[string]struct{},
	paths map[string]struct{},
	partitions []*models.Partition,
) []security.RelationTuple {
	tuples := make([]security.RelationTuple, 0, len(subjects)*len(paths)+len(partitions))

	for subject := range subjects {
		for path := range paths {
			tuples = append(tuples, authz.BuildServiceAccessTuple(path, subject))
		}
	}

	byID := make(map[string]*models.Partition, len(partitions))
	for _, p := range partitions {
		if p != nil && p.ID != "" {
			byID[p.ID] = p
		}
	}

	seenEdges := make(map[string]struct{}, len(partitions))
	for _, child := range partitions {
		parentPath, childPath, ok := partitionServiceInheritanceEdge(child, byID)
		if !ok {
			continue
		}
		edgeKey := parentPath + "->" + childPath
		if _, exists := seenEdges[edgeKey]; exists {
			continue
		}
		seenEdges[edgeKey] = struct{}{}
		tuples = append(tuples, authz.BuildServicePartitionInheritanceTuple(parentPath, childPath))
	}
	return tuples
}

func partitionServiceInheritanceEdge(
	child *models.Partition,
	byID map[string]*models.Partition,
) (parentPath, childPath string, ok bool) {
	if child == nil || child.ID == "" {
		return "", "", false
	}
	parentID := strings.TrimSpace(child.ParentID)
	if parentID == "" {
		return "", "", false
	}

	parent, found := byID[parentID]
	if !found || parent == nil {
		parent = &models.Partition{}
		parent.ID = parentID
		if parentID == authz.RootPartitionID {
			parent.TenantID = authz.RootTenantID
		} else {
			parent.TenantID = child.TenantID
		}
	}

	parentTenant := strings.TrimSpace(parent.TenantID)
	if parentTenant == "" {
		parentTenant = strings.TrimSpace(child.TenantID)
	}
	childTenant := strings.TrimSpace(child.TenantID)
	if parentTenant == "" || childTenant == "" {
		return "", "", false
	}
	return fmt.Sprintf("%s/%s", parentTenant, parent.ID),
		fmt.Sprintf("%s/%s", childTenant, child.ID),
		true
}
