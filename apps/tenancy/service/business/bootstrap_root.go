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

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

// RootAuthorizationDeps bundles everything EnsureRootAuthorization needs.
type RootAuthorizationDeps struct {
	AccessRepo           repository.AccessRepository
	AccessRoleRepo       repository.AccessRoleRepository
	PartitionRoleRepo    repository.PartitionRoleRepository
	ServiceNamespaceRepo repository.ServiceNamespaceRepository
	Authorizer           security.Authorizer
}

// EnsureRootAuthorization synchronously provisions the Keto tuples that make
// root-partition owners/admins fully functional super-users. It runs once at
// service start, blocks until every write succeeds, and returns an error if
// any step fails so the service never comes up half-provisioned.
//
// For every access record on the root partition that has an owner or admin
// role it writes, without any self-healing or retries:
//
//	tenancy_access:root/root#member   ← profile_user:<id>
//	tenancy_access:root/root#<role>   ← profile_user:<id>
//	tenancy_access:root/root#service  ← profile_user:<id>
//	<ns>:root/root#member             ← profile_user:<id>   for every registered ns
//	<ns>:root/root#<role>             ← profile_user:<id>   for every registered ns
//
// The #service tuple on tenancy_access is what Frame's TenancyAccessChecker
// looks up when a JWT carries the "internal" role, so this is what unblocks
// root owners/admins from the "cannot service on tenancy_access" denial.
//
// The per-namespace role tuples guarantee the root super-user can grant
// permissions in every registered service — tenancy, audit, profile, device,
// setting, and anything else registered via the permissions manifest — even
// if they have never touched those services directly.
//
// Idempotent: Keto tuple writes are set semantics, so re-running on every
// boot is safe and cheap.
func EnsureRootAuthorization(ctx context.Context, deps RootAuthorizationDeps) error {
	logger := util.Log(ctx).WithField("component", "root_authz_bootstrap")

	ctx = security.SkipTenancyChecksOnClaims(ctx)

	accesses, err := deps.AccessRepo.ListByPartition(ctx, authz.RootPartitionID)
	if err != nil {
		return fmt.Errorf("bootstrap: list root access records: %w", err)
	}
	if len(accesses) == 0 {
		logger.Warn("no access records found on root partition — bootstrap skipped")
		return nil
	}

	nsRecords, err := resolveBootstrapNamespaces(ctx, deps.ServiceNamespaceRepo)
	if err != nil {
		return fmt.Errorf("bootstrap: resolve namespaces: %w", err)
	}

	var allTuples []security.RelationTuple
	rootPath := fmt.Sprintf("%s/%s", authz.RootTenantID, authz.RootPartitionID)

	provisioned := 0
	for _, access := range accesses {
		roles, roleErr := resolveAccessRoleNames(ctx, deps, access.GetID())
		if roleErr != nil {
			return fmt.Errorf("bootstrap: resolve roles for access %s: %w", access.GetID(), roleErr)
		}

		privileged := filterPrivilegedRoles(roles)
		if len(privileged) == 0 {
			continue
		}

		allTuples = append(allTuples, buildRootTuples(rootPath, access.ProfileID, privileged, nsRecords)...)
		provisioned++

		logger.WithFields(map[string]any{
			"access_id":  access.GetID(),
			"profile_id": access.ProfileID,
			"roles":      privileged,
		}).Info("provisioning root super-user tuples")
	}

	if len(allTuples) == 0 {
		logger.Warn("no root partition owner/admin access records found — bootstrap skipped")
		return nil
	}

	// Group tuples by namespace so that a namespace missing from Keto's OPL
	// doesn't fail the entire batch. This is expected during initial cluster
	// setup where OPL configs deploy asynchronously.
	grouped := groupTuplesByNamespace(allTuples)
	var written, skipped int
	for ns, tuples := range grouped {
		if writeErr := deps.Authorizer.WriteTuples(ctx, tuples); writeErr != nil {
			skipped += len(tuples)
			logger.WithFields(map[string]any{
				"namespace": ns,
				"tuples":    len(tuples),
			}).WithError(writeErr).Warn("skipping namespace — not yet configured in Keto")
			continue
		}
		written += len(tuples)
	}

	if written == 0 {
		return fmt.Errorf("bootstrap: wrote 0 of %d root tuples — no namespaces available in Keto", len(allTuples))
	}

	logger.WithFields(map[string]any{
		"written":    written,
		"skipped":    skipped,
		"accesses":   provisioned,
		"namespaces": len(nsRecords),
	}).Info("root authorization bootstrap complete")
	return nil
}

// resolveBootstrapNamespaces returns the full set of namespace records that
// should receive root tuples. It loads all registered namespaces from the DB
// so that each record's RoleBindings can be used to determine which relations
// the namespace actually supports.
func resolveBootstrapNamespaces(ctx context.Context, repo repository.ServiceNamespaceRepository) ([]*models.ServiceNamespace, error) {
	if repo == nil {
		return nil, nil
	}

	registered, err := repo.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	return registered, nil
}

// resolveAccessRoleNames returns the distinct role names attached to an
// access record.
func resolveAccessRoleNames(ctx context.Context, deps RootAuthorizationDeps, accessID string) ([]string, error) {
	accessRoles, err := deps.AccessRoleRepo.GetByAccessID(ctx, accessID)
	if err != nil {
		return nil, err
	}
	if len(accessRoles) == 0 {
		return nil, nil
	}

	ids := make([]string, 0, len(accessRoles))
	for _, ar := range accessRoles {
		ids = append(ids, ar.PartitionRoleID)
	}
	roles, err := deps.PartitionRoleRepo.GetRolesByID(ctx, ids...)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(roles))
	names := make([]string, 0, len(roles))
	for _, r := range roles {
		if seen[r.Name] {
			continue
		}
		seen[r.Name] = true
		names = append(names, r.Name)
	}
	return names, nil
}

// filterPrivilegedRoles returns only the role names that qualify a user as a
// root super-user: owner and admin. Member and anything else is filtered out
// because those don't warrant the cross-namespace blanket grants.
func filterPrivilegedRoles(roles []string) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if r == authz.RoleOwner || r == authz.RoleAdmin {
			out = append(out, r)
		}
	}
	return out
}

// buildRootTuples produces the full tuple set for a single root super-user.
//
// It always writes the base tenancy_access#member + tenancy_access#service
// tuples (service is what satisfies Frame's internal-system check), plus an
// explicit tenancy_access#<role> tuple per privileged role.
//
// For each registered namespace, it only writes tuples for relations that
// the namespace's RoleBindings declares. This avoids writing tuples for
// relations that don't exist in the OPL (which Keto rejects with NotFound).
func buildRootTuples(rootPath, profileID string, privilegedRoles []string, nsRecords []*models.ServiceNamespace) []security.RelationTuple {
	tuples := make([]security.RelationTuple, 0, 3+len(privilegedRoles)+2*len(nsRecords))

	subject := security.SubjectRef{Namespace: authz.NamespaceProfile, ID: profileID}
	tenancyAccess := security.ObjectRef{Namespace: authz.NamespaceTenancyAccess, ID: rootPath}

	tuples = append(tuples,
		security.RelationTuple{Object: tenancyAccess, Relation: authz.RoleMember, Subject: subject},
		security.RelationTuple{Object: tenancyAccess, Relation: authz.RoleService, Subject: subject},
	)
	for _, role := range privilegedRoles {
		tuples = append(tuples, security.RelationTuple{
			Object:   tenancyAccess,
			Relation: role,
			Subject:  subject,
		})
	}

	for _, nsRec := range nsRecords {
		obj := security.ObjectRef{Namespace: nsRec.Namespace, ID: rootPath}
		supportedRoles := extractRoleBindingKeys(nsRec.RoleBindings)

		if hasRole(supportedRoles, authz.RoleMember) {
			tuples = append(tuples, security.RelationTuple{
				Object:   obj,
				Relation: authz.RoleMember,
				Subject:  subject,
			})
		}
		for _, role := range privilegedRoles {
			if hasRole(supportedRoles, role) {
				tuples = append(tuples, security.RelationTuple{
					Object:   obj,
					Relation: role,
					Subject:  subject,
				})
			}
		}
	}

	return tuples
}

// extractRoleBindingKeys returns the role names declared in a namespace's
// RoleBindings JSONMap. These correspond to the relations that actually
// exist in the namespace's OPL class definition.
func extractRoleBindingKeys(roleBindings map[string]any) []string {
	if len(roleBindings) == 0 {
		return nil
	}
	keys := make([]string, 0, len(roleBindings))
	for k := range roleBindings {
		keys = append(keys, k)
	}
	return keys
}

// groupTuplesByNamespace partitions tuples by their Object.Namespace so each
// namespace can be written independently.
func groupTuplesByNamespace(tuples []security.RelationTuple) map[string][]security.RelationTuple {
	grouped := make(map[string][]security.RelationTuple)
	for _, t := range tuples {
		ns := t.Object.Namespace
		grouped[ns] = append(grouped[ns], t)
	}
	return grouped
}

func hasRole(roles []string, target string) bool {
	for _, r := range roles {
		if r == target {
			return true
		}
	}
	return false
}
