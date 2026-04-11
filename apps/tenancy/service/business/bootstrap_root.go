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

	namespaces, err := resolveBootstrapNamespaces(ctx, deps.ServiceNamespaceRepo)
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

		allTuples = append(allTuples, buildRootTuples(rootPath, access.ProfileID, privileged, namespaces)...)
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

	if err := deps.Authorizer.WriteTuples(ctx, allTuples); err != nil {
		return fmt.Errorf("bootstrap: write %d root tuples: %w", len(allTuples), err)
	}

	logger.WithFields(map[string]any{
		"tuples":     len(allTuples),
		"accesses":   provisioned,
		"namespaces": len(namespaces),
	}).Info("root authorization bootstrap complete")
	return nil
}

// resolveBootstrapNamespaces returns the full set of namespaces that should
// receive root tuples. It unions CoreServiceNamespaces with every namespace
// already registered via the permissions manifest so the super-user keeps
// up with services that join the platform over time.
func resolveBootstrapNamespaces(ctx context.Context, repo repository.ServiceNamespaceRepository) ([]string, error) {
	seen := make(map[string]bool, len(authz.CoreServiceNamespaces))
	result := make([]string, 0, len(authz.CoreServiceNamespaces))

	add := func(ns string) {
		if ns == "" || seen[ns] {
			return
		}
		seen[ns] = true
		result = append(result, ns)
	}

	for _, ns := range authz.CoreServiceNamespaces {
		add(ns)
	}

	if repo == nil {
		return result, nil
	}

	registered, err := repo.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	for _, ns := range registered {
		add(ns.Namespace)
	}
	return result, nil
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
// explicit tenancy_access#<role> tuple per privileged role, plus matching
// #member + #<role> tuples in every bootstrap namespace so the user can
// directly manage them without going through any SubjectSet bridge.
func buildRootTuples(rootPath, profileID string, privilegedRoles, namespaces []string) []security.RelationTuple {
	tuples := make([]security.RelationTuple, 0, 3+len(privilegedRoles)+(1+len(privilegedRoles))*len(namespaces))

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

	for _, ns := range namespaces {
		obj := security.ObjectRef{Namespace: ns, ID: rootPath}
		tuples = append(tuples, security.RelationTuple{
			Object:   obj,
			Relation: authz.RoleMember,
			Subject:  subject,
		})
		for _, role := range privilegedRoles {
			tuples = append(tuples, security.RelationTuple{
				Object:   obj,
				Relation: role,
				Subject:  subject,
			})
		}
	}

	return tuples
}
