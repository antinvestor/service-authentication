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

package authz

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/security"
)

// SortRelationTuples gives reconciliation and audit output a stable order.
func SortRelationTuples(tuples []security.RelationTuple) {
	slices.SortFunc(tuples, func(left, right security.RelationTuple) int {
		for _, comparison := range [][2]string{
			{left.Object.Namespace, right.Object.Namespace},
			{left.Object.ID, right.Object.ID},
			{left.Relation, right.Relation},
			{left.Subject.Namespace, right.Subject.Namespace},
			{left.Subject.ID, right.Subject.ID},
			{left.Subject.Relation, right.Subject.Relation},
		} {
			if result := cmp.Compare(comparison[0], comparison[1]); result != 0 {
				return result
			}
		}
		return 0
	})
}

// ResolveServiceGrants validates and expands service-account grants against the
// namespace manifests used to generate Keto's OPL. It returns only relations
// that are guaranteed to exist in the currently registered schema.
//
// A wildcard is accepted only as authoring shorthand and is materialised into
// the explicit permissions bound to the service role. No service-role bridge
// tuple is written to Keto.
func ResolveServiceGrants(
	requested map[string][]string,
	namespaces []*models.ServiceNamespace,
) (map[string][]string, error) {
	registry := make(map[string]*models.ServiceNamespace, len(namespaces))
	for _, namespace := range namespaces {
		registry[namespace.Namespace] = namespace
	}

	resolved := make(map[string][]string, len(requested))
	for namespace, permissions := range requested {
		manifest, ok := registry[namespace]
		if !ok {
			return nil, fmt.Errorf("authorization namespace %q is not registered", namespace)
		}

		available := jsonMapStringValues(manifest.Permissions, "values")
		if IsFullAccess(permissions) {
			permissions = jsonMapStringValues(manifest.RoleBindings, RoleService)
			if len(permissions) == 0 {
				return nil, fmt.Errorf("authorization namespace %q has no %q role binding", namespace, RoleService)
			}
		}
		if len(permissions) == 0 {
			return nil, fmt.Errorf("authorization namespace %q has no requested permissions", namespace)
		}

		permissions = slices.Clone(permissions)
		slices.Sort(permissions)
		permissions = slices.Compact(permissions)
		for _, permission := range permissions {
			if permission == PermissionFullAccess || !slices.Contains(available, permission) {
				return nil, fmt.Errorf(
					"authorization permission %q is not registered in namespace %q",
					permission,
					namespace,
				)
			}
		}
		resolved[namespace] = permissions
	}

	return resolved, nil
}

// SelectDeployedNamespaceRecords excludes runtime observations that are not in
// the compiled GitOps schema shipped with the service.
func SelectDeployedNamespaceRecords(
	observed []*models.ServiceNamespace,
) []*models.ServiceNamespace {
	deployed := make(map[string]struct{}, len(deployedServicePermissions))
	for namespace := range deployedServicePermissions {
		deployed[namespace] = struct{}{}
	}
	selected := make([]*models.ServiceNamespace, 0, len(observed))
	for _, namespace := range observed {
		if _, ok := deployed[namespace.Namespace]; ok {
			selected = append(selected, namespace)
		}
	}
	return selected
}

func jsonMapStringValues(values map[string]any, key string) []string {
	raw, ok := values[key]
	if !ok {
		return nil
	}
	switch typed := raw.(type) {
	case []string:
		return slices.Clone(typed)
	case []any:
		result := make([]string, 0, len(typed))
		for _, value := range typed {
			if stringValue, ok := value.(string); ok {
				result = append(result, stringValue)
			}
		}
		return result
	default:
		return nil
	}
}

// RolePermissions documents the permission model defined in the OPL namespace config.
// Keto's Check API evaluates OPL permits, so only role tuples need to be written;
// permission resolution happens automatically through the OPL model.
//
// These permissions are scoped to the service_tenancy namespace only.
// Each downstream service manages its own functional permissions independently.
var RolePermissions = map[string][]string{ //nolint:gochecknoglobals // permission model registry
	RoleOwner: {
		PermissionTenantManage,
		PermissionTenantView,
		PermissionPartitionManage,
		PermissionPartitionView,
		PermissionAccessManage,
		PermissionAccessView,
		PermissionRolesManage,
		PermissionPagesManage,
		PermissionPagesView,
		PermissionPermissionGrant,
		PermissionServiceAccountView,
		PermissionServiceAccountManage,
		PermissionClientView,
		PermissionClientManage,
	},
	RoleAdmin: {
		PermissionTenantView,
		PermissionPartitionManage,
		PermissionPartitionView,
		PermissionAccessManage,
		PermissionAccessView,
		PermissionRolesManage,
		PermissionPagesManage,
		PermissionPagesView,
		PermissionPermissionGrant,
		PermissionServiceAccountView,
		PermissionClientView,
	},
	RoleMember: {
		PermissionTenantView,
		PermissionPartitionView,
		PermissionPagesView,
	},
	RoleService: {
		PermissionTenantManage,
		PermissionTenantView,
		PermissionPartitionManage,
		PermissionPartitionView,
		PermissionAccessManage,
		PermissionAccessView,
		PermissionRolesManage,
		PermissionPagesManage,
		PermissionPagesView,
		PermissionPermissionGrant,
		PermissionServiceAccountView,
		PermissionServiceAccountManage,
		PermissionClientView,
		PermissionClientManage,
	},
}

// RegisteredNamespaceNames extracts the namespace name strings from a list of
// ServiceNamespace records. If the list is empty, it falls back to
// CoreServiceNamespaces so that callers without DB access still get the
// minimum set of namespaces.
func RegisteredNamespaceNames(namespaces []*models.ServiceNamespace) []string {
	if len(namespaces) == 0 {
		return CoreServiceNamespaces
	}
	result := make([]string, 0, len(namespaces))
	for _, ns := range namespaces {
		result = append(result, ns.Namespace)
	}
	return result
}

// NamespaceSupportsRole reports whether a ServiceNamespace's RoleBindings
// declares the given role. Namespaces whose OPL class lacks a relation
// for the role must be skipped to avoid Keto NotFound errors.
func NamespaceSupportsRole(ns *models.ServiceNamespace, role string) bool {
	if len(ns.RoleBindings) == 0 {
		return false
	}
	_, ok := ns.RoleBindings[role]
	return ok
}

// FilterNamespacesForRole returns only the namespace names that support the
// given role according to their RoleBindings. This prevents writing tuples
// for relations that don't exist in the namespace's OPL class.
func FilterNamespacesForRole(namespaces []*models.ServiceNamespace, role string) []string {
	result := make([]string, 0, len(namespaces))
	for _, ns := range namespaces {
		if NamespaceSupportsRole(ns, role) {
			result = append(result, ns.Namespace)
		}
	}
	return result
}

// BuildRoleTuples creates role relation tuples for a user on a partition.
//
// Only writes tuples to namespaces whose RoleBindings include the given role,
// preventing Keto NotFound errors for namespaces that lack that relation in
// their OPL class. The tenancy_access tuple is always written since it
// supports all standard roles.
//
// The tenancyPath should be "tenantID/partitionID" to match the object ID
// format used by FunctionChecker.Check().
func BuildRoleTuples(tenancyPath, profileID, role string, namespaces []*models.ServiceNamespace) []security.RelationTuple {
	supported := FilterNamespacesForRole(namespaces, role)
	tuples := make([]security.RelationTuple, 0, len(supported)+1)

	for _, ns := range supported {
		tuples = append(tuples, security.RelationTuple{
			Object:   security.ObjectRef{Namespace: ns, ID: tenancyPath},
			Relation: role,
			Subject:  security.SubjectRef{Namespace: NamespaceProfile, ID: profileID},
		})
	}

	// tenancy_access is always written for data-access role propagation.
	tuples = append(tuples, security.RelationTuple{
		Object:   security.ObjectRef{Namespace: NamespaceTenancyAccess, ID: tenancyPath},
		Relation: role,
		Subject:  security.SubjectRef{Namespace: NamespaceProfile, ID: profileID},
	})

	return tuples
}

// GrantedRelation returns the OPL relation name for a direct permission grant.
// OPL relations are prefixed with "granted_" to avoid name conflicts with
// the permits functions (Keto skips permit evaluation when a relation with
// the same name exists).
func GrantedRelation(permission string) string {
	return "granted_" + permission
}

// BuildPermissionTuple creates a single direct permission grant tuple.
// The relation is automatically prefixed with "granted_" to match the OPL schema.
func BuildPermissionTuple(namespace, tenantID, permission, profileID string) security.RelationTuple {
	return security.RelationTuple{
		Object:   security.ObjectRef{Namespace: namespace, ID: tenantID},
		Relation: GrantedRelation(permission),
		Subject:  security.SubjectRef{Namespace: NamespaceProfile, ID: profileID},
	}
}

// BuildAccessTuple creates a member relation tuple in the tenancy_access namespace,
// recording that a profile has access to a tenant/partition combination.
func BuildAccessTuple(tenancyPath, profileID string) security.RelationTuple {
	return security.RelationTuple{
		Object:   security.ObjectRef{Namespace: NamespaceTenancyAccess, ID: tenancyPath},
		Relation: RoleMember,
		Subject:  security.SubjectRef{Namespace: NamespaceProfile, ID: profileID},
	}
}

// BuildPartitionInheritanceTuple creates a subject set tuple that grants all members
// of a parent partition automatic membership in a child partition.
// This enables Plane 1 (data access) inheritance: anyone with access to the parent
// partition also gets access to the child partition, resolved transitively by Keto.
func BuildPartitionInheritanceTuple(parentTenancyPath, childTenancyPath string) security.RelationTuple {
	return security.RelationTuple{
		Object:   security.ObjectRef{Namespace: NamespaceTenancyAccess, ID: childTenancyPath},
		Relation: RoleMember,
		Subject:  security.SubjectRef{Namespace: NamespaceTenancyAccess, ID: parentTenancyPath, Relation: RoleMember},
	}
}

// BuildServiceAccessTuple creates a service relation tuple in tenancy_access,
// marking a profile as a service account for data-access inheritance only.
// Functional access is always represented by explicit granted_* tuples.
func BuildServiceAccessTuple(tenancyPath, profileID string) security.RelationTuple {
	return security.RelationTuple{
		Object:   security.ObjectRef{Namespace: NamespaceTenancyAccess, ID: tenancyPath},
		Relation: RoleService,
		Subject:  security.SubjectRef{Namespace: NamespaceProfile, ID: profileID},
	}
}

// BuildServicePartitionInheritanceTuple creates a subject set tuple that grants all
// service accounts of a parent partition automatic service access to a child partition.
// This enables transitive service bot access: a bot registered on the parent partition
// can also access child partitions, resolved by Keto through the subject set chain.
func BuildServicePartitionInheritanceTuple(parentTenancyPath, childTenancyPath string) security.RelationTuple {
	return security.RelationTuple{
		Object:   security.ObjectRef{Namespace: NamespaceTenancyAccess, ID: childTenancyPath},
		Relation: RoleService,
		Subject:  security.SubjectRef{Namespace: NamespaceTenancyAccess, ID: parentTenancyPath, Relation: RoleService},
	}
}

// StandardRoles lists the human-assignable roles that OPL recognises.
// When a partition is synced, bridge tuples are written for each of these
// roles so that a role assigned in tenancy_access propagates to every
// service namespace. Custom partition roles work the same way as long as
// they are declared in the OPL for the relevant service namespaces.
var StandardRoles = []string{RoleOwner, RoleAdmin, RoleMember} //nolint:gochecknoglobals // role registry

// BuildRoleInheritanceTuples creates bridge tuples that propagate human roles
// from tenancy_access to each service namespace.
//
// For every (namespace, role) pair it writes:
//
//	ns:tenancyPath#role ← tenancy_access:tenancyPath#role
//
// This lets Keto resolve: "user is owner in tenancy_access for this partition"
// → "user is owner in service_profile for this partition" → OPL grants permissions.
func BuildRoleInheritanceTuples(tenancyPath string, namespaces []string, roles []string) []security.RelationTuple {
	tuples := make([]security.RelationTuple, 0, len(namespaces)*len(roles))

	for _, ns := range namespaces {
		for _, role := range roles {
			tuples = append(tuples, security.RelationTuple{
				Object:   security.ObjectRef{Namespace: ns, ID: tenancyPath},
				Relation: role,
				Subject:  security.SubjectRef{Namespace: NamespaceTenancyAccess, ID: tenancyPath, Relation: role},
			})
		}
	}
	return tuples
}

// BuildServicePermissionTuples creates explicit per-permission grant tuples for
// a service account in a specific namespace. Instead of granting blanket "service"
// access, each permission is individually materialised as a granted_ relation.
//
// This is the preferred approach for service account authorization — each SA
// declares exactly which permissions it needs per namespace, following the
// principle of least privilege.
//
// Example: BuildServicePermissionTuples("t/p", "bot1", "service_profile", ["tenant_view", "partition_view"])
// writes:
//
//	service_profile:t/p#granted_tenant_view ← profile_user:bot1
//	service_profile:t/p#granted_partition_view ← profile_user:bot1
func BuildServicePermissionTuples(tenancyPath, profileID, namespace string, permissions []string) []security.RelationTuple {
	tuples := make([]security.RelationTuple, 0, len(permissions))
	for _, perm := range permissions {
		tuples = append(tuples, BuildPermissionTuple(namespace, tenancyPath, perm, profileID))
	}
	return tuples
}

// PermissionFullAccess is the wildcard marker for full service-level access.
// It is expanded to explicit grants from the registered service role before
// any tuple is written.
const PermissionFullAccess = "*"

// IsFullAccess returns true if the permission list contains the wildcard "*".
// An empty list means no permissions are granted — it does NOT imply full access.
func IsFullAccess(perms []string) bool {
	return len(perms) == 1 && perms[0] == PermissionFullAccess
}
