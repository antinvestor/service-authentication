package authz

import (
	"slices"

	"github.com/pitabwire/frame/security"
)

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
	},
}

// BuildRoleTuples creates a role relation tuple in the service_tenancy namespace.
// Only the role tuple is written; Keto evaluates OPL permits to resolve the
// individual permissions granted by the role.
//
// The tenancyPath should be "tenantID/partitionID" to match the object ID
// format used by FunctionChecker.Check().
func BuildRoleTuples(tenancyPath, profileID, role string) []security.RelationTuple {
	return []security.RelationTuple{
		{
			Object:   security.ObjectRef{Namespace: NamespaceTenancy, ID: tenancyPath},
			Relation: role,
			Subject:  security.SubjectRef{Namespace: NamespaceProfile, ID: profileID},
		},
	}
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
// marking a profile as a service account for the given tenancy path.
// Service accounts with this tuple get full functional roles via subject set
// bridge tuples that link tenancy_access#service to each service namespace.
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

// BuildServiceInheritanceTuples creates the subject set chain that gives service
// accounts automatic access to functional roles via Keto composition.
// Bridge tuples (ns#service ← tenancy_access#service) are written for namespaces
// derived from SA audiences — no hardcoded namespace lists.
func BuildServiceInheritanceTuples(tenancyPath string, namespaces []string) []security.RelationTuple {
	tuples := make([]security.RelationTuple, 0, len(namespaces))

	for _, ns := range namespaces {
		// Cross-namespace bridge: ns#service ← tenancy_access#service
		tuples = append(tuples, security.RelationTuple{
			Object:   security.ObjectRef{Namespace: ns, ID: tenancyPath},
			Relation: RoleService,
			Subject:  security.SubjectRef{Namespace: NamespaceTenancyAccess, ID: tenancyPath, Relation: RoleService},
		})
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

// AllServicePermissions returns the full list of permissions granted to the
// "service" role in the service_tenancy namespace. Useful for tests and for
// building explicit permission tuples when writing Keto tuples directly.
func AllServicePermissions() []string {
	return RolePermissions[RoleService]
}

// PermissionFullAccess is the wildcard marker for full service-level access.
// When a namespace's permission list contains only "*", the SA gets a bridge
// tuple (ns#service ← tenancy_access#service) instead of explicit granted_*
// tuples. This is more readable than an empty array.
const PermissionFullAccess = "*"

// IsFullAccess returns true if the permission list contains the wildcard "*",
// meaning full service-level access via bridge tuples.
// An empty list means no permissions are granted — it does NOT imply full access.
func IsFullAccess(perms []string) bool {
	return len(perms) == 1 && perms[0] == PermissionFullAccess
}

// ParseAudiencePermissions extracts per-namespace permission grants from an
// Audiences JSONMap.
//
// Format: {"service_profile": ["profile_view"], "service_device": ["*"], ...}
//
// Each key is a Keto OPL namespace. The value is a list of permissions:
//   - ["*"]                  → full service access via bridge tuple
//   - ["perm1", "perm2"]    → only these granted_* permissions (least-privilege)
//   - []                    → namespace is recorded but no permissions are granted
//
// Returns a map of namespace → permission list.
func ParseAudiencePermissions(audiences map[string]any) map[string][]string {
	result := make(map[string][]string)

	for ns, raw := range audiences {
		var perms []string
		switch typed := raw.(type) {
		case []any:
			for _, v := range typed {
				if s, ok := v.(string); ok {
					perms = append(perms, s)
				}
			}
		case []string:
			perms = typed
		}
		result[ns] = perms
	}

	return result
}

// AudienceNamespaces extracts the sorted list of namespace names from an audiences map.
func AudienceNamespaces(audiences map[string]any) []string {
	if len(audiences) == 0 {
		return nil
	}
	namespaces := make([]string, 0, len(audiences))
	for ns := range audiences {
		namespaces = append(namespaces, ns)
	}
	slices.Sort(namespaces)
	return namespaces
}
