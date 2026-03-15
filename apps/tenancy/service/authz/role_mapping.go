package authz

import (
	"slices"
	"strings"

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
//
// Deprecated: Use BuildServicePermissionTuples for explicit per-permission grants.
// This function is retained for backward compatibility with partition sync and
// legacy service accounts that use the old {"namespaces": [...]} format.
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
// "service" role. Used as a fallback when a service account's audience entry
// specifies a namespace without explicit permissions (legacy format).
func AllServicePermissions() []string {
	return RolePermissions[RoleService]
}

// ParseAudiencePermissions extracts per-namespace permission grants from an
// Audiences JSONMap. It supports two formats:
//
// New (explicit): {"service_profile": ["tenant_view", "partition_view"], ...}
// Legacy:         {"namespaces": ["service_profile", ...]}
//
// For the legacy format, each namespace receives all RoleService permissions.
// Returns a map of namespace → permission list.
func ParseAudiencePermissions(audiences map[string]any) map[string][]string {
	result := make(map[string][]string)

	// Check for legacy format: {"namespaces": [...]} or {"namespaces": "ns1,ns2"}
	if raw, ok := audiences["namespaces"]; ok {
		var nsList []string
		switch typed := raw.(type) {
		case []any:
			for _, v := range typed {
				if s, ok := v.(string); ok {
					nsList = append(nsList, s)
				}
			}
		case []string:
			nsList = typed
		case string:
			if strings.Contains(typed, ",") {
				nsList = strings.Split(typed, ",")
			} else if typed != "" {
				nsList = []string{typed}
			}
		}
		for _, ns := range nsList {
			result[ns] = AllServicePermissions()
		}
		return result
	}

	// New format: {"namespace": ["perm1", "perm2"], ...}
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
		if len(perms) > 0 {
			result[ns] = perms
		}
	}

	return result
}

// AudienceNamespaces extracts the list of namespace names from an audiences map,
// supporting both legacy and new formats.
func AudienceNamespaces(audiences map[string]any) []string {
	parsed := ParseAudiencePermissions(audiences)
	if len(parsed) == 0 {
		return nil
	}
	namespaces := make([]string, 0, len(parsed))
	for ns := range parsed {
		namespaces = append(namespaces, ns)
	}
	slices.Sort(namespaces)
	return namespaces
}
