package authz

import "github.com/pitabwire/frame/security"

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
// The namespaces parameter controls which service namespaces get bridge tuples.
// Callers pass only the specific namespaces the service bot needs access to
// (e.g. the audiences requested during credential registration).
//
// For each namespace it writes a single cross-namespace bridge:
//
//	ns:path#service ← tenancy_access:path#service
//
// Permission resolution from service role to individual permissions is handled
// by Keto's OPL permits evaluation.
//
// The resolution chain is: botID → tenancy_access:path#service → ns:path#service → OPL permits
// These tuples are written once per partition path (not per bot). Each new service
// bot only needs a single tenancy_access:path#service tuple to get full access.
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
