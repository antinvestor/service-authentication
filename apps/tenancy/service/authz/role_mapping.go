package authz

import "github.com/pitabwire/frame/security"

// RolePermissions maps each role to the tenancy-specific permissions it grants.
// This materialises the permission model defined in the OPL namespace config,
// since the Keto v1alpha2 gRPC API does not evaluate OPL permits.
//
// These permissions are scoped to the service_tenancy namespace only.
// Each downstream service manages its own functional permissions independently.
var RolePermissions = map[string][]string{ //nolint:gochecknoglobals // permission model registry
	RoleOwner: {
		PermissionManageTenant,
		PermissionViewTenant,
		PermissionManagePartition,
		PermissionViewPartition,
		PermissionManageAccess,
		PermissionViewAccess,
		PermissionManageRoles,
		PermissionManagePages,
		PermissionViewPages,
		PermissionGrantPermission,
	},
	RoleAdmin: {
		PermissionViewTenant,
		PermissionManagePartition,
		PermissionViewPartition,
		PermissionManageAccess,
		PermissionViewAccess,
		PermissionManageRoles,
		PermissionManagePages,
		PermissionViewPages,
		PermissionGrantPermission,
	},
	RoleMember: {
		PermissionViewTenant,
		PermissionViewPartition,
		PermissionViewPages,
	},
	RoleService: {
		PermissionManageTenant,
		PermissionViewTenant,
		PermissionManagePartition,
		PermissionViewPartition,
		PermissionManageAccess,
		PermissionViewAccess,
		PermissionManageRoles,
		PermissionManagePages,
		PermissionViewPages,
		PermissionGrantPermission,
	},
}

// BuildRoleTuples creates relation tuples in the service_tenancy namespace for
// a given role assignment. It writes both the role tuple and all the permission
// tuples that the role grants.
//
// Only service_tenancy permissions are written here. Each downstream service
// (commerce, payment, etc.) manages its own functional permissions independently.
func BuildRoleTuples(tenantID, profileID, role string) []security.RelationTuple {
	permissions := RolePermissions[role]
	tuples := make([]security.RelationTuple, 0, 1+len(permissions))

	// Write the role tuple
	tuples = append(tuples, security.RelationTuple{
		Object:   security.ObjectRef{Namespace: NamespaceTenancy, ID: tenantID},
		Relation: role,
		Subject:  security.SubjectRef{Namespace: NamespaceProfile, ID: profileID},
	})

	// Write all permission tuples granted by this role
	for _, perm := range permissions {
		tuples = append(tuples, security.RelationTuple{
			Object:   security.ObjectRef{Namespace: NamespaceTenancy, ID: tenantID},
			Relation: perm,
			Subject:  security.SubjectRef{Namespace: NamespaceProfile, ID: profileID},
		})
	}

	return tuples
}

// BuildPermissionTuple creates a single direct permission grant tuple.
func BuildPermissionTuple(namespace, tenantID, permission, profileID string) security.RelationTuple {
	return security.RelationTuple{
		Object:   security.ObjectRef{Namespace: namespace, ID: tenantID},
		Relation: permission,
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

// BuildServiceInheritanceTuples creates the subject set chain that gives service
// accounts automatic access to functional roles via Keto composition.
//
// The namespaces parameter controls which service namespaces get bridge tuples.
// Callers pass only the specific namespaces the service bot needs access to
// (e.g. the audiences requested during credential registration).
//
// For each namespace it writes:
//  1. Cross-namespace bridge: ns:path#service ← tenancy_access:path#service
//  2. Permission bridges: ns:path#perm ← ns:path#service (for every permission the service role grants)
//
// The resolution chain is: botID → tenancy_access:path#service → ns:path#service → ns:path#manage_tenant etc.
// These tuples are written once per partition path (not per bot). Each new service
// bot only needs a single tenancy_access:path#service tuple to get full access.
func BuildServiceInheritanceTuples(tenancyPath string, namespaces []string) []security.RelationTuple {
	servicePermissions := RolePermissions[RoleService]
	tuples := make([]security.RelationTuple, 0, len(namespaces)*(1+len(servicePermissions)))

	for _, ns := range namespaces {
		// Cross-namespace bridge: ns#service ← tenancy_access#service
		tuples = append(tuples, security.RelationTuple{
			Object:   security.ObjectRef{Namespace: ns, ID: tenancyPath},
			Relation: RoleService,
			Subject:  security.SubjectRef{Namespace: NamespaceTenancyAccess, ID: tenancyPath, Relation: RoleService},
		})

		// Permission bridges: ns#perm ← ns#service
		for _, perm := range servicePermissions {
			tuples = append(tuples, security.RelationTuple{
				Object:   security.ObjectRef{Namespace: ns, ID: tenancyPath},
				Relation: perm,
				Subject:  security.SubjectRef{Namespace: ns, ID: tenancyPath, Relation: RoleService},
			})
		}
	}
	return tuples
}
