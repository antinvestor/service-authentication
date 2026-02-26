package authz

import "github.com/pitabwire/frame/security"

// AllServiceNamespaces lists all tenant-scoped namespaces across services.
// When a role is assigned in tenancy, tuples are written to each of these namespaces.
var AllServiceNamespaces = []string{ //nolint:gochecknoglobals // cross-service namespace registry
	NamespaceTenant,
	"payment_tenant",
	"ledger_tenant",
	"commerce_tenant",
	"trustage_tenant",
	"notification_tenant",
	"profile_tenant",
}

// BuildRoleTuples creates relation tuples for all service namespaces for a given role assignment.
func BuildRoleTuples(tenantID, profileID, role string) []security.RelationTuple {
	tuples := make([]security.RelationTuple, 0, len(AllServiceNamespaces))
	for _, ns := range AllServiceNamespaces {
		tuples = append(tuples, security.RelationTuple{
			Object:   security.ObjectRef{Namespace: ns, ID: tenantID},
			Relation: role,
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
