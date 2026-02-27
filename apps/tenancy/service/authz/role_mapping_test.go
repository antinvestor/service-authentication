package authz_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/stretchr/testify/assert"
)

func TestBuildRoleTuples_AllNamespaces(t *testing.T) {
	role := authz.RoleAdmin
	tuples := authz.BuildRoleTuples("tenant1", "profile1", role)

	permissions := authz.RolePermissions[role]
	expectedCount := len(authz.AllServiceNamespaces) * (1 + len(permissions))
	assert.Len(t, tuples, expectedCount)

	// Verify each namespace gets a role tuple and all permission tuples
	namespaceSeen := make(map[string][]string) // namespace -> list of relations
	for _, tuple := range tuples {
		assert.Equal(t, "tenant1", tuple.Object.ID)
		assert.Equal(t, authz.NamespaceProfile, tuple.Subject.Namespace)
		assert.Equal(t, "profile1", tuple.Subject.ID)
		namespaceSeen[tuple.Object.Namespace] = append(namespaceSeen[tuple.Object.Namespace], tuple.Relation)
	}

	for _, ns := range authz.AllServiceNamespaces {
		relations := namespaceSeen[ns]
		assert.Contains(t, relations, role, "namespace %s missing role tuple", ns)
		for _, perm := range permissions {
			assert.Contains(t, relations, perm, "namespace %s missing permission %s", ns, perm)
		}
	}
}

func TestBuildPermissionTuple(t *testing.T) {
	tuple := authz.BuildPermissionTuple("service_payment", "tenant1", "send_payment", "profile1")

	assert.Equal(t, "service_payment", tuple.Object.Namespace)
	assert.Equal(t, "tenant1", tuple.Object.ID)
	assert.Equal(t, "send_payment", tuple.Relation)
	assert.Equal(t, authz.NamespaceProfile, tuple.Subject.Namespace)
	assert.Equal(t, "profile1", tuple.Subject.ID)
}

func TestBuildPartitionInheritanceTuple(t *testing.T) {
	parentPath := "tenant1/parent-partition"
	childPath := "tenant1/child-partition"

	tuple := authz.BuildPartitionInheritanceTuple(parentPath, childPath)

	// Object is the child partition in tenancy_access namespace
	assert.Equal(t, authz.NamespaceTenancyAccess, tuple.Object.Namespace)
	assert.Equal(t, childPath, tuple.Object.ID)

	// Relation is member
	assert.Equal(t, authz.RoleMember, tuple.Relation)

	// Subject is a subject set referencing parent partition's members
	assert.Equal(t, authz.NamespaceTenancyAccess, tuple.Subject.Namespace)
	assert.Equal(t, parentPath, tuple.Subject.ID)
	assert.Equal(t, authz.RoleMember, tuple.Subject.Relation)
}

func TestBuildServiceAccessTuple(t *testing.T) {
	tuple := authz.BuildServiceAccessTuple("tenant1/partition1", "bot1")

	assert.Equal(t, authz.NamespaceTenancyAccess, tuple.Object.Namespace)
	assert.Equal(t, "tenant1/partition1", tuple.Object.ID)
	assert.Equal(t, authz.RoleService, tuple.Relation)
	assert.Equal(t, authz.NamespaceProfile, tuple.Subject.Namespace)
	assert.Equal(t, "bot1", tuple.Subject.ID)
	assert.Empty(t, tuple.Subject.Relation)
}

func TestBuildServiceInheritanceTuples(t *testing.T) {
	tenancyPath := "tenant1/partition1"
	tuples := authz.BuildServiceInheritanceTuples(tenancyPath, authz.AllServiceNamespaces)

	servicePermissions := authz.RolePermissions[authz.RoleService]
	// Per namespace: 1 cross-namespace bridge + N permission bridges
	expectedCount := len(authz.AllServiceNamespaces) * (1 + len(servicePermissions))
	assert.Len(t, tuples, expectedCount)

	// Group tuples by namespace for verification
	byNamespace := make(map[string][]string) // namespace -> list of relations
	for _, tuple := range tuples {
		assert.Equal(t, tenancyPath, tuple.Object.ID)
		byNamespace[tuple.Object.Namespace] = append(byNamespace[tuple.Object.Namespace], tuple.Relation)
	}

	for _, ns := range authz.AllServiceNamespaces {
		relations := byNamespace[ns]
		// Must have the cross-namespace bridge (service role)
		assert.Contains(t, relations, authz.RoleService, "namespace %s missing service bridge", ns)

		// Must have all permission bridges
		for _, perm := range servicePermissions {
			assert.Contains(t, relations, perm, "namespace %s missing permission bridge %s", ns, perm)
		}
	}
}
