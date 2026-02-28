package authz_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/stretchr/testify/assert"
)

func TestBuildRoleTuples_TenancyNamespaceOnly(t *testing.T) {
	role := authz.RoleAdmin
	tuples := authz.BuildRoleTuples("tenant1", "profile1", role)

	permissions := authz.RolePermissions[role]
	// 1 role tuple + N permission tuples, all in service_tenancy namespace
	expectedCount := 1 + len(permissions)
	assert.Len(t, tuples, expectedCount)

	// Verify all tuples are in the service_tenancy namespace
	for _, tuple := range tuples {
		assert.Equal(t, authz.NamespaceTenancy, tuple.Object.Namespace)
		assert.Equal(t, "tenant1", tuple.Object.ID)
		assert.Equal(t, authz.NamespaceProfile, tuple.Subject.Namespace)
		assert.Equal(t, "profile1", tuple.Subject.ID)
	}

	// First tuple is the role assignment
	assert.Equal(t, role, tuples[0].Relation)

	// Remaining tuples are the permissions granted by the role
	for i, perm := range permissions {
		assert.Equal(t, perm, tuples[i+1].Relation)
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
	// Only specific namespaces the bot needs, not all services
	namespaces := []string{"service_commerce", "service_payment"}
	tuples := authz.BuildServiceInheritanceTuples(tenancyPath, namespaces)

	servicePermissions := authz.RolePermissions[authz.RoleService]
	// Per namespace: 1 cross-namespace bridge + N permission bridges
	expectedCount := len(namespaces) * (1 + len(servicePermissions))
	assert.Len(t, tuples, expectedCount)

	// Group tuples by namespace for verification
	byNamespace := make(map[string][]string) // namespace -> list of relations
	for _, tuple := range tuples {
		assert.Equal(t, tenancyPath, tuple.Object.ID)
		byNamespace[tuple.Object.Namespace] = append(byNamespace[tuple.Object.Namespace], tuple.Relation)
	}

	for _, ns := range namespaces {
		relations := byNamespace[ns]
		// Must have the cross-namespace bridge (service role)
		assert.Contains(t, relations, authz.RoleService, "namespace %s missing service bridge", ns)

		// Must have all permission bridges
		for _, perm := range servicePermissions {
			assert.Contains(t, relations, perm, "namespace %s missing permission bridge %s", ns, perm)
		}
	}
}
