package authz_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/stretchr/testify/assert"
)

func TestBuildRoleTuples_AllNamespaces(t *testing.T) {
	tuples := authz.BuildRoleTuples("tenant1", "profile1", "admin")

	assert.Len(t, tuples, len(authz.AllServiceNamespaces))

	// Verify each namespace gets a tuple
	namespaces := make(map[string]bool)
	for _, tuple := range tuples {
		namespaces[tuple.Object.Namespace] = true
		assert.Equal(t, "tenant1", tuple.Object.ID)
		assert.Equal(t, "admin", tuple.Relation)
		assert.Equal(t, authz.NamespaceProfile, tuple.Subject.Namespace)
		assert.Equal(t, "profile1", tuple.Subject.ID)
	}

	for _, ns := range authz.AllServiceNamespaces {
		assert.True(t, namespaces[ns], "missing namespace: %s", ns)
	}
}

func TestBuildPermissionTuple(t *testing.T) {
	tuple := authz.BuildPermissionTuple("payment_tenant", "tenant1", "send_payment", "profile1")

	assert.Equal(t, "payment_tenant", tuple.Object.Namespace)
	assert.Equal(t, "tenant1", tuple.Object.ID)
	assert.Equal(t, "send_payment", tuple.Relation)
	assert.Equal(t, authz.NamespaceProfile, tuple.Subject.Namespace)
	assert.Equal(t, "profile1", tuple.Subject.ID)
}
