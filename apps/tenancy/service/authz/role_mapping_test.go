package authz_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type RoleMappingTestSuite struct {
	suite.Suite
}

func TestRoleMappingTestSuite(t *testing.T) {
	suite.Run(t, new(RoleMappingTestSuite))
}

func (suite *RoleMappingTestSuite) TestBuildRoleTuples_TenancyNamespaceOnly() {
	t := suite.T()
	role := authz.RoleAdmin
	tuples := authz.BuildRoleTuples("tenant1/partition1", "profile1", role)

	// Only 1 role tuple — OPL permits handle permission resolution
	assert.Len(t, tuples, 1)

	assert.Equal(t, authz.NamespaceTenancy, tuples[0].Object.Namespace)
	assert.Equal(t, "tenant1/partition1", tuples[0].Object.ID)
	assert.Equal(t, role, tuples[0].Relation)
	assert.Equal(t, authz.NamespaceProfile, tuples[0].Subject.Namespace)
	assert.Equal(t, "profile1", tuples[0].Subject.ID)
}

func (suite *RoleMappingTestSuite) TestBuildPermissionTuple() {
	t := suite.T()
	tuple := authz.BuildPermissionTuple("service_payment", "tenant1", "send_payment", "profile1")

	assert.Equal(t, "service_payment", tuple.Object.Namespace)
	assert.Equal(t, "tenant1", tuple.Object.ID)
	assert.Equal(t, "granted_send_payment", tuple.Relation)
	assert.Equal(t, authz.NamespaceProfile, tuple.Subject.Namespace)
	assert.Equal(t, "profile1", tuple.Subject.ID)
}

func (suite *RoleMappingTestSuite) TestBuildPartitionInheritanceTuple() {
	t := suite.T()
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

func (suite *RoleMappingTestSuite) TestBuildServiceAccessTuple() {
	t := suite.T()
	tuple := authz.BuildServiceAccessTuple("tenant1/partition1", "bot1")

	assert.Equal(t, authz.NamespaceTenancyAccess, tuple.Object.Namespace)
	assert.Equal(t, "tenant1/partition1", tuple.Object.ID)
	assert.Equal(t, authz.RoleService, tuple.Relation)
	assert.Equal(t, authz.NamespaceProfile, tuple.Subject.Namespace)
	assert.Equal(t, "bot1", tuple.Subject.ID)
	assert.Empty(t, tuple.Subject.Relation)
}

func (suite *RoleMappingTestSuite) TestRolePermissions_OwnerHasAll() {
	t := suite.T()
	perms := authz.RolePermissions[authz.RoleOwner]
	assert.Contains(t, perms, authz.PermissionTenantManage)
	assert.Contains(t, perms, authz.PermissionPermissionGrant)
	assert.Len(t, perms, 10)
}

func (suite *RoleMappingTestSuite) TestRolePermissions_MemberViewOnly() {
	t := suite.T()
	perms := authz.RolePermissions[authz.RoleMember]
	assert.Contains(t, perms, authz.PermissionTenantView)
	assert.Contains(t, perms, authz.PermissionPartitionView)
	assert.Contains(t, perms, authz.PermissionPagesView)
	assert.NotContains(t, perms, authz.PermissionTenantManage)
	assert.NotContains(t, perms, authz.PermissionAccessManage)
}

func (suite *RoleMappingTestSuite) TestRolePermissions_AdminNoTenantManage() {
	t := suite.T()
	perms := authz.RolePermissions[authz.RoleAdmin]
	assert.NotContains(t, perms, authz.PermissionTenantManage)
	assert.Contains(t, perms, authz.PermissionTenantView)
}

func (suite *RoleMappingTestSuite) TestGrantedRelation() {
	t := suite.T()
	assert.Equal(t, "granted_tenant_manage", authz.GrantedRelation(authz.PermissionTenantManage))
	assert.Equal(t, "granted_partition_view", authz.GrantedRelation(authz.PermissionPartitionView))
}

func (suite *RoleMappingTestSuite) TestBuildAccessTuple() {
	t := suite.T()
	tuple := authz.BuildAccessTuple("t1/p1", "profile-1")
	assert.Equal(t, authz.NamespaceTenancyAccess, tuple.Object.Namespace)
	assert.Equal(t, "t1/p1", tuple.Object.ID)
	assert.Equal(t, authz.RoleMember, tuple.Relation)
	assert.Equal(t, authz.NamespaceProfile, tuple.Subject.Namespace)
	assert.Equal(t, "profile-1", tuple.Subject.ID)
}

func (suite *RoleMappingTestSuite) TestBuildServicePartitionInheritanceTuple() {
	t := suite.T()
	tuple := authz.BuildServicePartitionInheritanceTuple("t1/parent", "t1/child")
	assert.Equal(t, authz.NamespaceTenancyAccess, tuple.Object.Namespace)
	assert.Equal(t, "t1/child", tuple.Object.ID)
	assert.Equal(t, authz.RoleService, tuple.Relation)
	assert.Equal(t, authz.NamespaceTenancyAccess, tuple.Subject.Namespace)
	assert.Equal(t, "t1/parent", tuple.Subject.ID)
	assert.Equal(t, authz.RoleService, tuple.Subject.Relation)
}

func (suite *RoleMappingTestSuite) TestBuildServiceInheritanceTuples_Empty() {
	t := suite.T()
	tuples := authz.BuildServiceInheritanceTuples("t1/p1", nil)
	assert.Empty(t, tuples)
}

func (suite *RoleMappingTestSuite) TestBuildServiceInheritanceTuples() {
	t := suite.T()
	tenancyPath := "tenant1/partition1"
	// Only specific namespaces the bot needs, not all services
	namespaces := []string{"service_commerce", "service_payment"}
	tuples := authz.BuildServiceInheritanceTuples(tenancyPath, namespaces)

	// 1 cross-namespace bridge per namespace — OPL permits handle permission resolution
	assert.Len(t, tuples, len(namespaces))

	for i, ns := range namespaces {
		assert.Equal(t, ns, tuples[i].Object.Namespace)
		assert.Equal(t, tenancyPath, tuples[i].Object.ID)
		assert.Equal(t, authz.RoleService, tuples[i].Relation)
		assert.Equal(t, authz.NamespaceTenancyAccess, tuples[i].Subject.Namespace)
		assert.Equal(t, tenancyPath, tuples[i].Subject.ID)
		assert.Equal(t, authz.RoleService, tuples[i].Subject.Relation)
	}
}
