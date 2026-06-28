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

package authz_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type RoleMappingTestSuite struct {
	suite.Suite
}

func TestRoleMappingTestSuite(t *testing.T) {
	suite.Run(t, new(RoleMappingTestSuite))
}

func (suite *RoleMappingTestSuite) TestBuildRoleTuples_CoreNamespacesAndTenancyAccess() {
	t := suite.T()
	role := authz.RoleAdmin
	nsRecords := authz.CoreServiceNamespaceRecords()
	tuples := authz.BuildRoleTuples("tenant1/partition1", "profile1", role, nsRecords)

	// One tuple per CoreServiceNamespace + one for tenancy_access
	expectedCount := len(authz.CoreServiceNamespaces) + 1
	assert.Len(t, tuples, expectedCount)

	// All core service namespaces get direct profile_user role tuples
	for i, ns := range authz.CoreServiceNamespaces {
		assert.Equal(t, ns, tuples[i].Object.Namespace)
		assert.Equal(t, "tenant1/partition1", tuples[i].Object.ID)
		assert.Equal(t, role, tuples[i].Relation)
		assert.Equal(t, authz.NamespaceProfile, tuples[i].Subject.Namespace)
		assert.Equal(t, "profile1", tuples[i].Subject.ID)
	}

	// Last tuple: tenancy_access role (data-access plane)
	last := tuples[len(tuples)-1]
	assert.Equal(t, authz.NamespaceTenancyAccess, last.Object.Namespace)
	assert.Equal(t, "tenant1/partition1", last.Object.ID)
	assert.Equal(t, role, last.Relation)
	assert.Equal(t, authz.NamespaceProfile, last.Subject.Namespace)
	assert.Equal(t, "profile1", last.Subject.ID)
}

func (suite *RoleMappingTestSuite) TestBuildRoleTuples_DynamicNamespaces() {
	t := suite.T()
	role := authz.RoleOwner
	nsRecords := []*models.ServiceNamespace{
		{Namespace: "service_commerce", RoleBindings: map[string]any{authz.RoleOwner: []string{}, authz.RoleMember: []string{}}},
		{Namespace: "service_payment", RoleBindings: map[string]any{authz.RoleOwner: []string{}, authz.RoleMember: []string{}}},
		{Namespace: "service_tenancy", RoleBindings: map[string]any{authz.RoleOwner: []string{}, authz.RoleMember: []string{}}},
	}
	tuples := authz.BuildRoleTuples("t1/p1", "profile1", role, nsRecords)

	// One tuple per namespace + one for tenancy_access
	assert.Len(t, tuples, len(nsRecords)+1)

	for i, ns := range nsRecords {
		assert.Equal(t, ns.Namespace, tuples[i].Object.Namespace)
		assert.Equal(t, role, tuples[i].Relation)
	}

	last := tuples[len(tuples)-1]
	assert.Equal(t, authz.NamespaceTenancyAccess, last.Object.Namespace)
}

func (suite *RoleMappingTestSuite) TestBuildRoleTuples_NilWritesTenancyAccessOnly() {
	t := suite.T()
	tuples := authz.BuildRoleTuples("t1/p1", "profile1", authz.RoleMember, nil)

	// Nil namespaces means no service namespace tuples — only tenancy_access
	assert.Len(t, tuples, 1)
	assert.Equal(t, authz.NamespaceTenancyAccess, tuples[0].Object.Namespace)
}

func (suite *RoleMappingTestSuite) TestBuildRoleTuples_SkipsNamespacesWithoutRole() {
	t := suite.T()
	nsRecords := []*models.ServiceNamespace{
		{Namespace: "service_tenancy", RoleBindings: map[string]any{authz.RoleOwner: []string{}, authz.RoleMember: []string{}}},
		{Namespace: "service_authentication", RoleBindings: map[string]any{}}, // no roles declared
		{Namespace: "service_profile", RoleBindings: map[string]any{authz.RoleOwner: []string{}, authz.RoleMember: []string{}}},
	}
	tuples := authz.BuildRoleTuples("t1/p1", "profile1", authz.RoleOwner, nsRecords)

	// Only service_tenancy and service_profile support owner, + tenancy_access
	assert.Len(t, tuples, 3)
	assert.Equal(t, "service_tenancy", tuples[0].Object.Namespace)
	assert.Equal(t, "service_profile", tuples[1].Object.Namespace)
	assert.Equal(t, authz.NamespaceTenancyAccess, tuples[2].Object.Namespace)
}

func (suite *RoleMappingTestSuite) TestRegisteredNamespaceNames() {
	t := suite.T()

	// Nil input falls back to CoreServiceNamespaces
	result := authz.RegisteredNamespaceNames(nil)
	assert.Equal(t, authz.CoreServiceNamespaces, result)

	// Non-empty input extracts namespace strings
	input := []*models.ServiceNamespace{
		{Namespace: "service_commerce"},
		{Namespace: "service_payment"},
	}
	result = authz.RegisteredNamespaceNames(input)
	assert.Equal(t, []string{"service_commerce", "service_payment"}, result)
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
	assert.Len(t, perms, 14)
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

func (suite *RoleMappingTestSuite) TestBuildServicePermissionTuples() {
	t := suite.T()
	perms := []string{"tenant_view", "partition_manage"}
	tuples := authz.BuildServicePermissionTuples("t1/p1", "bot1", "service_profile", perms)

	assert.Len(t, tuples, 2)
	for i, perm := range perms {
		assert.Equal(t, "service_profile", tuples[i].Object.Namespace)
		assert.Equal(t, "t1/p1", tuples[i].Object.ID)
		assert.Equal(t, "granted_"+perm, tuples[i].Relation)
		assert.Equal(t, authz.NamespaceProfile, tuples[i].Subject.Namespace)
		assert.Equal(t, "bot1", tuples[i].Subject.ID)
	}
}

func (suite *RoleMappingTestSuite) TestBuildServicePermissionTuples_Empty() {
	tuples := authz.BuildServicePermissionTuples("t1/p1", "bot1", "ns", nil)
	assert.Empty(suite.T(), tuples)
}

func (suite *RoleMappingTestSuite) TestParseAudiencePermissions_FullAccessWildcard() {
	t := suite.T()
	audiences := map[string]any{"service_profile": []any{"*"}, "service_payment": []any{"*"}}
	result := authz.ParseAudiencePermissions(audiences)

	assert.Len(t, result, 2)
	// ["*"] is parsed as-is — IsFullAccess checks for it.
	assert.Equal(t, []string{"*"}, result["service_profile"])
	assert.Equal(t, []string{"*"}, result["service_payment"])
}

func (suite *RoleMappingTestSuite) TestParseAudiencePermissions_EmptyArrayNoAccess() {
	t := suite.T()
	// Empty arrays mean no permissions — NOT full access.
	audiences := map[string]any{"service_profile": []any{}}
	result := authz.ParseAudiencePermissions(audiences)

	assert.Len(t, result, 1)
	assert.Contains(t, result, "service_profile")
	assert.Nil(t, result["service_profile"])
	assert.False(t, authz.IsFullAccess(result["service_profile"]))
}

func (suite *RoleMappingTestSuite) TestParseAudiencePermissions_ExplicitFormat() {
	t := suite.T()
	audiences := map[string]any{
		"service_profile": []any{"tenant_view", "partition_view"},
		"service_payment": []any{"tenant_view"},
	}
	result := authz.ParseAudiencePermissions(audiences)

	assert.Len(t, result, 2)
	assert.Equal(t, []string{"tenant_view", "partition_view"}, result["service_profile"])
	assert.Equal(t, []string{"tenant_view"}, result["service_payment"])
}

func (suite *RoleMappingTestSuite) TestParseAudiencePermissions_NonArrayValueIgnored() {
	t := suite.T()
	audiences := map[string]any{
		"other": "value",
	}
	result := authz.ParseAudiencePermissions(audiences)
	// Non-array values produce nil permissions — namespace is recorded but no access.
	assert.Len(t, result, 1)
	assert.Contains(t, result, "other")
	assert.Nil(t, result["other"])
}

func (suite *RoleMappingTestSuite) TestIsFullAccess() {
	t := suite.T()
	assert.False(t, authz.IsFullAccess(nil))
	assert.False(t, authz.IsFullAccess([]string{}))
	assert.True(t, authz.IsFullAccess([]string{"*"}))
	assert.False(t, authz.IsFullAccess([]string{"tenant_view"}))
	assert.False(t, authz.IsFullAccess([]string{"*", "tenant_view"}))
}

func (suite *RoleMappingTestSuite) TestAudienceNamespaces_ExplicitFormat() {
	t := suite.T()
	audiences := map[string]any{
		"service_profile": []any{"tenant_view"},
		"service_payment": []any{"tenant_view"},
	}
	result := authz.AudienceNamespaces(audiences)
	assert.ElementsMatch(t, []string{"service_profile", "service_payment"}, result)
}

func (suite *RoleMappingTestSuite) TestResolveServiceGrantsExpandsServiceRole() {
	t := suite.T()
	namespaces := []*models.ServiceNamespace{{
		Namespace:   "service_profile",
		Permissions: data.JSONMap{"values": []any{"profile_view", "profile_manage"}},
		RoleBindings: data.JSONMap{
			authz.RoleService: []any{"profile_manage", "profile_view"},
		},
	}}

	resolved, err := authz.ResolveServiceGrants(
		map[string][]string{"service_profile": {"*"}},
		namespaces,
	)

	require.NoError(t, err)
	assert.Equal(t, []string{"profile_manage", "profile_view"}, resolved["service_profile"])
}

func (suite *RoleMappingTestSuite) TestResolveServiceGrantsRejectsUnknownSchema() {
	t := suite.T()
	namespaces := []*models.ServiceNamespace{{
		Namespace:   "service_profile",
		Permissions: data.JSONMap{"values": []any{"profile_view"}},
	}}

	_, err := authz.ResolveServiceGrants(
		map[string][]string{"opportunities_api": {"opportunity_view"}},
		namespaces,
	)

	require.ErrorContains(t, err, `authorization namespace "opportunities_api" is not registered`)
}

func (suite *RoleMappingTestSuite) TestResolveServiceGrantsRejectsUnknownPermission() {
	t := suite.T()
	namespaces := []*models.ServiceNamespace{{
		Namespace:   "service_profile",
		Permissions: data.JSONMap{"values": []any{"profile_view"}},
	}}

	_, err := authz.ResolveServiceGrants(
		map[string][]string{"service_profile": {"profile_delete"}},
		namespaces,
	)

	require.ErrorContains(t, err, `authorization permission "profile_delete" is not registered`)
}

func (suite *RoleMappingTestSuite) TestSelectRegisteredServiceGrantsExcludesOAuthRecipients() {
	t := suite.T()
	namespaces := []*models.ServiceNamespace{{Namespace: "service_profile"}}
	requested := map[string][]string{
		"service_profile":   {"profile_view"},
		"opportunities_api": {"*"},
	}

	selected := authz.SelectRegisteredServiceGrants(requested, namespaces)

	require.Equal(t, map[string][]string{"service_profile": {"profile_view"}}, selected)
}

func (suite *RoleMappingTestSuite) TestSortRelationTuples() {
	t := suite.T()
	tuples := []security.RelationTuple{
		authz.BuildPermissionTuple("service_profile", "t/p", "profile_view", "profile-b"),
		authz.BuildPermissionTuple("service_audit", "t/p", "audit_view", "profile-a"),
	}

	authz.SortRelationTuples(tuples)

	require.Equal(t, "service_audit", tuples[0].Object.Namespace)
	require.Equal(t, "service_profile", tuples[1].Object.Namespace)
}

func (suite *RoleMappingTestSuite) TestDeployedCatalogRejectsRuntimeOnlyNamespace() {
	t := suite.T()
	selected := authz.SelectDeployedNamespaceRecords([]*models.ServiceNamespace{
		{Namespace: "service_profile"},
		{Namespace: "opportunities_api"},
	})

	require.Len(t, selected, 1)
	require.Equal(t, "service_profile", selected[0].Namespace)
	require.NotEmpty(t, authz.DeployedServiceNamespaceRecords())
}
