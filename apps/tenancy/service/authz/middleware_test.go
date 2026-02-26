package authz_test

import (
	"context"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz/mock"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/frame/security/authorizer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ctxWithClaims(subjectID string) context.Context {
	claims := &security.AuthenticationClaims{
		TenantID: "tenant1",
	}
	claims.Subject = subjectID
	return claims.ClaimsToContext(context.Background())
}

func TestMiddleware_OwnerHasAllPermissions(t *testing.T) {
	mockAuthz := mock.NewAuthzService()
	err := mockAuthz.AddTenantMember("tenant1", "user1", authz.RoleOwner)
	require.NoError(t, err)

	mw := authz.NewMiddleware(mockAuthz)
	ctx := ctxWithClaims("user1")

	assert.NoError(t, mw.CanManageTenant(ctx))
	assert.NoError(t, mw.CanViewTenant(ctx))
	assert.NoError(t, mw.CanManagePartition(ctx))
	assert.NoError(t, mw.CanViewPartition(ctx))
	assert.NoError(t, mw.CanManageAccess(ctx))
	assert.NoError(t, mw.CanManageRoles(ctx))
	assert.NoError(t, mw.CanManagePages(ctx))
	assert.NoError(t, mw.CanViewPages(ctx))
	assert.NoError(t, mw.CanGrantPermission(ctx))
}

func TestMiddleware_AdminPermissions(t *testing.T) {
	mockAuthz := mock.NewAuthzService()
	err := mockAuthz.AddTenantMember("tenant1", "user2", authz.RoleAdmin)
	require.NoError(t, err)

	mw := authz.NewMiddleware(mockAuthz)
	ctx := ctxWithClaims("user2")

	// Admin cannot manage tenant
	assert.Error(t, mw.CanManageTenant(ctx))

	// Admin can do everything else
	assert.NoError(t, mw.CanViewTenant(ctx))
	assert.NoError(t, mw.CanManagePartition(ctx))
	assert.NoError(t, mw.CanViewPartition(ctx))
	assert.NoError(t, mw.CanManageAccess(ctx))
	assert.NoError(t, mw.CanManageRoles(ctx))
	assert.NoError(t, mw.CanManagePages(ctx))
	assert.NoError(t, mw.CanViewPages(ctx))
	assert.NoError(t, mw.CanGrantPermission(ctx))
}

func TestMiddleware_MemberPermissions(t *testing.T) {
	mockAuthz := mock.NewAuthzService()
	err := mockAuthz.AddTenantMember("tenant1", "user3", authz.RoleMember)
	require.NoError(t, err)

	mw := authz.NewMiddleware(mockAuthz)
	ctx := ctxWithClaims("user3")

	// Member can only view
	assert.NoError(t, mw.CanViewTenant(ctx))
	assert.NoError(t, mw.CanViewPartition(ctx))
	assert.NoError(t, mw.CanViewPages(ctx))

	// Member cannot manage
	assert.Error(t, mw.CanManageTenant(ctx))
	assert.Error(t, mw.CanManagePartition(ctx))
	assert.Error(t, mw.CanManageAccess(ctx))
	assert.Error(t, mw.CanManageRoles(ctx))
	assert.Error(t, mw.CanManagePages(ctx))
	assert.Error(t, mw.CanGrantPermission(ctx))
}

func TestMiddleware_NoClaims(t *testing.T) {
	mockAuthz := mock.NewAuthzService()
	mw := authz.NewMiddleware(mockAuthz)

	err := mw.CanViewTenant(context.Background())
	assert.ErrorIs(t, err, authorizer.ErrInvalidSubject)
}

func TestMiddleware_NoTenant(t *testing.T) {
	mockAuthz := mock.NewAuthzService()
	mw := authz.NewMiddleware(mockAuthz)

	claims := &security.AuthenticationClaims{}
	claims.Subject = "user1"
	ctx := claims.ClaimsToContext(context.Background())
	err := mw.CanViewTenant(ctx)
	assert.ErrorIs(t, err, authorizer.ErrInvalidObject)
}

func TestMiddleware_DirectPermissionGrant(t *testing.T) {
	mockAuthz := mock.NewAuthzService()
	mw := authz.NewMiddleware(mockAuthz)

	// User has no role but a direct permission grant
	err := mockAuthz.WriteTuple(context.Background(), security.RelationTuple{
		Object:   security.ObjectRef{Namespace: authz.NamespaceTenant, ID: "tenant1"},
		Relation: authz.PermissionManagePages,
		Subject:  security.SubjectRef{Namespace: authz.NamespaceProfile, ID: "user4"},
	})
	require.NoError(t, err)

	ctx := ctxWithClaims("user4")

	// Direct grant works
	assert.NoError(t, mw.CanManagePages(ctx))

	// Other permissions still denied
	assert.Error(t, mw.CanManageTenant(ctx))
	assert.Error(t, mw.CanManageAccess(ctx))
}
