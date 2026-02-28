package authz

import (
	"context"

	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/frame/security/authorizer"
)

// Middleware defines functional permission checks for tenancy operations.
// Data access (tenancy_access) is verified by the TenancyAccessInterceptor
// in the Connect/HTTP middleware chain. This middleware only checks functional
// permissions in the service_tenancy namespace.
type Middleware interface {
	CanTenantManage(ctx context.Context) error
	CanTenantView(ctx context.Context) error
	CanPartitionManage(ctx context.Context) error
	CanPartitionView(ctx context.Context) error
	CanAccessManage(ctx context.Context) error
	CanRolesManage(ctx context.Context) error
	CanPagesManage(ctx context.Context) error
	CanPagesView(ctx context.Context) error
	CanPermissionGrant(ctx context.Context) error
}

type middleware struct {
	checker *authorizer.FunctionChecker
}

// NewMiddleware creates a new functional permission middleware that checks
// application-specific permissions in the service_tenancy namespace.
func NewMiddleware(auth security.Authorizer) Middleware {
	return &middleware{
		checker: authorizer.NewFunctionChecker(auth, NamespaceTenancy),
	}
}

func (m *middleware) CanTenantManage(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionTenantManage)
}

func (m *middleware) CanTenantView(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionTenantView)
}

func (m *middleware) CanPartitionManage(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionPartitionManage)
}

func (m *middleware) CanPartitionView(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionPartitionView)
}

func (m *middleware) CanAccessManage(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionAccessManage)
}

func (m *middleware) CanRolesManage(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionRolesManage)
}

func (m *middleware) CanPagesManage(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionPagesManage)
}

func (m *middleware) CanPagesView(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionPagesView)
}

func (m *middleware) CanPermissionGrant(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionPermissionGrant)
}
