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
	CanManageTenant(ctx context.Context) error
	CanViewTenant(ctx context.Context) error
	CanManagePartition(ctx context.Context) error
	CanViewPartition(ctx context.Context) error
	CanManageAccess(ctx context.Context) error
	CanManageRoles(ctx context.Context) error
	CanManagePages(ctx context.Context) error
	CanViewPages(ctx context.Context) error
	CanGrantPermission(ctx context.Context) error
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

func (m *middleware) CanManageTenant(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionManageTenant)
}

func (m *middleware) CanViewTenant(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionViewTenant)
}

func (m *middleware) CanManagePartition(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionManagePartition)
}

func (m *middleware) CanViewPartition(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionViewPartition)
}

func (m *middleware) CanManageAccess(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionManageAccess)
}

func (m *middleware) CanManageRoles(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionManageRoles)
}

func (m *middleware) CanManagePages(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionManagePages)
}

func (m *middleware) CanViewPages(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionViewPages)
}

func (m *middleware) CanGrantPermission(ctx context.Context) error {
	return m.checker.Check(ctx, PermissionGrantPermission)
}
