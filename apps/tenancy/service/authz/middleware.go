package authz

import (
	"context"

	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/frame/security/authorizer"
)

// Middleware defines permission checks for tenancy operations.
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
	authorizer security.Authorizer
}

// NewMiddleware creates a new tenancy authorization middleware.
func NewMiddleware(auth security.Authorizer) Middleware {
	return &middleware{authorizer: auth}
}

func (m *middleware) CanManageTenant(ctx context.Context) error {
	return m.check(ctx, PermissionManageTenant)
}

func (m *middleware) CanViewTenant(ctx context.Context) error {
	return m.check(ctx, PermissionViewTenant)
}

func (m *middleware) CanManagePartition(ctx context.Context) error {
	return m.check(ctx, PermissionManagePartition)
}

func (m *middleware) CanViewPartition(ctx context.Context) error {
	return m.check(ctx, PermissionViewPartition)
}

func (m *middleware) CanManageAccess(ctx context.Context) error {
	return m.check(ctx, PermissionManageAccess)
}

func (m *middleware) CanManageRoles(ctx context.Context) error {
	return m.check(ctx, PermissionManageRoles)
}

func (m *middleware) CanManagePages(ctx context.Context) error {
	return m.check(ctx, PermissionManagePages)
}

func (m *middleware) CanViewPages(ctx context.Context) error {
	return m.check(ctx, PermissionViewPages)
}

func (m *middleware) CanGrantPermission(ctx context.Context) error {
	return m.check(ctx, PermissionGrantPermission)
}

func (m *middleware) check(ctx context.Context, permission string) error {
	claims := security.ClaimsFromContext(ctx)
	if claims == nil {
		return authorizer.ErrInvalidSubject
	}

	subjectID, err := claims.GetSubject()
	if err != nil || subjectID == "" {
		return authorizer.ErrInvalidSubject
	}

	tenantID := claims.GetTenantID()
	if tenantID == "" {
		return authorizer.ErrInvalidObject
	}

	req := security.CheckRequest{
		Object:     security.ObjectRef{Namespace: NamespaceTenant, ID: tenantID},
		Permission: permission,
		Subject:    security.SubjectRef{Namespace: NamespaceProfile, ID: subjectID},
	}

	result, err := m.authorizer.Check(ctx, req)
	if err != nil {
		return err
	}
	if !result.Allowed {
		return authorizer.NewPermissionDeniedError(req.Object, permission, req.Subject, result.Reason)
	}

	return nil
}
