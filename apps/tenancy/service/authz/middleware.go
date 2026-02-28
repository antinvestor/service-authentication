package authz

import (
	"context"
	"fmt"

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
	auth    security.Authorizer
	checker *authorizer.FunctionChecker
}

// NewMiddleware creates a new functional permission middleware that checks
// application-specific permissions in the service_tenancy namespace.
func NewMiddleware(auth security.Authorizer) Middleware {
	return &middleware{
		auth:    auth,
		checker: authorizer.NewFunctionChecker(auth, NamespaceTenancy),
	}
}

// check verifies the given permission. For system_internal callers whose tokens
// lack tenant/partition context, it queries the authorizer directly using the
// caller's subject ID — the authorizer decides (returning allowed in permissive
// mode, or checking Keto tuples when configured).
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
	partitionID := claims.GetPartitionID()

	// System_internal callers don't carry tenant/partition in their token.
	// Query the authorizer directly so it can decide (permissive when Keto
	// is unconfigured, or resolve via Keto subject sets when configured).
	if claims.IsInternalSystem() && (tenantID == "" || partitionID == "") {
		result, chkErr := m.auth.Check(ctx, security.CheckRequest{
			Object:     security.ObjectRef{Namespace: NamespaceTenancy, ID: fmt.Sprintf("%s/%s", tenantID, partitionID)},
			Permission: permission,
			Subject:    security.SubjectRef{Namespace: NamespaceProfile, ID: subjectID},
		})
		if chkErr != nil {
			return chkErr
		}
		if result.Allowed {
			return nil
		}
		return authorizer.NewPermissionDeniedError(
			security.ObjectRef{Namespace: NamespaceTenancy, ID: fmt.Sprintf("%s/%s", tenantID, partitionID)},
			permission,
			security.SubjectRef{Namespace: NamespaceProfile, ID: subjectID},
			result.Reason,
		)
	}

	return m.checker.Check(ctx, permission)
}

func (m *middleware) CanTenantManage(ctx context.Context) error {
	return m.check(ctx, PermissionTenantManage)
}

func (m *middleware) CanTenantView(ctx context.Context) error {
	return m.check(ctx, PermissionTenantView)
}

func (m *middleware) CanPartitionManage(ctx context.Context) error {
	return m.check(ctx, PermissionPartitionManage)
}

func (m *middleware) CanPartitionView(ctx context.Context) error {
	return m.check(ctx, PermissionPartitionView)
}

func (m *middleware) CanAccessManage(ctx context.Context) error {
	return m.check(ctx, PermissionAccessManage)
}

func (m *middleware) CanRolesManage(ctx context.Context) error {
	return m.check(ctx, PermissionRolesManage)
}

func (m *middleware) CanPagesManage(ctx context.Context) error {
	return m.check(ctx, PermissionPagesManage)
}

func (m *middleware) CanPagesView(ctx context.Context) error {
	return m.check(ctx, PermissionPagesView)
}

func (m *middleware) CanPermissionGrant(ctx context.Context) error {
	return m.check(ctx, PermissionPermissionGrant)
}
