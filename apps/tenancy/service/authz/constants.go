package authz

const (
	NamespaceTenancy       = "service_tenancy"
	NamespaceTenancyAccess = "tenancy_access"
	NamespaceProfile       = "profile_user"

	// Downstream service namespaces that accept service bot access via
	// the tenancy_access#service bridge pattern.
	NamespaceProfile_      = "service_profile"
	NamespaceNotifications = "service_notifications"
	NamespacePayment       = "service_payment"
	NamespaceLedger        = "service_ledger"
	NamespaceCommerce      = "service_commerce"
	NamespaceTrustage      = "service_trustage"
)

// AllServiceNamespaces lists every service namespace that should receive a
// bridge tuple (ns:path#service ← tenancy_access:path#service) when a
// partition is provisioned. This ensures service bots with a single
// tenancy_access#service tuple get functional permissions in all services.
var AllServiceNamespaces = []string{ //nolint:gochecknoglobals // namespace registry
	NamespaceTenancy,
	NamespaceProfile_,
	NamespaceNotifications,
	NamespacePayment,
	NamespaceLedger,
	NamespaceCommerce,
	NamespaceTrustage,
}

// Permission constants for tenancy operations.
// These names match the OPL permits functions and are used with Keto's Check API.
// Named as noun_verb (e.g. tenant_manage) so related permissions group together.
const (
	PermissionTenantManage    = "tenant_manage"
	PermissionTenantView      = "tenant_view"
	PermissionPartitionManage = "partition_manage"
	PermissionPartitionView   = "partition_view"
	PermissionAccessManage    = "access_manage"
	PermissionAccessView      = "access_view"
	PermissionRolesManage     = "roles_manage"
	PermissionPagesManage     = "pages_manage"
	PermissionPagesView       = "pages_view"
	PermissionPermissionGrant = "permission_grant"
)

// Granted relation constants for direct permission grants in the OPL.
// These are prefixed with "granted_" to avoid name conflicts with the OPL
// permits functions — Keto skips permit evaluation when a relation with
// the same name exists.
const (
	GrantedTenantManage    = "granted_tenant_manage"
	GrantedTenantView      = "granted_tenant_view"
	GrantedPartitionManage = "granted_partition_manage"
	GrantedPartitionView   = "granted_partition_view"
	GrantedAccessManage    = "granted_access_manage"
	GrantedAccessView      = "granted_access_view"
	GrantedRolesManage     = "granted_roles_manage"
	GrantedPagesManage     = "granted_pages_manage"
	GrantedPagesView       = "granted_pages_view"
	GrantedPermissionGrant = "granted_permission_grant"
)

// Role constants.
const (
	RoleOwner   = "owner"
	RoleAdmin   = "admin"
	RoleMember  = "member"
	RoleService = "service"
)
