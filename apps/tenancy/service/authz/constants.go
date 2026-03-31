package authz

const (
	NamespaceTenancy       = "service_tenancy"
	NamespaceTenancyAccess = "tenancy_access"
	NamespaceProfile       = "profile_user"
)

// Permission constants for tenancy operations.
// These names match the OPL permits functions and are used with Keto's Check API.
// Named as noun_verb (e.g. tenant_manage) so related permissions group together.
const (
	PermissionTenantManage         = "tenant_manage"
	PermissionTenantView           = "tenant_view"
	PermissionPartitionManage      = "partition_manage"
	PermissionPartitionView        = "partition_view"
	PermissionAccessManage         = "access_manage"
	PermissionAccessView           = "access_view"
	PermissionRolesManage          = "role_manage"
	PermissionPagesManage          = "page_manage"
	PermissionPagesView            = "page_view"
	PermissionPermissionGrant      = "permission_grant"
	PermissionServiceAccountView   = "service_account_view"
	PermissionServiceAccountManage = "service_account_manage"
	PermissionClientView           = "client_view"
	PermissionClientManage         = "client_manage"
)

// Granted relation constants for direct permission grants in the OPL.
// These are prefixed with "granted_" to avoid name conflicts with the OPL
// permits functions — Keto skips permit evaluation when a relation with
// the same name exists.
const (
	GrantedTenantManage         = "granted_tenant_manage"
	GrantedTenantView           = "granted_tenant_view"
	GrantedPartitionManage      = "granted_partition_manage"
	GrantedPartitionView        = "granted_partition_view"
	GrantedAccessManage         = "granted_access_manage"
	GrantedAccessView           = "granted_access_view"
	GrantedRolesManage          = "granted_role_manage"
	GrantedPagesManage          = "granted_page_manage"
	GrantedPagesView            = "granted_page_view"
	GrantedPermissionGrant      = "granted_permission_grant"
	GrantedServiceAccountView   = "granted_service_account_view"
	GrantedServiceAccountManage = "granted_service_account_manage"
	GrantedClientView           = "granted_client_view"
	GrantedClientManage         = "granted_client_manage"
)

// Role constants.
const (
	RoleOwner   = "owner"
	RoleAdmin   = "admin"
	RoleMember  = "member"
	RoleService = "service"
)
