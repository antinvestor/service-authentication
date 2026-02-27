package authz

const (
	NamespaceTenancy       = "service_tenancy"
	NamespaceTenancyAccess = "tenancy_access"
	NamespaceProfile       = "profile/user"
)

// Permission constants for tenancy operations.
const (
	PermissionManageTenant    = "manage_tenant"
	PermissionViewTenant      = "view_tenant"
	PermissionManagePartition = "manage_partition"
	PermissionViewPartition   = "view_partition"
	PermissionManageAccess    = "manage_access"
	PermissionViewAccess      = "view_access"
	PermissionManageRoles     = "manage_roles"
	PermissionManagePages     = "manage_pages"
	PermissionViewPages       = "view_pages"
	PermissionGrantPermission = "grant_permission"
)

// Role constants.
const (
	RoleOwner   = "owner"
	RoleAdmin   = "admin"
	RoleMember  = "member"
	RoleService = "service"
)
