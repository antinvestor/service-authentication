package authz

const (
	NamespaceTenant  = "tenancy_tenant"
	NamespaceProfile = "profile"
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
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)
