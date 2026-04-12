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

package authz

import (
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/data"
)

const (
	NamespaceTenancy        = "service_tenancy"
	NamespaceTenancyAccess  = "tenancy_access"
	NamespaceProfile        = "profile_user"
	NamespaceServiceProfile = "service_profile"
	NamespaceServiceDevice  = "service_device"
	NamespaceServiceSetting = "service_setting"
	NamespaceServiceAudit   = "service_audit"
)

// CoreServiceNamespaces lists the service namespaces that receive direct role
// tuples (profile_user → ns#role) whenever a user is assigned a partition role.
// This ensures that functional permissions in these namespaces are resolved
// directly by Keto without bridge tuples.
//
// Root partition owners/admins get owner/member tuples written to every entry
// here at bootstrap, which guarantees they can always manage tenancy, audit,
// profile, device, and setting services without any manual provisioning.
var CoreServiceNamespaces = []string{ //nolint:gochecknoglobals // namespace registry
	NamespaceTenancy,
	NamespaceServiceAudit,
	NamespaceServiceProfile,
	NamespaceServiceDevice,
	NamespaceServiceSetting,
}

// CoreServiceNamespaceRecords returns ServiceNamespace records for the core
// namespaces with RoleBindings set for all standard roles. Use this when you
// need []*models.ServiceNamespace but only have the hardcoded core list
// (e.g., in tests where the OPL is known to have all standard roles).
func CoreServiceNamespaceRecords() []*models.ServiceNamespace {
	bindings := data.JSONMap{
		RoleOwner:   []string{},
		RoleAdmin:   []string{},
		RoleMember:  []string{},
		RoleService: []string{},
	}
	records := make([]*models.ServiceNamespace, 0, len(CoreServiceNamespaces))
	for _, ns := range CoreServiceNamespaces {
		records = append(records, &models.ServiceNamespace{
			Namespace:    ns,
			RoleBindings: bindings,
		})
	}
	return records
}

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

// Root tenant and partition IDs. Users with owner/admin roles on this
// partition receive the "internal" JWT role at login, enabling cross-tenant
// administration via EnrichTenancyClaims.
const (
	RootTenantID    = "c2f4j7au6s7f91uqnojg"
	RootPartitionID = "c2f4j7au6s7f91uqnokg"
)

// IsRootPartition reports whether the given partition ID is the root partition.
func IsRootPartition(partitionID string) bool {
	return partitionID == RootPartitionID
}
