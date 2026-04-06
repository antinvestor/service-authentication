//
//  Generated code. Do not modify.
//  source: tenancy/v1/tenancy.proto
//

import "package:connectrpc/connect.dart" as connect;
import "tenancy.pb.dart" as tenancyv1tenancy;
import "tenancy.connect.spec.dart" as specs;

/// TenancyService provides multi-tenancy and data isolation.
/// All RPCs require authentication via Bearer token.
extension type TenancyServiceClient (connect.Transport _transport) {
  /// GetTenant retrieves a tenant by ID.
  Future<tenancyv1tenancy.GetTenantResponse> getTenant(
    tenancyv1tenancy.GetTenantRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.getTenant,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// ListTenant retrieves all tenants matching criteria.
  Stream<tenancyv1tenancy.ListTenantResponse> listTenant(
    tenancyv1tenancy.ListTenantRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).server(
      specs.TenancyService.listTenant,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// CreateTenant creates a new tenant.
  Future<tenancyv1tenancy.CreateTenantResponse> createTenant(
    tenancyv1tenancy.CreateTenantRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.createTenant,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// UpdateTenant updates an existing tenant.
  Future<tenancyv1tenancy.UpdateTenantResponse> updateTenant(
    tenancyv1tenancy.UpdateTenantRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.updateTenant,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// RemoveTenant soft-deletes a tenant and all its partitions.
  Future<tenancyv1tenancy.RemoveTenantResponse> removeTenant(
    tenancyv1tenancy.RemoveTenantRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.removeTenant,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// ListPartition retrieves all partitions matching criteria.
  Stream<tenancyv1tenancy.ListPartitionResponse> listPartition(
    tenancyv1tenancy.ListPartitionRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).server(
      specs.TenancyService.listPartition,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// CreatePartition creates a new partition.
  Future<tenancyv1tenancy.CreatePartitionResponse> createPartition(
    tenancyv1tenancy.CreatePartitionRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.createPartition,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// GetPartition retrieves a partition by ID or domain.
  Future<tenancyv1tenancy.GetPartitionResponse> getPartition(
    tenancyv1tenancy.GetPartitionRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.getPartition,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// GetPartitionParents retrieves the parent hierarchy.
  Future<tenancyv1tenancy.GetPartitionParentsResponse> getPartitionParents(
    tenancyv1tenancy.GetPartitionParentsRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.getPartitionParents,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// RemovePartition soft-deletes a partition.
  Future<tenancyv1tenancy.RemovePartitionResponse> removePartition(
    tenancyv1tenancy.RemovePartitionRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.removePartition,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// UpdatePartition updates an existing partition.
  Future<tenancyv1tenancy.UpdatePartitionResponse> updatePartition(
    tenancyv1tenancy.UpdatePartitionRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.updatePartition,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// CreatePartitionRole creates a role within a partition.
  Future<tenancyv1tenancy.CreatePartitionRoleResponse> createPartitionRole(
    tenancyv1tenancy.CreatePartitionRoleRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.createPartitionRole,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// ListPartitionRole retrieves all roles for a partition.
  Stream<tenancyv1tenancy.ListPartitionRoleResponse> listPartitionRole(
    tenancyv1tenancy.ListPartitionRoleRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).server(
      specs.TenancyService.listPartitionRole,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// UpdatePartitionRole updates an existing partition role.
  Future<tenancyv1tenancy.UpdatePartitionRoleResponse> updatePartitionRole(
    tenancyv1tenancy.UpdatePartitionRoleRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.updatePartitionRole,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// RemovePartitionRole deletes a partition role.
  Future<tenancyv1tenancy.RemovePartitionRoleResponse> removePartitionRole(
    tenancyv1tenancy.RemovePartitionRoleRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.removePartitionRole,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// CreatePage creates a custom UI page for a partition.
  Future<tenancyv1tenancy.CreatePageResponse> createPage(
    tenancyv1tenancy.CreatePageRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.createPage,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// ListPage retrieves all custom pages for a partition.
  Stream<tenancyv1tenancy.ListPageResponse> listPage(
    tenancyv1tenancy.ListPageRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).server(
      specs.TenancyService.listPage,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// GetPage retrieves a custom page.
  Future<tenancyv1tenancy.GetPageResponse> getPage(
    tenancyv1tenancy.GetPageRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.getPage,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// UpdatePage updates an existing custom page.
  Future<tenancyv1tenancy.UpdatePageResponse> updatePage(
    tenancyv1tenancy.UpdatePageRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.updatePage,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// RemovePage deletes a custom page.
  Future<tenancyv1tenancy.RemovePageResponse> removePage(
    tenancyv1tenancy.RemovePageRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.removePage,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// CreateAccess grants a profile access to a partition.
  Future<tenancyv1tenancy.CreateAccessResponse> createAccess(
    tenancyv1tenancy.CreateAccessRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.createAccess,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// GetAccess retrieves an access grant.
  Future<tenancyv1tenancy.GetAccessResponse> getAccess(
    tenancyv1tenancy.GetAccessRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.getAccess,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// ListAccess retrieves all access grants for a partition or profile.
  Stream<tenancyv1tenancy.ListAccessResponse> listAccess(
    tenancyv1tenancy.ListAccessRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).server(
      specs.TenancyService.listAccess,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// RemoveAccess revokes a profile's access to a partition.
  Future<tenancyv1tenancy.RemoveAccessResponse> removeAccess(
    tenancyv1tenancy.RemoveAccessRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.removeAccess,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// CreateAccessRole assigns a role to an access grant.
  Future<tenancyv1tenancy.CreateAccessRoleResponse> createAccessRole(
    tenancyv1tenancy.CreateAccessRoleRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.createAccessRole,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// ListAccessRole retrieves all roles for an access grant.
  Stream<tenancyv1tenancy.ListAccessRoleResponse> listAccessRole(
    tenancyv1tenancy.ListAccessRoleRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).server(
      specs.TenancyService.listAccessRole,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// RemoveAccessRole removes a role from an access grant.
  Future<tenancyv1tenancy.RemoveAccessRoleResponse> removeAccessRole(
    tenancyv1tenancy.RemoveAccessRoleRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.removeAccessRole,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// CreateServiceAccount registers a service account (bot) for a partition.
  Future<tenancyv1tenancy.CreateServiceAccountResponse> createServiceAccount(
    tenancyv1tenancy.CreateServiceAccountRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.createServiceAccount,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// GetServiceAccount retrieves a service account.
  Future<tenancyv1tenancy.GetServiceAccountResponse> getServiceAccount(
    tenancyv1tenancy.GetServiceAccountRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.getServiceAccount,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// UpdateServiceAccount updates an existing service account.
  Future<tenancyv1tenancy.UpdateServiceAccountResponse> updateServiceAccount(
    tenancyv1tenancy.UpdateServiceAccountRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.updateServiceAccount,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// ListServiceAccount retrieves all service accounts for a partition.
  Stream<tenancyv1tenancy.ListServiceAccountResponse> listServiceAccount(
    tenancyv1tenancy.ListServiceAccountRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).server(
      specs.TenancyService.listServiceAccount,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// RemoveServiceAccount deregisters a service account.
  Future<tenancyv1tenancy.RemoveServiceAccountResponse> removeServiceAccount(
    tenancyv1tenancy.RemoveServiceAccountRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.removeServiceAccount,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// CreateClient registers an OAuth2 client for a partition or service account.
  Future<tenancyv1tenancy.CreateClientResponse> createClient(
    tenancyv1tenancy.CreateClientRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.createClient,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// GetClient retrieves an OAuth2 client by ID or client_id.
  Future<tenancyv1tenancy.GetClientResponse> getClient(
    tenancyv1tenancy.GetClientRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.getClient,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// ListClient retrieves all OAuth2 clients for a partition or service account.
  Stream<tenancyv1tenancy.ListClientResponse> listClient(
    tenancyv1tenancy.ListClientRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).server(
      specs.TenancyService.listClient,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// UpdateClient updates an existing OAuth2 client.
  Future<tenancyv1tenancy.UpdateClientResponse> updateClient(
    tenancyv1tenancy.UpdateClientRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.updateClient,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// RemoveClient deletes an OAuth2 client.
  Future<tenancyv1tenancy.RemoveClientResponse> removeClient(
    tenancyv1tenancy.RemoveClientRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.removeClient,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// ListServiceNamespaces returns all registered service permission namespaces.
  Future<tenancyv1tenancy.ListServiceNamespacesResponse> listServiceNamespaces(
    tenancyv1tenancy.ListServiceNamespacesRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.listServiceNamespaces,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// GrantPermission grants a specific permission to a profile in a service namespace.
  Future<tenancyv1tenancy.GrantPermissionResponse> grantPermission(
    tenancyv1tenancy.GrantPermissionRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.grantPermission,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// RevokePermission revokes a specific permission from a profile in a service namespace.
  Future<tenancyv1tenancy.RevokePermissionResponse> revokePermission(
    tenancyv1tenancy.RevokePermissionRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.TenancyService.revokePermission,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }
}
