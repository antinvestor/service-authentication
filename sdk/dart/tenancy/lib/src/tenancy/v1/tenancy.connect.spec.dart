//
//  Generated code. Do not modify.
//  source: tenancy/v1/tenancy.proto
//

import "package:connectrpc/connect.dart" as connect;
import "tenancy.pb.dart" as tenancyv1tenancy;

/// TenancyService provides multi-tenancy and data isolation.
/// All RPCs require authentication via Bearer token.
abstract final class TenancyService {
  /// Fully-qualified name of the TenancyService service.
  static const name = 'tenancy.v1.TenancyService';

  /// GetTenant retrieves a tenant by ID.
  static const getTenant = connect.Spec(
    '/$name/GetTenant',
    connect.StreamType.unary,
    tenancyv1tenancy.GetTenantRequest.new,
    tenancyv1tenancy.GetTenantResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// ListTenant retrieves all tenants matching criteria.
  static const listTenant = connect.Spec(
    '/$name/ListTenant',
    connect.StreamType.server,
    tenancyv1tenancy.ListTenantRequest.new,
    tenancyv1tenancy.ListTenantResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// CreateTenant creates a new tenant.
  static const createTenant = connect.Spec(
    '/$name/CreateTenant',
    connect.StreamType.unary,
    tenancyv1tenancy.CreateTenantRequest.new,
    tenancyv1tenancy.CreateTenantResponse.new,
  );

  /// UpdateTenant updates an existing tenant.
  static const updateTenant = connect.Spec(
    '/$name/UpdateTenant',
    connect.StreamType.unary,
    tenancyv1tenancy.UpdateTenantRequest.new,
    tenancyv1tenancy.UpdateTenantResponse.new,
  );

  /// RemoveTenant soft-deletes a tenant and all its partitions.
  static const removeTenant = connect.Spec(
    '/$name/RemoveTenant',
    connect.StreamType.unary,
    tenancyv1tenancy.RemoveTenantRequest.new,
    tenancyv1tenancy.RemoveTenantResponse.new,
  );

  /// ListPartition retrieves all partitions matching criteria.
  static const listPartition = connect.Spec(
    '/$name/ListPartition',
    connect.StreamType.server,
    tenancyv1tenancy.ListPartitionRequest.new,
    tenancyv1tenancy.ListPartitionResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// CreatePartition creates a new partition.
  static const createPartition = connect.Spec(
    '/$name/CreatePartition',
    connect.StreamType.unary,
    tenancyv1tenancy.CreatePartitionRequest.new,
    tenancyv1tenancy.CreatePartitionResponse.new,
  );

  /// GetPartition retrieves a partition by ID or domain.
  static const getPartition = connect.Spec(
    '/$name/GetPartition',
    connect.StreamType.unary,
    tenancyv1tenancy.GetPartitionRequest.new,
    tenancyv1tenancy.GetPartitionResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// GetPartitionParents retrieves the parent hierarchy.
  static const getPartitionParents = connect.Spec(
    '/$name/GetPartitionParents',
    connect.StreamType.unary,
    tenancyv1tenancy.GetPartitionParentsRequest.new,
    tenancyv1tenancy.GetPartitionParentsResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// RemovePartition soft-deletes a partition.
  static const removePartition = connect.Spec(
    '/$name/RemovePartition',
    connect.StreamType.unary,
    tenancyv1tenancy.RemovePartitionRequest.new,
    tenancyv1tenancy.RemovePartitionResponse.new,
  );

  /// UpdatePartition updates an existing partition.
  static const updatePartition = connect.Spec(
    '/$name/UpdatePartition',
    connect.StreamType.unary,
    tenancyv1tenancy.UpdatePartitionRequest.new,
    tenancyv1tenancy.UpdatePartitionResponse.new,
  );

  /// CreatePartitionRole creates a role within a partition.
  static const createPartitionRole = connect.Spec(
    '/$name/CreatePartitionRole',
    connect.StreamType.unary,
    tenancyv1tenancy.CreatePartitionRoleRequest.new,
    tenancyv1tenancy.CreatePartitionRoleResponse.new,
  );

  /// ListPartitionRole retrieves all roles for a partition.
  static const listPartitionRole = connect.Spec(
    '/$name/ListPartitionRole',
    connect.StreamType.server,
    tenancyv1tenancy.ListPartitionRoleRequest.new,
    tenancyv1tenancy.ListPartitionRoleResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// UpdatePartitionRole updates an existing partition role.
  static const updatePartitionRole = connect.Spec(
    '/$name/UpdatePartitionRole',
    connect.StreamType.unary,
    tenancyv1tenancy.UpdatePartitionRoleRequest.new,
    tenancyv1tenancy.UpdatePartitionRoleResponse.new,
  );

  /// RemovePartitionRole deletes a partition role.
  static const removePartitionRole = connect.Spec(
    '/$name/RemovePartitionRole',
    connect.StreamType.unary,
    tenancyv1tenancy.RemovePartitionRoleRequest.new,
    tenancyv1tenancy.RemovePartitionRoleResponse.new,
  );

  /// CreatePage creates a custom UI page for a partition.
  static const createPage = connect.Spec(
    '/$name/CreatePage',
    connect.StreamType.unary,
    tenancyv1tenancy.CreatePageRequest.new,
    tenancyv1tenancy.CreatePageResponse.new,
  );

  /// ListPage retrieves all custom pages for a partition.
  static const listPage = connect.Spec(
    '/$name/ListPage',
    connect.StreamType.server,
    tenancyv1tenancy.ListPageRequest.new,
    tenancyv1tenancy.ListPageResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// GetPage retrieves a custom page.
  static const getPage = connect.Spec(
    '/$name/GetPage',
    connect.StreamType.unary,
    tenancyv1tenancy.GetPageRequest.new,
    tenancyv1tenancy.GetPageResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// UpdatePage updates an existing custom page.
  static const updatePage = connect.Spec(
    '/$name/UpdatePage',
    connect.StreamType.unary,
    tenancyv1tenancy.UpdatePageRequest.new,
    tenancyv1tenancy.UpdatePageResponse.new,
  );

  /// RemovePage deletes a custom page.
  static const removePage = connect.Spec(
    '/$name/RemovePage',
    connect.StreamType.unary,
    tenancyv1tenancy.RemovePageRequest.new,
    tenancyv1tenancy.RemovePageResponse.new,
  );

  /// CreateAccess grants a profile access to a partition.
  static const createAccess = connect.Spec(
    '/$name/CreateAccess',
    connect.StreamType.unary,
    tenancyv1tenancy.CreateAccessRequest.new,
    tenancyv1tenancy.CreateAccessResponse.new,
  );

  /// GetAccess retrieves an access grant.
  static const getAccess = connect.Spec(
    '/$name/GetAccess',
    connect.StreamType.unary,
    tenancyv1tenancy.GetAccessRequest.new,
    tenancyv1tenancy.GetAccessResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// ListAccess retrieves all access grants for a partition or profile.
  static const listAccess = connect.Spec(
    '/$name/ListAccess',
    connect.StreamType.server,
    tenancyv1tenancy.ListAccessRequest.new,
    tenancyv1tenancy.ListAccessResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// RemoveAccess revokes a profile's access to a partition.
  static const removeAccess = connect.Spec(
    '/$name/RemoveAccess',
    connect.StreamType.unary,
    tenancyv1tenancy.RemoveAccessRequest.new,
    tenancyv1tenancy.RemoveAccessResponse.new,
  );

  /// CreateAccessRole assigns a role to an access grant.
  static const createAccessRole = connect.Spec(
    '/$name/CreateAccessRole',
    connect.StreamType.unary,
    tenancyv1tenancy.CreateAccessRoleRequest.new,
    tenancyv1tenancy.CreateAccessRoleResponse.new,
  );

  /// ListAccessRole retrieves all roles for an access grant.
  static const listAccessRole = connect.Spec(
    '/$name/ListAccessRole',
    connect.StreamType.server,
    tenancyv1tenancy.ListAccessRoleRequest.new,
    tenancyv1tenancy.ListAccessRoleResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// RemoveAccessRole removes a role from an access grant.
  static const removeAccessRole = connect.Spec(
    '/$name/RemoveAccessRole',
    connect.StreamType.unary,
    tenancyv1tenancy.RemoveAccessRoleRequest.new,
    tenancyv1tenancy.RemoveAccessRoleResponse.new,
  );

  /// CreateServiceAccount registers a service account (bot) for a partition.
  static const createServiceAccount = connect.Spec(
    '/$name/CreateServiceAccount',
    connect.StreamType.unary,
    tenancyv1tenancy.CreateServiceAccountRequest.new,
    tenancyv1tenancy.CreateServiceAccountResponse.new,
  );

  /// GetServiceAccount retrieves a service account.
  static const getServiceAccount = connect.Spec(
    '/$name/GetServiceAccount',
    connect.StreamType.unary,
    tenancyv1tenancy.GetServiceAccountRequest.new,
    tenancyv1tenancy.GetServiceAccountResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// UpdateServiceAccount updates an existing service account.
  static const updateServiceAccount = connect.Spec(
    '/$name/UpdateServiceAccount',
    connect.StreamType.unary,
    tenancyv1tenancy.UpdateServiceAccountRequest.new,
    tenancyv1tenancy.UpdateServiceAccountResponse.new,
  );

  /// ListServiceAccount retrieves all service accounts for a partition.
  static const listServiceAccount = connect.Spec(
    '/$name/ListServiceAccount',
    connect.StreamType.server,
    tenancyv1tenancy.ListServiceAccountRequest.new,
    tenancyv1tenancy.ListServiceAccountResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// RemoveServiceAccount deregisters a service account.
  static const removeServiceAccount = connect.Spec(
    '/$name/RemoveServiceAccount',
    connect.StreamType.unary,
    tenancyv1tenancy.RemoveServiceAccountRequest.new,
    tenancyv1tenancy.RemoveServiceAccountResponse.new,
  );

  /// CreateClient registers an OAuth2 client for a partition or service account.
  static const createClient = connect.Spec(
    '/$name/CreateClient',
    connect.StreamType.unary,
    tenancyv1tenancy.CreateClientRequest.new,
    tenancyv1tenancy.CreateClientResponse.new,
  );

  /// GetClient retrieves an OAuth2 client by ID or client_id.
  static const getClient = connect.Spec(
    '/$name/GetClient',
    connect.StreamType.unary,
    tenancyv1tenancy.GetClientRequest.new,
    tenancyv1tenancy.GetClientResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// ListClient retrieves all OAuth2 clients for a partition or service account.
  static const listClient = connect.Spec(
    '/$name/ListClient',
    connect.StreamType.server,
    tenancyv1tenancy.ListClientRequest.new,
    tenancyv1tenancy.ListClientResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// UpdateClient updates an existing OAuth2 client.
  static const updateClient = connect.Spec(
    '/$name/UpdateClient',
    connect.StreamType.unary,
    tenancyv1tenancy.UpdateClientRequest.new,
    tenancyv1tenancy.UpdateClientResponse.new,
  );

  /// RemoveClient deletes an OAuth2 client.
  static const removeClient = connect.Spec(
    '/$name/RemoveClient',
    connect.StreamType.unary,
    tenancyv1tenancy.RemoveClientRequest.new,
    tenancyv1tenancy.RemoveClientResponse.new,
  );
}
