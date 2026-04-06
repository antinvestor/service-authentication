//
//  Generated code. Do not modify.
//  source: tenancy/v1/tenancy.proto
//
// @dart = 2.12

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_final_fields
// ignore_for_file: unnecessary_import, unnecessary_this, unused_import

import 'dart:async' as $async;
import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;

import 'tenancy.pb.dart' as $8;
import 'tenancy.pbjson.dart';

export 'tenancy.pb.dart';

abstract class TenancyServiceBase extends $pb.GeneratedService {
  $async.Future<$8.GetTenantResponse> getTenant($pb.ServerContext ctx, $8.GetTenantRequest request);
  $async.Future<$8.ListTenantResponse> listTenant($pb.ServerContext ctx, $8.ListTenantRequest request);
  $async.Future<$8.CreateTenantResponse> createTenant($pb.ServerContext ctx, $8.CreateTenantRequest request);
  $async.Future<$8.UpdateTenantResponse> updateTenant($pb.ServerContext ctx, $8.UpdateTenantRequest request);
  $async.Future<$8.RemoveTenantResponse> removeTenant($pb.ServerContext ctx, $8.RemoveTenantRequest request);
  $async.Future<$8.ListPartitionResponse> listPartition($pb.ServerContext ctx, $8.ListPartitionRequest request);
  $async.Future<$8.CreatePartitionResponse> createPartition($pb.ServerContext ctx, $8.CreatePartitionRequest request);
  $async.Future<$8.GetPartitionResponse> getPartition($pb.ServerContext ctx, $8.GetPartitionRequest request);
  $async.Future<$8.GetPartitionParentsResponse> getPartitionParents($pb.ServerContext ctx, $8.GetPartitionParentsRequest request);
  $async.Future<$8.RemovePartitionResponse> removePartition($pb.ServerContext ctx, $8.RemovePartitionRequest request);
  $async.Future<$8.UpdatePartitionResponse> updatePartition($pb.ServerContext ctx, $8.UpdatePartitionRequest request);
  $async.Future<$8.CreatePartitionRoleResponse> createPartitionRole($pb.ServerContext ctx, $8.CreatePartitionRoleRequest request);
  $async.Future<$8.ListPartitionRoleResponse> listPartitionRole($pb.ServerContext ctx, $8.ListPartitionRoleRequest request);
  $async.Future<$8.UpdatePartitionRoleResponse> updatePartitionRole($pb.ServerContext ctx, $8.UpdatePartitionRoleRequest request);
  $async.Future<$8.RemovePartitionRoleResponse> removePartitionRole($pb.ServerContext ctx, $8.RemovePartitionRoleRequest request);
  $async.Future<$8.CreatePageResponse> createPage($pb.ServerContext ctx, $8.CreatePageRequest request);
  $async.Future<$8.ListPageResponse> listPage($pb.ServerContext ctx, $8.ListPageRequest request);
  $async.Future<$8.GetPageResponse> getPage($pb.ServerContext ctx, $8.GetPageRequest request);
  $async.Future<$8.UpdatePageResponse> updatePage($pb.ServerContext ctx, $8.UpdatePageRequest request);
  $async.Future<$8.RemovePageResponse> removePage($pb.ServerContext ctx, $8.RemovePageRequest request);
  $async.Future<$8.CreateAccessResponse> createAccess($pb.ServerContext ctx, $8.CreateAccessRequest request);
  $async.Future<$8.GetAccessResponse> getAccess($pb.ServerContext ctx, $8.GetAccessRequest request);
  $async.Future<$8.ListAccessResponse> listAccess($pb.ServerContext ctx, $8.ListAccessRequest request);
  $async.Future<$8.RemoveAccessResponse> removeAccess($pb.ServerContext ctx, $8.RemoveAccessRequest request);
  $async.Future<$8.CreateAccessRoleResponse> createAccessRole($pb.ServerContext ctx, $8.CreateAccessRoleRequest request);
  $async.Future<$8.ListAccessRoleResponse> listAccessRole($pb.ServerContext ctx, $8.ListAccessRoleRequest request);
  $async.Future<$8.RemoveAccessRoleResponse> removeAccessRole($pb.ServerContext ctx, $8.RemoveAccessRoleRequest request);
  $async.Future<$8.CreateServiceAccountResponse> createServiceAccount($pb.ServerContext ctx, $8.CreateServiceAccountRequest request);
  $async.Future<$8.GetServiceAccountResponse> getServiceAccount($pb.ServerContext ctx, $8.GetServiceAccountRequest request);
  $async.Future<$8.UpdateServiceAccountResponse> updateServiceAccount($pb.ServerContext ctx, $8.UpdateServiceAccountRequest request);
  $async.Future<$8.ListServiceAccountResponse> listServiceAccount($pb.ServerContext ctx, $8.ListServiceAccountRequest request);
  $async.Future<$8.RemoveServiceAccountResponse> removeServiceAccount($pb.ServerContext ctx, $8.RemoveServiceAccountRequest request);
  $async.Future<$8.CreateClientResponse> createClient($pb.ServerContext ctx, $8.CreateClientRequest request);
  $async.Future<$8.GetClientResponse> getClient($pb.ServerContext ctx, $8.GetClientRequest request);
  $async.Future<$8.ListClientResponse> listClient($pb.ServerContext ctx, $8.ListClientRequest request);
  $async.Future<$8.UpdateClientResponse> updateClient($pb.ServerContext ctx, $8.UpdateClientRequest request);
  $async.Future<$8.RemoveClientResponse> removeClient($pb.ServerContext ctx, $8.RemoveClientRequest request);
  $async.Future<$8.ListServiceNamespacesResponse> listServiceNamespaces($pb.ServerContext ctx, $8.ListServiceNamespacesRequest request);
  $async.Future<$8.GrantPermissionResponse> grantPermission($pb.ServerContext ctx, $8.GrantPermissionRequest request);
  $async.Future<$8.RevokePermissionResponse> revokePermission($pb.ServerContext ctx, $8.RevokePermissionRequest request);

  $pb.GeneratedMessage createRequest($core.String methodName) {
    switch (methodName) {
      case 'GetTenant': return $8.GetTenantRequest();
      case 'ListTenant': return $8.ListTenantRequest();
      case 'CreateTenant': return $8.CreateTenantRequest();
      case 'UpdateTenant': return $8.UpdateTenantRequest();
      case 'RemoveTenant': return $8.RemoveTenantRequest();
      case 'ListPartition': return $8.ListPartitionRequest();
      case 'CreatePartition': return $8.CreatePartitionRequest();
      case 'GetPartition': return $8.GetPartitionRequest();
      case 'GetPartitionParents': return $8.GetPartitionParentsRequest();
      case 'RemovePartition': return $8.RemovePartitionRequest();
      case 'UpdatePartition': return $8.UpdatePartitionRequest();
      case 'CreatePartitionRole': return $8.CreatePartitionRoleRequest();
      case 'ListPartitionRole': return $8.ListPartitionRoleRequest();
      case 'UpdatePartitionRole': return $8.UpdatePartitionRoleRequest();
      case 'RemovePartitionRole': return $8.RemovePartitionRoleRequest();
      case 'CreatePage': return $8.CreatePageRequest();
      case 'ListPage': return $8.ListPageRequest();
      case 'GetPage': return $8.GetPageRequest();
      case 'UpdatePage': return $8.UpdatePageRequest();
      case 'RemovePage': return $8.RemovePageRequest();
      case 'CreateAccess': return $8.CreateAccessRequest();
      case 'GetAccess': return $8.GetAccessRequest();
      case 'ListAccess': return $8.ListAccessRequest();
      case 'RemoveAccess': return $8.RemoveAccessRequest();
      case 'CreateAccessRole': return $8.CreateAccessRoleRequest();
      case 'ListAccessRole': return $8.ListAccessRoleRequest();
      case 'RemoveAccessRole': return $8.RemoveAccessRoleRequest();
      case 'CreateServiceAccount': return $8.CreateServiceAccountRequest();
      case 'GetServiceAccount': return $8.GetServiceAccountRequest();
      case 'UpdateServiceAccount': return $8.UpdateServiceAccountRequest();
      case 'ListServiceAccount': return $8.ListServiceAccountRequest();
      case 'RemoveServiceAccount': return $8.RemoveServiceAccountRequest();
      case 'CreateClient': return $8.CreateClientRequest();
      case 'GetClient': return $8.GetClientRequest();
      case 'ListClient': return $8.ListClientRequest();
      case 'UpdateClient': return $8.UpdateClientRequest();
      case 'RemoveClient': return $8.RemoveClientRequest();
      case 'ListServiceNamespaces': return $8.ListServiceNamespacesRequest();
      case 'GrantPermission': return $8.GrantPermissionRequest();
      case 'RevokePermission': return $8.RevokePermissionRequest();
      default: throw $core.ArgumentError('Unknown method: $methodName');
    }
  }

  $async.Future<$pb.GeneratedMessage> handleCall($pb.ServerContext ctx, $core.String methodName, $pb.GeneratedMessage request) {
    switch (methodName) {
      case 'GetTenant': return this.getTenant(ctx, request as $8.GetTenantRequest);
      case 'ListTenant': return this.listTenant(ctx, request as $8.ListTenantRequest);
      case 'CreateTenant': return this.createTenant(ctx, request as $8.CreateTenantRequest);
      case 'UpdateTenant': return this.updateTenant(ctx, request as $8.UpdateTenantRequest);
      case 'RemoveTenant': return this.removeTenant(ctx, request as $8.RemoveTenantRequest);
      case 'ListPartition': return this.listPartition(ctx, request as $8.ListPartitionRequest);
      case 'CreatePartition': return this.createPartition(ctx, request as $8.CreatePartitionRequest);
      case 'GetPartition': return this.getPartition(ctx, request as $8.GetPartitionRequest);
      case 'GetPartitionParents': return this.getPartitionParents(ctx, request as $8.GetPartitionParentsRequest);
      case 'RemovePartition': return this.removePartition(ctx, request as $8.RemovePartitionRequest);
      case 'UpdatePartition': return this.updatePartition(ctx, request as $8.UpdatePartitionRequest);
      case 'CreatePartitionRole': return this.createPartitionRole(ctx, request as $8.CreatePartitionRoleRequest);
      case 'ListPartitionRole': return this.listPartitionRole(ctx, request as $8.ListPartitionRoleRequest);
      case 'UpdatePartitionRole': return this.updatePartitionRole(ctx, request as $8.UpdatePartitionRoleRequest);
      case 'RemovePartitionRole': return this.removePartitionRole(ctx, request as $8.RemovePartitionRoleRequest);
      case 'CreatePage': return this.createPage(ctx, request as $8.CreatePageRequest);
      case 'ListPage': return this.listPage(ctx, request as $8.ListPageRequest);
      case 'GetPage': return this.getPage(ctx, request as $8.GetPageRequest);
      case 'UpdatePage': return this.updatePage(ctx, request as $8.UpdatePageRequest);
      case 'RemovePage': return this.removePage(ctx, request as $8.RemovePageRequest);
      case 'CreateAccess': return this.createAccess(ctx, request as $8.CreateAccessRequest);
      case 'GetAccess': return this.getAccess(ctx, request as $8.GetAccessRequest);
      case 'ListAccess': return this.listAccess(ctx, request as $8.ListAccessRequest);
      case 'RemoveAccess': return this.removeAccess(ctx, request as $8.RemoveAccessRequest);
      case 'CreateAccessRole': return this.createAccessRole(ctx, request as $8.CreateAccessRoleRequest);
      case 'ListAccessRole': return this.listAccessRole(ctx, request as $8.ListAccessRoleRequest);
      case 'RemoveAccessRole': return this.removeAccessRole(ctx, request as $8.RemoveAccessRoleRequest);
      case 'CreateServiceAccount': return this.createServiceAccount(ctx, request as $8.CreateServiceAccountRequest);
      case 'GetServiceAccount': return this.getServiceAccount(ctx, request as $8.GetServiceAccountRequest);
      case 'UpdateServiceAccount': return this.updateServiceAccount(ctx, request as $8.UpdateServiceAccountRequest);
      case 'ListServiceAccount': return this.listServiceAccount(ctx, request as $8.ListServiceAccountRequest);
      case 'RemoveServiceAccount': return this.removeServiceAccount(ctx, request as $8.RemoveServiceAccountRequest);
      case 'CreateClient': return this.createClient(ctx, request as $8.CreateClientRequest);
      case 'GetClient': return this.getClient(ctx, request as $8.GetClientRequest);
      case 'ListClient': return this.listClient(ctx, request as $8.ListClientRequest);
      case 'UpdateClient': return this.updateClient(ctx, request as $8.UpdateClientRequest);
      case 'RemoveClient': return this.removeClient(ctx, request as $8.RemoveClientRequest);
      case 'ListServiceNamespaces': return this.listServiceNamespaces(ctx, request as $8.ListServiceNamespacesRequest);
      case 'GrantPermission': return this.grantPermission(ctx, request as $8.GrantPermissionRequest);
      case 'RevokePermission': return this.revokePermission(ctx, request as $8.RevokePermissionRequest);
      default: throw $core.ArgumentError('Unknown method: $methodName');
    }
  }

  $core.Map<$core.String, $core.dynamic> get $json => TenancyServiceBase$json;
  $core.Map<$core.String, $core.Map<$core.String, $core.dynamic>> get $messageJson => TenancyServiceBase$messageJson;
}

