//
//  Generated code. Do not modify.
//  source: tenancy/v2/auth_contract.proto
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

import 'auth_contract.pb.dart' as $9;
import 'auth_contract.pbjson.dart';

export 'auth_contract.pb.dart';

abstract class AuthContractServiceBase extends $pb.GeneratedService {
  $async.Future<$9.CreateOAuthClientResponse> createOAuthClient(
      $pb.ServerContext ctx, $9.CreateOAuthClientRequest request);
  $async.Future<$9.GetOAuthClientResponse> getOAuthClient(
      $pb.ServerContext ctx, $9.GetOAuthClientRequest request);
  $async.Future<$9.ListOAuthClientsResponse> listOAuthClients(
      $pb.ServerContext ctx, $9.ListOAuthClientsRequest request);
  $async.Future<$9.UpdateOAuthClientResponse> updateOAuthClient(
      $pb.ServerContext ctx, $9.UpdateOAuthClientRequest request);
  $async.Future<$9.RemoveOAuthClientResponse> removeOAuthClient(
      $pb.ServerContext ctx, $9.RemoveOAuthClientRequest request);
  $async.Future<$9.CreateServiceAccountResponse> createServiceAccount(
      $pb.ServerContext ctx, $9.CreateServiceAccountRequest request);
  $async.Future<$9.GetServiceAccountResponse> getServiceAccount(
      $pb.ServerContext ctx, $9.GetServiceAccountRequest request);
  $async.Future<$9.ListServiceAccountsResponse> listServiceAccounts(
      $pb.ServerContext ctx, $9.ListServiceAccountsRequest request);
  $async.Future<$9.UpdateServiceAccountResponse> updateServiceAccount(
      $pb.ServerContext ctx, $9.UpdateServiceAccountRequest request);
  $async.Future<$9.RemoveServiceAccountResponse> removeServiceAccount(
      $pb.ServerContext ctx, $9.RemoveServiceAccountRequest request);
  $async.Future<$9.ReconcileServiceAccountAuthorizationResponse>
      reconcileServiceAccountAuthorization($pb.ServerContext ctx,
          $9.ReconcileServiceAccountAuthorizationRequest request);

  $pb.GeneratedMessage createRequest($core.String methodName) {
    switch (methodName) {
      case 'CreateOAuthClient':
        return $9.CreateOAuthClientRequest();
      case 'GetOAuthClient':
        return $9.GetOAuthClientRequest();
      case 'ListOAuthClients':
        return $9.ListOAuthClientsRequest();
      case 'UpdateOAuthClient':
        return $9.UpdateOAuthClientRequest();
      case 'RemoveOAuthClient':
        return $9.RemoveOAuthClientRequest();
      case 'CreateServiceAccount':
        return $9.CreateServiceAccountRequest();
      case 'GetServiceAccount':
        return $9.GetServiceAccountRequest();
      case 'ListServiceAccounts':
        return $9.ListServiceAccountsRequest();
      case 'UpdateServiceAccount':
        return $9.UpdateServiceAccountRequest();
      case 'RemoveServiceAccount':
        return $9.RemoveServiceAccountRequest();
      case 'ReconcileServiceAccountAuthorization':
        return $9.ReconcileServiceAccountAuthorizationRequest();
      default:
        throw $core.ArgumentError('Unknown method: $methodName');
    }
  }

  $async.Future<$pb.GeneratedMessage> handleCall($pb.ServerContext ctx,
      $core.String methodName, $pb.GeneratedMessage request) {
    switch (methodName) {
      case 'CreateOAuthClient':
        return this
            .createOAuthClient(ctx, request as $9.CreateOAuthClientRequest);
      case 'GetOAuthClient':
        return this.getOAuthClient(ctx, request as $9.GetOAuthClientRequest);
      case 'ListOAuthClients':
        return this
            .listOAuthClients(ctx, request as $9.ListOAuthClientsRequest);
      case 'UpdateOAuthClient':
        return this
            .updateOAuthClient(ctx, request as $9.UpdateOAuthClientRequest);
      case 'RemoveOAuthClient':
        return this
            .removeOAuthClient(ctx, request as $9.RemoveOAuthClientRequest);
      case 'CreateServiceAccount':
        return this.createServiceAccount(
            ctx, request as $9.CreateServiceAccountRequest);
      case 'GetServiceAccount':
        return this
            .getServiceAccount(ctx, request as $9.GetServiceAccountRequest);
      case 'ListServiceAccounts':
        return this
            .listServiceAccounts(ctx, request as $9.ListServiceAccountsRequest);
      case 'UpdateServiceAccount':
        return this.updateServiceAccount(
            ctx, request as $9.UpdateServiceAccountRequest);
      case 'RemoveServiceAccount':
        return this.removeServiceAccount(
            ctx, request as $9.RemoveServiceAccountRequest);
      case 'ReconcileServiceAccountAuthorization':
        return this.reconcileServiceAccountAuthorization(
            ctx, request as $9.ReconcileServiceAccountAuthorizationRequest);
      default:
        throw $core.ArgumentError('Unknown method: $methodName');
    }
  }

  $core.Map<$core.String, $core.dynamic> get $json =>
      AuthContractServiceBase$json;
  $core.Map<$core.String, $core.Map<$core.String, $core.dynamic>>
      get $messageJson => AuthContractServiceBase$messageJson;
}
