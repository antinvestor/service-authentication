// This is a generated file - do not edit.
//
// Generated from tenancy/v2/auth_contract.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports

import 'dart:async' as $async;
import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;

import 'auth_contract.pb.dart' as $4;
import 'auth_contract.pbjson.dart';

export 'auth_contract.pb.dart';

abstract class AuthContractServiceBase extends $pb.GeneratedService {
  $async.Future<$4.CreateOAuthClientResponse> createOAuthClient(
      $pb.ServerContext ctx, $4.CreateOAuthClientRequest request);
  $async.Future<$4.GetOAuthClientResponse> getOAuthClient(
      $pb.ServerContext ctx, $4.GetOAuthClientRequest request);
  $async.Future<$4.ListOAuthClientsResponse> listOAuthClients(
      $pb.ServerContext ctx, $4.ListOAuthClientsRequest request);
  $async.Future<$4.UpdateOAuthClientResponse> updateOAuthClient(
      $pb.ServerContext ctx, $4.UpdateOAuthClientRequest request);
  $async.Future<$4.RemoveOAuthClientResponse> removeOAuthClient(
      $pb.ServerContext ctx, $4.RemoveOAuthClientRequest request);
  $async.Future<$4.CreateServiceAccountResponse> createServiceAccount(
      $pb.ServerContext ctx, $4.CreateServiceAccountRequest request);
  $async.Future<$4.GetServiceAccountResponse> getServiceAccount(
      $pb.ServerContext ctx, $4.GetServiceAccountRequest request);
  $async.Future<$4.ListServiceAccountsResponse> listServiceAccounts(
      $pb.ServerContext ctx, $4.ListServiceAccountsRequest request);
  $async.Future<$4.UpdateServiceAccountResponse> updateServiceAccount(
      $pb.ServerContext ctx, $4.UpdateServiceAccountRequest request);
  $async.Future<$4.RemoveServiceAccountResponse> removeServiceAccount(
      $pb.ServerContext ctx, $4.RemoveServiceAccountRequest request);
  $async.Future<$4.ReconcileServiceAccountAuthorizationResponse>
      reconcileServiceAccountAuthorization($pb.ServerContext ctx,
          $4.ReconcileServiceAccountAuthorizationRequest request);

  $pb.GeneratedMessage createRequest($core.String methodName) {
    switch (methodName) {
      case 'CreateOAuthClient':
        return $4.CreateOAuthClientRequest();
      case 'GetOAuthClient':
        return $4.GetOAuthClientRequest();
      case 'ListOAuthClients':
        return $4.ListOAuthClientsRequest();
      case 'UpdateOAuthClient':
        return $4.UpdateOAuthClientRequest();
      case 'RemoveOAuthClient':
        return $4.RemoveOAuthClientRequest();
      case 'CreateServiceAccount':
        return $4.CreateServiceAccountRequest();
      case 'GetServiceAccount':
        return $4.GetServiceAccountRequest();
      case 'ListServiceAccounts':
        return $4.ListServiceAccountsRequest();
      case 'UpdateServiceAccount':
        return $4.UpdateServiceAccountRequest();
      case 'RemoveServiceAccount':
        return $4.RemoveServiceAccountRequest();
      case 'ReconcileServiceAccountAuthorization':
        return $4.ReconcileServiceAccountAuthorizationRequest();
      default:
        throw $core.ArgumentError('Unknown method: $methodName');
    }
  }

  $async.Future<$pb.GeneratedMessage> handleCall($pb.ServerContext ctx,
      $core.String methodName, $pb.GeneratedMessage request) {
    switch (methodName) {
      case 'CreateOAuthClient':
        return createOAuthClient(ctx, request as $4.CreateOAuthClientRequest);
      case 'GetOAuthClient':
        return getOAuthClient(ctx, request as $4.GetOAuthClientRequest);
      case 'ListOAuthClients':
        return listOAuthClients(ctx, request as $4.ListOAuthClientsRequest);
      case 'UpdateOAuthClient':
        return updateOAuthClient(ctx, request as $4.UpdateOAuthClientRequest);
      case 'RemoveOAuthClient':
        return removeOAuthClient(ctx, request as $4.RemoveOAuthClientRequest);
      case 'CreateServiceAccount':
        return createServiceAccount(
            ctx, request as $4.CreateServiceAccountRequest);
      case 'GetServiceAccount':
        return getServiceAccount(ctx, request as $4.GetServiceAccountRequest);
      case 'ListServiceAccounts':
        return listServiceAccounts(
            ctx, request as $4.ListServiceAccountsRequest);
      case 'UpdateServiceAccount':
        return updateServiceAccount(
            ctx, request as $4.UpdateServiceAccountRequest);
      case 'RemoveServiceAccount':
        return removeServiceAccount(
            ctx, request as $4.RemoveServiceAccountRequest);
      case 'ReconcileServiceAccountAuthorization':
        return reconcileServiceAccountAuthorization(
            ctx, request as $4.ReconcileServiceAccountAuthorizationRequest);
      default:
        throw $core.ArgumentError('Unknown method: $methodName');
    }
  }

  $core.Map<$core.String, $core.dynamic> get $json =>
      AuthContractServiceBase$json;
  $core.Map<$core.String, $core.Map<$core.String, $core.dynamic>>
      get $messageJson => AuthContractServiceBase$messageJson;
}
