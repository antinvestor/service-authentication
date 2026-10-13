// This is a generated file - do not edit.
//
// Generated from audit/v1/audit.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports

import 'dart:async' as $async;
import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;

import 'audit.pb.dart' as $2;
import 'audit.pbjson.dart';

export 'audit.pb.dart';

abstract class AuditServiceBase extends $pb.GeneratedService {
  $async.Future<$2.CreateAuditEntryResponse> createAuditEntry(
      $pb.ServerContext ctx, $2.CreateAuditEntryRequest request);
  $async.Future<$2.BatchCreateAuditEntriesResponse> batchCreateAuditEntries(
      $pb.ServerContext ctx, $2.BatchCreateAuditEntriesRequest request);
  $async.Future<$2.GetAuditEntryResponse> getAuditEntry(
      $pb.ServerContext ctx, $2.GetAuditEntryRequest request);
  $async.Future<$2.ListAuditEntriesResponse> listAuditEntries(
      $pb.ServerContext ctx, $2.ListAuditEntriesRequest request);
  $async.Future<$2.SearchAuditEntriesResponse> searchAuditEntries(
      $pb.ServerContext ctx, $2.SearchAuditEntriesRequest request);
  $async.Future<$2.VerifyIntegrityResponse> verifyIntegrity(
      $pb.ServerContext ctx, $2.VerifyIntegrityRequest request);
  $async.Future<$2.ExportAuditEntriesResponse> exportAuditEntries(
      $pb.ServerContext ctx, $2.ExportAuditEntriesRequest request);
  $async.Future<$2.ListCheckpointsResponse> listCheckpoints(
      $pb.ServerContext ctx, $2.ListCheckpointsRequest request);
  $async.Future<$2.GetSigningKeysResponse> getSigningKeys(
      $pb.ServerContext ctx, $2.GetSigningKeysRequest request);
  $async.Future<$2.RegisterAuditManifestResponse> registerAuditManifest(
      $pb.ServerContext ctx, $2.RegisterAuditManifestRequest request);
  $async.Future<$2.GetAuditManifestResponse> getAuditManifest(
      $pb.ServerContext ctx, $2.GetAuditManifestRequest request);
  $async.Future<$2.RequeueIntakeResponse> requeueIntake(
      $pb.ServerContext ctx, $2.RequeueIntakeRequest request);
  $async.Future<$2.RetireSigningKeyResponse> retireSigningKey(
      $pb.ServerContext ctx, $2.RetireSigningKeyRequest request);

  $pb.GeneratedMessage createRequest($core.String methodName) {
    switch (methodName) {
      case 'CreateAuditEntry':
        return $2.CreateAuditEntryRequest();
      case 'BatchCreateAuditEntries':
        return $2.BatchCreateAuditEntriesRequest();
      case 'GetAuditEntry':
        return $2.GetAuditEntryRequest();
      case 'ListAuditEntries':
        return $2.ListAuditEntriesRequest();
      case 'SearchAuditEntries':
        return $2.SearchAuditEntriesRequest();
      case 'VerifyIntegrity':
        return $2.VerifyIntegrityRequest();
      case 'ExportAuditEntries':
        return $2.ExportAuditEntriesRequest();
      case 'ListCheckpoints':
        return $2.ListCheckpointsRequest();
      case 'GetSigningKeys':
        return $2.GetSigningKeysRequest();
      case 'RegisterAuditManifest':
        return $2.RegisterAuditManifestRequest();
      case 'GetAuditManifest':
        return $2.GetAuditManifestRequest();
      case 'RequeueIntake':
        return $2.RequeueIntakeRequest();
      case 'RetireSigningKey':
        return $2.RetireSigningKeyRequest();
      default:
        throw $core.ArgumentError('Unknown method: $methodName');
    }
  }

  $async.Future<$pb.GeneratedMessage> handleCall($pb.ServerContext ctx,
      $core.String methodName, $pb.GeneratedMessage request) {
    switch (methodName) {
      case 'CreateAuditEntry':
        return createAuditEntry(ctx, request as $2.CreateAuditEntryRequest);
      case 'BatchCreateAuditEntries':
        return batchCreateAuditEntries(
            ctx, request as $2.BatchCreateAuditEntriesRequest);
      case 'GetAuditEntry':
        return getAuditEntry(ctx, request as $2.GetAuditEntryRequest);
      case 'ListAuditEntries':
        return listAuditEntries(ctx, request as $2.ListAuditEntriesRequest);
      case 'SearchAuditEntries':
        return searchAuditEntries(ctx, request as $2.SearchAuditEntriesRequest);
      case 'VerifyIntegrity':
        return verifyIntegrity(ctx, request as $2.VerifyIntegrityRequest);
      case 'ExportAuditEntries':
        return exportAuditEntries(ctx, request as $2.ExportAuditEntriesRequest);
      case 'ListCheckpoints':
        return listCheckpoints(ctx, request as $2.ListCheckpointsRequest);
      case 'GetSigningKeys':
        return getSigningKeys(ctx, request as $2.GetSigningKeysRequest);
      case 'RegisterAuditManifest':
        return registerAuditManifest(
            ctx, request as $2.RegisterAuditManifestRequest);
      case 'GetAuditManifest':
        return getAuditManifest(ctx, request as $2.GetAuditManifestRequest);
      case 'RequeueIntake':
        return requeueIntake(ctx, request as $2.RequeueIntakeRequest);
      case 'RetireSigningKey':
        return retireSigningKey(ctx, request as $2.RetireSigningKeyRequest);
      default:
        throw $core.ArgumentError('Unknown method: $methodName');
    }
  }

  $core.Map<$core.String, $core.dynamic> get $json => AuditServiceBase$json;
  $core.Map<$core.String, $core.Map<$core.String, $core.dynamic>>
      get $messageJson => AuditServiceBase$messageJson;
}
