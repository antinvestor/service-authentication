//
//  Generated code. Do not modify.
//  source: audit/v1/audit.proto
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

import 'audit.pb.dart' as $7;
import 'audit.pbjson.dart';

export 'audit.pb.dart';

abstract class AuditServiceBase extends $pb.GeneratedService {
  $async.Future<$7.CreateAuditEntryResponse> createAuditEntry($pb.ServerContext ctx, $7.CreateAuditEntryRequest request);
  $async.Future<$7.BatchCreateAuditEntriesResponse> batchCreateAuditEntries($pb.ServerContext ctx, $7.BatchCreateAuditEntriesRequest request);
  $async.Future<$7.GetAuditEntryResponse> getAuditEntry($pb.ServerContext ctx, $7.GetAuditEntryRequest request);
  $async.Future<$7.ListAuditEntriesResponse> listAuditEntries($pb.ServerContext ctx, $7.ListAuditEntriesRequest request);
  $async.Future<$7.SearchAuditEntriesResponse> searchAuditEntries($pb.ServerContext ctx, $7.SearchAuditEntriesRequest request);
  $async.Future<$7.VerifyIntegrityResponse> verifyIntegrity($pb.ServerContext ctx, $7.VerifyIntegrityRequest request);

  $pb.GeneratedMessage createRequest($core.String methodName) {
    switch (methodName) {
      case 'CreateAuditEntry': return $7.CreateAuditEntryRequest();
      case 'BatchCreateAuditEntries': return $7.BatchCreateAuditEntriesRequest();
      case 'GetAuditEntry': return $7.GetAuditEntryRequest();
      case 'ListAuditEntries': return $7.ListAuditEntriesRequest();
      case 'SearchAuditEntries': return $7.SearchAuditEntriesRequest();
      case 'VerifyIntegrity': return $7.VerifyIntegrityRequest();
      default: throw $core.ArgumentError('Unknown method: $methodName');
    }
  }

  $async.Future<$pb.GeneratedMessage> handleCall($pb.ServerContext ctx, $core.String methodName, $pb.GeneratedMessage request) {
    switch (methodName) {
      case 'CreateAuditEntry': return this.createAuditEntry(ctx, request as $7.CreateAuditEntryRequest);
      case 'BatchCreateAuditEntries': return this.batchCreateAuditEntries(ctx, request as $7.BatchCreateAuditEntriesRequest);
      case 'GetAuditEntry': return this.getAuditEntry(ctx, request as $7.GetAuditEntryRequest);
      case 'ListAuditEntries': return this.listAuditEntries(ctx, request as $7.ListAuditEntriesRequest);
      case 'SearchAuditEntries': return this.searchAuditEntries(ctx, request as $7.SearchAuditEntriesRequest);
      case 'VerifyIntegrity': return this.verifyIntegrity(ctx, request as $7.VerifyIntegrityRequest);
      default: throw $core.ArgumentError('Unknown method: $methodName');
    }
  }

  $core.Map<$core.String, $core.dynamic> get $json => AuditServiceBase$json;
  $core.Map<$core.String, $core.Map<$core.String, $core.dynamic>> get $messageJson => AuditServiceBase$messageJson;
}

