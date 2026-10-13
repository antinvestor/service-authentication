// This is a generated file - do not edit.
//
// Generated from authentication/v1/authentication.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports

import 'dart:async' as $async;
import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;

import 'authentication.pb.dart' as $2;
import 'authentication.pbjson.dart';

export 'authentication.pb.dart';

abstract class AuthenticationServiceBase extends $pb.GeneratedService {
  $async.Future<$2.GetLoginEventResponse> getLoginEvent(
      $pb.ServerContext ctx, $2.GetLoginEventRequest request);
  $async.Future<$2.ListLoginEventsResponse> listLoginEvents(
      $pb.ServerContext ctx, $2.ListLoginEventsRequest request);
  $async.Future<$2.IssueGenesisSessionProofResponse> issueGenesisSessionProof(
      $pb.ServerContext ctx, $2.IssueGenesisSessionProofRequest request);
  $async.Future<$2.VerifyGenesisSessionProofResponse> verifyGenesisSessionProof(
      $pb.ServerContext ctx, $2.VerifyGenesisSessionProofRequest request);

  $pb.GeneratedMessage createRequest($core.String methodName) {
    switch (methodName) {
      case 'GetLoginEvent':
        return $2.GetLoginEventRequest();
      case 'ListLoginEvents':
        return $2.ListLoginEventsRequest();
      case 'IssueGenesisSessionProof':
        return $2.IssueGenesisSessionProofRequest();
      case 'VerifyGenesisSessionProof':
        return $2.VerifyGenesisSessionProofRequest();
      default:
        throw $core.ArgumentError('Unknown method: $methodName');
    }
  }

  $async.Future<$pb.GeneratedMessage> handleCall($pb.ServerContext ctx,
      $core.String methodName, $pb.GeneratedMessage request) {
    switch (methodName) {
      case 'GetLoginEvent':
        return getLoginEvent(ctx, request as $2.GetLoginEventRequest);
      case 'ListLoginEvents':
        return listLoginEvents(ctx, request as $2.ListLoginEventsRequest);
      case 'IssueGenesisSessionProof':
        return issueGenesisSessionProof(
            ctx, request as $2.IssueGenesisSessionProofRequest);
      case 'VerifyGenesisSessionProof':
        return verifyGenesisSessionProof(
            ctx, request as $2.VerifyGenesisSessionProofRequest);
      default:
        throw $core.ArgumentError('Unknown method: $methodName');
    }
  }

  $core.Map<$core.String, $core.dynamic> get $json =>
      AuthenticationServiceBase$json;
  $core.Map<$core.String, $core.Map<$core.String, $core.dynamic>>
      get $messageJson => AuthenticationServiceBase$messageJson;
}
