//
//  Generated code. Do not modify.
//  source: tenancy/v2/auth_contract.proto
//
// @dart = 2.12

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_final_fields
// ignore_for_file: unnecessary_import, unnecessary_this, unused_import

import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;

class AuthorizationScope extends $pb.ProtobufEnum {
  static const AuthorizationScope AUTHORIZATION_SCOPE_UNSPECIFIED =
      AuthorizationScope._(
          0, _omitEnumNames ? '' : 'AUTHORIZATION_SCOPE_UNSPECIFIED');
  static const AuthorizationScope AUTHORIZATION_SCOPE_PARTITION_ONLY =
      AuthorizationScope._(
          1, _omitEnumNames ? '' : 'AUTHORIZATION_SCOPE_PARTITION_ONLY');
  static const AuthorizationScope AUTHORIZATION_SCOPE_PARTITION_TREE =
      AuthorizationScope._(
          2, _omitEnumNames ? '' : 'AUTHORIZATION_SCOPE_PARTITION_TREE');

  static const $core.List<AuthorizationScope> values = <AuthorizationScope>[
    AUTHORIZATION_SCOPE_UNSPECIFIED,
    AUTHORIZATION_SCOPE_PARTITION_ONLY,
    AUTHORIZATION_SCOPE_PARTITION_TREE,
  ];

  static final $core.Map<$core.int, AuthorizationScope> _byValue =
      $pb.ProtobufEnum.initByValue(values);
  static AuthorizationScope? valueOf($core.int value) => _byValue[value];

  const AuthorizationScope._($core.int v, $core.String n) : super(v, n);
}

class AuthorizationPolicyStatus extends $pb.ProtobufEnum {
  static const AuthorizationPolicyStatus
      AUTHORIZATION_POLICY_STATUS_UNSPECIFIED = AuthorizationPolicyStatus._(
          0, _omitEnumNames ? '' : 'AUTHORIZATION_POLICY_STATUS_UNSPECIFIED');
  static const AuthorizationPolicyStatus AUTHORIZATION_POLICY_STATUS_PENDING =
      AuthorizationPolicyStatus._(
          1, _omitEnumNames ? '' : 'AUTHORIZATION_POLICY_STATUS_PENDING');
  static const AuthorizationPolicyStatus AUTHORIZATION_POLICY_STATUS_APPLIED =
      AuthorizationPolicyStatus._(
          2, _omitEnumNames ? '' : 'AUTHORIZATION_POLICY_STATUS_APPLIED');
  static const AuthorizationPolicyStatus AUTHORIZATION_POLICY_STATUS_FAILED =
      AuthorizationPolicyStatus._(
          3, _omitEnumNames ? '' : 'AUTHORIZATION_POLICY_STATUS_FAILED');

  static const $core.List<AuthorizationPolicyStatus> values =
      <AuthorizationPolicyStatus>[
    AUTHORIZATION_POLICY_STATUS_UNSPECIFIED,
    AUTHORIZATION_POLICY_STATUS_PENDING,
    AUTHORIZATION_POLICY_STATUS_APPLIED,
    AUTHORIZATION_POLICY_STATUS_FAILED,
  ];

  static final $core.Map<$core.int, AuthorizationPolicyStatus> _byValue =
      $pb.ProtobufEnum.initByValue(values);
  static AuthorizationPolicyStatus? valueOf($core.int value) => _byValue[value];

  const AuthorizationPolicyStatus._($core.int v, $core.String n) : super(v, n);
}

const _omitEnumNames = $core.bool.fromEnvironment('protobuf.omit_enum_names');
