// This is a generated file - do not edit.
//
// Generated from tenancy/v2/auth_contract.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports

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

  static final $core.List<AuthorizationScope?> _byValue =
      $pb.ProtobufEnum.$_initByValueList(values, 2);
  static AuthorizationScope? valueOf($core.int value) =>
      value < 0 || value >= _byValue.length ? null : _byValue[value];

  const AuthorizationScope._(super.value, super.name);
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

  static final $core.List<AuthorizationPolicyStatus?> _byValue =
      $pb.ProtobufEnum.$_initByValueList(values, 3);
  static AuthorizationPolicyStatus? valueOf($core.int value) =>
      value < 0 || value >= _byValue.length ? null : _byValue[value];

  const AuthorizationPolicyStatus._(super.value, super.name);
}

const $core.bool _omitEnumNames =
    $core.bool.fromEnvironment('protobuf.omit_enum_names');
