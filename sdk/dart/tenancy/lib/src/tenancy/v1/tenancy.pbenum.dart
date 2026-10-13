// This is a generated file - do not edit.
//
// Generated from tenancy/v1/tenancy.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports

import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;

/// TenantEnvironment identifies the deployment environment a tenant belongs to.
class TenantEnvironment extends $pb.ProtobufEnum {
  static const TenantEnvironment TENANT_ENVIRONMENT_UNSPECIFIED =
      TenantEnvironment._(
          0, _omitEnumNames ? '' : 'TENANT_ENVIRONMENT_UNSPECIFIED');
  static const TenantEnvironment TENANT_ENVIRONMENT_PRODUCTION =
      TenantEnvironment._(
          1, _omitEnumNames ? '' : 'TENANT_ENVIRONMENT_PRODUCTION');
  static const TenantEnvironment TENANT_ENVIRONMENT_STAGING =
      TenantEnvironment._(
          2, _omitEnumNames ? '' : 'TENANT_ENVIRONMENT_STAGING');

  static const $core.List<TenantEnvironment> values = <TenantEnvironment>[
    TENANT_ENVIRONMENT_UNSPECIFIED,
    TENANT_ENVIRONMENT_PRODUCTION,
    TENANT_ENVIRONMENT_STAGING,
  ];

  static final $core.List<TenantEnvironment?> _byValue =
      $pb.ProtobufEnum.$_initByValueList(values, 2);
  static TenantEnvironment? valueOf($core.int value) =>
      value < 0 || value >= _byValue.length ? null : _byValue[value];

  const TenantEnvironment._(super.value, super.name);
}

const $core.bool _omitEnumNames =
    $core.bool.fromEnvironment('protobuf.omit_enum_names');
