//
//  Generated code. Do not modify.
//  source: authentication/v1/authentication.proto
//
// @dart = 2.12

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_final_fields
// ignore_for_file: unnecessary_import, unnecessary_this, unused_import

import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;

/// LoginSource identifies how a user authenticated.
class LoginSource extends $pb.ProtobufEnum {
  static const LoginSource LOGIN_SOURCE_UNSPECIFIED = LoginSource._(0, _omitEnumNames ? '' : 'LOGIN_SOURCE_UNSPECIFIED');
  static const LoginSource LOGIN_SOURCE_DIRECT = LoginSource._(1, _omitEnumNames ? '' : 'LOGIN_SOURCE_DIRECT');
  static const LoginSource LOGIN_SOURCE_GOOGLE = LoginSource._(2, _omitEnumNames ? '' : 'LOGIN_SOURCE_GOOGLE');
  static const LoginSource LOGIN_SOURCE_FACEBOOK = LoginSource._(3, _omitEnumNames ? '' : 'LOGIN_SOURCE_FACEBOOK');
  static const LoginSource LOGIN_SOURCE_SERVICE_ACCOUNT = LoginSource._(4, _omitEnumNames ? '' : 'LOGIN_SOURCE_SERVICE_ACCOUNT');
  static const LoginSource LOGIN_SOURCE_SESSION_REFRESH = LoginSource._(5, _omitEnumNames ? '' : 'LOGIN_SOURCE_SESSION_REFRESH');

  static const $core.List<LoginSource> values = <LoginSource> [
    LOGIN_SOURCE_UNSPECIFIED,
    LOGIN_SOURCE_DIRECT,
    LOGIN_SOURCE_GOOGLE,
    LOGIN_SOURCE_FACEBOOK,
    LOGIN_SOURCE_SERVICE_ACCOUNT,
    LOGIN_SOURCE_SESSION_REFRESH,
  ];

  static final $core.Map<$core.int, LoginSource> _byValue = $pb.ProtobufEnum.initByValue(values);
  static LoginSource? valueOf($core.int value) => _byValue[value];

  const LoginSource._($core.int v, $core.String n) : super(v, n);
}


const _omitEnumNames = $core.bool.fromEnvironment('protobuf.omit_enum_names');
