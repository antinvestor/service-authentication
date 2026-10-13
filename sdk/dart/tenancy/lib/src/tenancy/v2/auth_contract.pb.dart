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

import 'package:fixnum/fixnum.dart' as $fixnum;
import 'package:protobuf/protobuf.dart' as $pb;
import 'package:protobuf/well_known_types/google/protobuf/field_mask.pb.dart'
    as $3;
import 'package:protobuf/well_known_types/google/protobuf/struct.pb.dart' as $0;
import 'package:protobuf/well_known_types/google/protobuf/timestamp.pb.dart'
    as $1;

import '../../common/v1/common.pb.dart' as $2;
import 'auth_contract.pbenum.dart';

export 'package:protobuf/protobuf.dart' show GeneratedMessageGenericExtensions;

export 'auth_contract.pbenum.dart';

class OAuthClientConfiguration extends $pb.GeneratedMessage {
  factory OAuthClientConfiguration({
    $core.Iterable<$core.String>? grantTypes,
    $core.Iterable<$core.String>? responseTypes,
    $core.Iterable<$core.String>? redirectUris,
    $core.String? scopes,
    $core.Iterable<$core.String>? resourceRecipients,
    $core.String? tokenEndpointAuthMethod,
    $0.Struct? properties,
  }) {
    final result = OAuthClientConfiguration._();
    if (grantTypes != null) result.grantTypes.addAll(grantTypes);
    if (responseTypes != null) result.responseTypes.addAll(responseTypes);
    if (redirectUris != null) result.redirectUris.addAll(redirectUris);
    if (scopes != null) result.scopes = scopes;
    if (resourceRecipients != null)
      result.resourceRecipients.addAll(resourceRecipients);
    if (tokenEndpointAuthMethod != null)
      result.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    if (properties != null) result.properties = properties;
    return result;
  }

  OAuthClientConfiguration._();

  factory OAuthClientConfiguration.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      OAuthClientConfiguration()..mergeFromBuffer(data, registry);
  factory OAuthClientConfiguration.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      OAuthClientConfiguration()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'OAuthClientConfiguration',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: OAuthClientConfiguration.$_createMessage)
    ..pPS(1, _omitFieldNames ? '' : 'grantTypes')
    ..pPS(2, _omitFieldNames ? '' : 'responseTypes')
    ..pPS(3, _omitFieldNames ? '' : 'redirectUris')
    ..aOS(4, _omitFieldNames ? '' : 'scopes')
    ..pPS(5, _omitFieldNames ? '' : 'resourceRecipients')
    ..aOS(6, _omitFieldNames ? '' : 'tokenEndpointAuthMethod')
    ..aOM<$0.Struct>(7, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  OAuthClientConfiguration clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  OAuthClientConfiguration copyWith(
          void Function(OAuthClientConfiguration) updates) =>
      super.copyWith((message) => updates(message as OAuthClientConfiguration))
          as OAuthClientConfiguration;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use OAuthClientConfiguration() / OAuthClientConfiguration.new instead')
  static OAuthClientConfiguration create() => OAuthClientConfiguration._();
  static $pb.GeneratedMessage $_createMessage() => OAuthClientConfiguration._();
  @$core.override
  OAuthClientConfiguration createEmptyInstance() =>
      OAuthClientConfiguration._();
  @$core.pragma('dart2js:noInline')
  static OAuthClientConfiguration getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<OAuthClientConfiguration>(
          OAuthClientConfiguration.$_createMessage);
  static OAuthClientConfiguration? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<$core.String> get grantTypes => $_getList(0);

  @$pb.TagNumber(2)
  $pb.PbList<$core.String> get responseTypes => $_getList(1);

  @$pb.TagNumber(3)
  $pb.PbList<$core.String> get redirectUris => $_getList(2);

  @$pb.TagNumber(4)
  $core.String get scopes => $_getSZ(3);
  @$pb.TagNumber(4)
  set scopes($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasScopes() => $_has(3);
  @$pb.TagNumber(4)
  void clearScopes() => $_clearField(4);

  @$pb.TagNumber(5)
  $pb.PbList<$core.String> get resourceRecipients => $_getList(4);

  @$pb.TagNumber(6)
  $core.String get tokenEndpointAuthMethod => $_getSZ(5);
  @$pb.TagNumber(6)
  set tokenEndpointAuthMethod($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasTokenEndpointAuthMethod() => $_has(5);
  @$pb.TagNumber(6)
  void clearTokenEndpointAuthMethod() => $_clearField(6);

  @$pb.TagNumber(7)
  $0.Struct get properties => $_getN(6);
  @$pb.TagNumber(7)
  set properties($0.Struct value) => $_setField(7, value);
  @$pb.TagNumber(7)
  $core.bool hasProperties() => $_has(6);
  @$pb.TagNumber(7)
  void clearProperties() => $_clearField(7);
  @$pb.TagNumber(7)
  $0.Struct ensureProperties() => $_ensure(6);
}

enum OAuthClient_Owner { partitionId, serviceAccountId, notSet }

class OAuthClient extends $pb.GeneratedMessage {
  factory OAuthClient({
    $core.String? id,
    $core.String? name,
    $core.String? clientId,
    $core.String? type,
    OAuthClientConfiguration? configuration,
    $2.STATE? state,
    $1.Timestamp? createdAt,
    $core.String? partitionId,
    $core.String? serviceAccountId,
  }) {
    final result = OAuthClient._();
    if (id != null) result.id = id;
    if (name != null) result.name = name;
    if (clientId != null) result.clientId = clientId;
    if (type != null) result.type = type;
    if (configuration != null) result.configuration = configuration;
    if (state != null) result.state = state;
    if (createdAt != null) result.createdAt = createdAt;
    if (partitionId != null) result.partitionId = partitionId;
    if (serviceAccountId != null) result.serviceAccountId = serviceAccountId;
    return result;
  }

  OAuthClient._();

  factory OAuthClient.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      OAuthClient()..mergeFromBuffer(data, registry);
  factory OAuthClient.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      OAuthClient()..mergeFromJson(json, registry);

  static const $core.Map<$core.int, OAuthClient_Owner> _OAuthClient_OwnerByTag =
      {
    8: OAuthClient_Owner.partitionId,
    9: OAuthClient_Owner.serviceAccountId,
    0: OAuthClient_Owner.notSet
  };
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'OAuthClient',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: OAuthClient.$_createMessage)
    ..oo(0, [8, 9])
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'clientId')
    ..aOS(4, _omitFieldNames ? '' : 'type')
    ..aOM<OAuthClientConfiguration>(5, _omitFieldNames ? '' : 'configuration',
        subBuilder: OAuthClientConfiguration.$_createMessage)
    ..aE<$2.STATE>(6, _omitFieldNames ? '' : 'state',
        enumValues: $2.STATE.values)
    ..aOM<$1.Timestamp>(7, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOS(8, _omitFieldNames ? '' : 'partitionId')
    ..aOS(9, _omitFieldNames ? '' : 'serviceAccountId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  OAuthClient clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  OAuthClient copyWith(void Function(OAuthClient) updates) =>
      super.copyWith((message) => updates(message as OAuthClient))
          as OAuthClient;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use OAuthClient() / OAuthClient.new instead')
  static OAuthClient create() => OAuthClient._();
  static $pb.GeneratedMessage $_createMessage() => OAuthClient._();
  @$core.override
  OAuthClient createEmptyInstance() => OAuthClient._();
  @$core.pragma('dart2js:noInline')
  static OAuthClient getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<OAuthClient>(
          OAuthClient.$_createMessage);
  static OAuthClient? _defaultInstance;

  @$pb.TagNumber(8)
  @$pb.TagNumber(9)
  OAuthClient_Owner whichOwner() => _OAuthClient_OwnerByTag[$_whichOneof(0)]!;
  @$pb.TagNumber(8)
  @$pb.TagNumber(9)
  void clearOwner() => $_clearField($_whichOneof(0));

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get name => $_getSZ(1);
  @$pb.TagNumber(2)
  set name($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasName() => $_has(1);
  @$pb.TagNumber(2)
  void clearName() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get clientId => $_getSZ(2);
  @$pb.TagNumber(3)
  set clientId($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasClientId() => $_has(2);
  @$pb.TagNumber(3)
  void clearClientId() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get type => $_getSZ(3);
  @$pb.TagNumber(4)
  set type($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasType() => $_has(3);
  @$pb.TagNumber(4)
  void clearType() => $_clearField(4);

  @$pb.TagNumber(5)
  OAuthClientConfiguration get configuration => $_getN(4);
  @$pb.TagNumber(5)
  set configuration(OAuthClientConfiguration value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasConfiguration() => $_has(4);
  @$pb.TagNumber(5)
  void clearConfiguration() => $_clearField(5);
  @$pb.TagNumber(5)
  OAuthClientConfiguration ensureConfiguration() => $_ensure(4);

  @$pb.TagNumber(6)
  $2.STATE get state => $_getN(5);
  @$pb.TagNumber(6)
  set state($2.STATE value) => $_setField(6, value);
  @$pb.TagNumber(6)
  $core.bool hasState() => $_has(5);
  @$pb.TagNumber(6)
  void clearState() => $_clearField(6);

  @$pb.TagNumber(7)
  $1.Timestamp get createdAt => $_getN(6);
  @$pb.TagNumber(7)
  set createdAt($1.Timestamp value) => $_setField(7, value);
  @$pb.TagNumber(7)
  $core.bool hasCreatedAt() => $_has(6);
  @$pb.TagNumber(7)
  void clearCreatedAt() => $_clearField(7);
  @$pb.TagNumber(7)
  $1.Timestamp ensureCreatedAt() => $_ensure(6);

  @$pb.TagNumber(8)
  $core.String get partitionId => $_getSZ(7);
  @$pb.TagNumber(8)
  set partitionId($core.String value) => $_setString(7, value);
  @$pb.TagNumber(8)
  $core.bool hasPartitionId() => $_has(7);
  @$pb.TagNumber(8)
  void clearPartitionId() => $_clearField(8);

  @$pb.TagNumber(9)
  $core.String get serviceAccountId => $_getSZ(8);
  @$pb.TagNumber(9)
  set serviceAccountId($core.String value) => $_setString(8, value);
  @$pb.TagNumber(9)
  $core.bool hasServiceAccountId() => $_has(8);
  @$pb.TagNumber(9)
  void clearServiceAccountId() => $_clearField(9);
}

class ServiceAuthorizationGrant extends $pb.GeneratedMessage {
  factory ServiceAuthorizationGrant({
    $core.String? namespace,
    $core.Iterable<$core.String>? permissions,
    AuthorizationScope? scope,
  }) {
    final result = ServiceAuthorizationGrant._();
    if (namespace != null) result.namespace = namespace;
    if (permissions != null) result.permissions.addAll(permissions);
    if (scope != null) result.scope = scope;
    return result;
  }

  ServiceAuthorizationGrant._();

  factory ServiceAuthorizationGrant.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ServiceAuthorizationGrant()..mergeFromBuffer(data, registry);
  factory ServiceAuthorizationGrant.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ServiceAuthorizationGrant()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ServiceAuthorizationGrant',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: ServiceAuthorizationGrant.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'namespace')
    ..pPS(2, _omitFieldNames ? '' : 'permissions')
    ..aE<AuthorizationScope>(3, _omitFieldNames ? '' : 'scope',
        enumValues: AuthorizationScope.values)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ServiceAuthorizationGrant clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ServiceAuthorizationGrant copyWith(
          void Function(ServiceAuthorizationGrant) updates) =>
      super.copyWith((message) => updates(message as ServiceAuthorizationGrant))
          as ServiceAuthorizationGrant;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ServiceAuthorizationGrant() / ServiceAuthorizationGrant.new instead')
  static ServiceAuthorizationGrant create() => ServiceAuthorizationGrant._();
  static $pb.GeneratedMessage $_createMessage() =>
      ServiceAuthorizationGrant._();
  @$core.override
  ServiceAuthorizationGrant createEmptyInstance() =>
      ServiceAuthorizationGrant._();
  @$core.pragma('dart2js:noInline')
  static ServiceAuthorizationGrant getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ServiceAuthorizationGrant>(
          ServiceAuthorizationGrant.$_createMessage);
  static ServiceAuthorizationGrant? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get namespace => $_getSZ(0);
  @$pb.TagNumber(1)
  set namespace($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasNamespace() => $_has(0);
  @$pb.TagNumber(1)
  void clearNamespace() => $_clearField(1);

  @$pb.TagNumber(2)
  $pb.PbList<$core.String> get permissions => $_getList(1);

  @$pb.TagNumber(3)
  AuthorizationScope get scope => $_getN(2);
  @$pb.TagNumber(3)
  set scope(AuthorizationScope value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasScope() => $_has(2);
  @$pb.TagNumber(3)
  void clearScope() => $_clearField(3);
}

class ServiceAuthorizationPolicyInput extends $pb.GeneratedMessage {
  factory ServiceAuthorizationPolicyInput({
    $core.int? schemaVersion,
    $core.Iterable<ServiceAuthorizationGrant>? grants,
  }) {
    final result = ServiceAuthorizationPolicyInput._();
    if (schemaVersion != null) result.schemaVersion = schemaVersion;
    if (grants != null) result.grants.addAll(grants);
    return result;
  }

  ServiceAuthorizationPolicyInput._();

  factory ServiceAuthorizationPolicyInput.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ServiceAuthorizationPolicyInput()..mergeFromBuffer(data, registry);
  factory ServiceAuthorizationPolicyInput.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ServiceAuthorizationPolicyInput()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ServiceAuthorizationPolicyInput',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: ServiceAuthorizationPolicyInput.$_createMessage)
    ..aI(1, _omitFieldNames ? '' : 'schemaVersion')
    ..pPM<ServiceAuthorizationGrant>(2, _omitFieldNames ? '' : 'grants',
        subBuilder: ServiceAuthorizationGrant.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ServiceAuthorizationPolicyInput clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ServiceAuthorizationPolicyInput copyWith(
          void Function(ServiceAuthorizationPolicyInput) updates) =>
      super.copyWith(
              (message) => updates(message as ServiceAuthorizationPolicyInput))
          as ServiceAuthorizationPolicyInput;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ServiceAuthorizationPolicyInput() / ServiceAuthorizationPolicyInput.new instead')
  static ServiceAuthorizationPolicyInput create() =>
      ServiceAuthorizationPolicyInput._();
  static $pb.GeneratedMessage $_createMessage() =>
      ServiceAuthorizationPolicyInput._();
  @$core.override
  ServiceAuthorizationPolicyInput createEmptyInstance() =>
      ServiceAuthorizationPolicyInput._();
  @$core.pragma('dart2js:noInline')
  static ServiceAuthorizationPolicyInput getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ServiceAuthorizationPolicyInput>(
          ServiceAuthorizationPolicyInput.$_createMessage);
  static ServiceAuthorizationPolicyInput? _defaultInstance;

  @$pb.TagNumber(1)
  $core.int get schemaVersion => $_getIZ(0);
  @$pb.TagNumber(1)
  set schemaVersion($core.int value) => $_setSignedInt32(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSchemaVersion() => $_has(0);
  @$pb.TagNumber(1)
  void clearSchemaVersion() => $_clearField(1);

  @$pb.TagNumber(2)
  $pb.PbList<ServiceAuthorizationGrant> get grants => $_getList(1);
}

class ServiceAuthorizationPolicy extends $pb.GeneratedMessage {
  factory ServiceAuthorizationPolicy({
    $core.String? id,
    $core.int? schemaVersion,
    $fixnum.Int64? generation,
    $fixnum.Int64? appliedGeneration,
    AuthorizationPolicyStatus? status,
    $core.Iterable<ServiceAuthorizationGrant>? grants,
    $core.String? lastErrorCode,
    $1.Timestamp? nextAttemptAt,
    $1.Timestamp? syncedAt,
  }) {
    final result = ServiceAuthorizationPolicy._();
    if (id != null) result.id = id;
    if (schemaVersion != null) result.schemaVersion = schemaVersion;
    if (generation != null) result.generation = generation;
    if (appliedGeneration != null) result.appliedGeneration = appliedGeneration;
    if (status != null) result.status = status;
    if (grants != null) result.grants.addAll(grants);
    if (lastErrorCode != null) result.lastErrorCode = lastErrorCode;
    if (nextAttemptAt != null) result.nextAttemptAt = nextAttemptAt;
    if (syncedAt != null) result.syncedAt = syncedAt;
    return result;
  }

  ServiceAuthorizationPolicy._();

  factory ServiceAuthorizationPolicy.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ServiceAuthorizationPolicy()..mergeFromBuffer(data, registry);
  factory ServiceAuthorizationPolicy.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ServiceAuthorizationPolicy()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ServiceAuthorizationPolicy',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: ServiceAuthorizationPolicy.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aI(2, _omitFieldNames ? '' : 'schemaVersion')
    ..aInt64(3, _omitFieldNames ? '' : 'generation')
    ..aInt64(4, _omitFieldNames ? '' : 'appliedGeneration')
    ..aE<AuthorizationPolicyStatus>(5, _omitFieldNames ? '' : 'status',
        enumValues: AuthorizationPolicyStatus.values)
    ..pPM<ServiceAuthorizationGrant>(6, _omitFieldNames ? '' : 'grants',
        subBuilder: ServiceAuthorizationGrant.$_createMessage)
    ..aOS(7, _omitFieldNames ? '' : 'lastErrorCode')
    ..aOM<$1.Timestamp>(8, _omitFieldNames ? '' : 'nextAttemptAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOM<$1.Timestamp>(9, _omitFieldNames ? '' : 'syncedAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ServiceAuthorizationPolicy clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ServiceAuthorizationPolicy copyWith(
          void Function(ServiceAuthorizationPolicy) updates) =>
      super.copyWith(
              (message) => updates(message as ServiceAuthorizationPolicy))
          as ServiceAuthorizationPolicy;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ServiceAuthorizationPolicy() / ServiceAuthorizationPolicy.new instead')
  static ServiceAuthorizationPolicy create() => ServiceAuthorizationPolicy._();
  static $pb.GeneratedMessage $_createMessage() =>
      ServiceAuthorizationPolicy._();
  @$core.override
  ServiceAuthorizationPolicy createEmptyInstance() =>
      ServiceAuthorizationPolicy._();
  @$core.pragma('dart2js:noInline')
  static ServiceAuthorizationPolicy getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ServiceAuthorizationPolicy>(
          ServiceAuthorizationPolicy.$_createMessage);
  static ServiceAuthorizationPolicy? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.int get schemaVersion => $_getIZ(1);
  @$pb.TagNumber(2)
  set schemaVersion($core.int value) => $_setSignedInt32(1, value);
  @$pb.TagNumber(2)
  $core.bool hasSchemaVersion() => $_has(1);
  @$pb.TagNumber(2)
  void clearSchemaVersion() => $_clearField(2);

  @$pb.TagNumber(3)
  $fixnum.Int64 get generation => $_getI64(2);
  @$pb.TagNumber(3)
  set generation($fixnum.Int64 value) => $_setInt64(2, value);
  @$pb.TagNumber(3)
  $core.bool hasGeneration() => $_has(2);
  @$pb.TagNumber(3)
  void clearGeneration() => $_clearField(3);

  @$pb.TagNumber(4)
  $fixnum.Int64 get appliedGeneration => $_getI64(3);
  @$pb.TagNumber(4)
  set appliedGeneration($fixnum.Int64 value) => $_setInt64(3, value);
  @$pb.TagNumber(4)
  $core.bool hasAppliedGeneration() => $_has(3);
  @$pb.TagNumber(4)
  void clearAppliedGeneration() => $_clearField(4);

  @$pb.TagNumber(5)
  AuthorizationPolicyStatus get status => $_getN(4);
  @$pb.TagNumber(5)
  set status(AuthorizationPolicyStatus value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasStatus() => $_has(4);
  @$pb.TagNumber(5)
  void clearStatus() => $_clearField(5);

  @$pb.TagNumber(6)
  $pb.PbList<ServiceAuthorizationGrant> get grants => $_getList(5);

  @$pb.TagNumber(7)
  $core.String get lastErrorCode => $_getSZ(6);
  @$pb.TagNumber(7)
  set lastErrorCode($core.String value) => $_setString(6, value);
  @$pb.TagNumber(7)
  $core.bool hasLastErrorCode() => $_has(6);
  @$pb.TagNumber(7)
  void clearLastErrorCode() => $_clearField(7);

  @$pb.TagNumber(8)
  $1.Timestamp get nextAttemptAt => $_getN(7);
  @$pb.TagNumber(8)
  set nextAttemptAt($1.Timestamp value) => $_setField(8, value);
  @$pb.TagNumber(8)
  $core.bool hasNextAttemptAt() => $_has(7);
  @$pb.TagNumber(8)
  void clearNextAttemptAt() => $_clearField(8);
  @$pb.TagNumber(8)
  $1.Timestamp ensureNextAttemptAt() => $_ensure(7);

  @$pb.TagNumber(9)
  $1.Timestamp get syncedAt => $_getN(8);
  @$pb.TagNumber(9)
  set syncedAt($1.Timestamp value) => $_setField(9, value);
  @$pb.TagNumber(9)
  $core.bool hasSyncedAt() => $_has(8);
  @$pb.TagNumber(9)
  void clearSyncedAt() => $_clearField(9);
  @$pb.TagNumber(9)
  $1.Timestamp ensureSyncedAt() => $_ensure(8);
}

class ServiceAccount extends $pb.GeneratedMessage {
  factory ServiceAccount({
    $core.String? id,
    $core.String? tenantId,
    $core.String? partitionId,
    $core.String? profileId,
    $core.String? name,
    $core.String? type,
    OAuthClient? oauthClient,
    ServiceAuthorizationPolicy? authorizationPolicy,
    $0.Struct? publicKeys,
    $0.Struct? properties,
    $2.STATE? state,
    $1.Timestamp? createdAt,
  }) {
    final result = ServiceAccount._();
    if (id != null) result.id = id;
    if (tenantId != null) result.tenantId = tenantId;
    if (partitionId != null) result.partitionId = partitionId;
    if (profileId != null) result.profileId = profileId;
    if (name != null) result.name = name;
    if (type != null) result.type = type;
    if (oauthClient != null) result.oauthClient = oauthClient;
    if (authorizationPolicy != null)
      result.authorizationPolicy = authorizationPolicy;
    if (publicKeys != null) result.publicKeys = publicKeys;
    if (properties != null) result.properties = properties;
    if (state != null) result.state = state;
    if (createdAt != null) result.createdAt = createdAt;
    return result;
  }

  ServiceAccount._();

  factory ServiceAccount.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ServiceAccount()..mergeFromBuffer(data, registry);
  factory ServiceAccount.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ServiceAccount()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ServiceAccount',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: ServiceAccount.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'tenantId')
    ..aOS(3, _omitFieldNames ? '' : 'partitionId')
    ..aOS(4, _omitFieldNames ? '' : 'profileId')
    ..aOS(5, _omitFieldNames ? '' : 'name')
    ..aOS(6, _omitFieldNames ? '' : 'type')
    ..aOM<OAuthClient>(7, _omitFieldNames ? '' : 'oauthClient',
        subBuilder: OAuthClient.$_createMessage)
    ..aOM<ServiceAuthorizationPolicy>(
        8, _omitFieldNames ? '' : 'authorizationPolicy',
        subBuilder: ServiceAuthorizationPolicy.$_createMessage)
    ..aOM<$0.Struct>(9, _omitFieldNames ? '' : 'publicKeys',
        subBuilder: $0.Struct.$_createMessage)
    ..aOM<$0.Struct>(10, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..aE<$2.STATE>(11, _omitFieldNames ? '' : 'state',
        enumValues: $2.STATE.values)
    ..aOM<$1.Timestamp>(12, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ServiceAccount clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ServiceAccount copyWith(void Function(ServiceAccount) updates) =>
      super.copyWith((message) => updates(message as ServiceAccount))
          as ServiceAccount;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use ServiceAccount() / ServiceAccount.new instead')
  static ServiceAccount create() => ServiceAccount._();
  static $pb.GeneratedMessage $_createMessage() => ServiceAccount._();
  @$core.override
  ServiceAccount createEmptyInstance() => ServiceAccount._();
  @$core.pragma('dart2js:noInline')
  static ServiceAccount getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ServiceAccount>(
          ServiceAccount.$_createMessage);
  static ServiceAccount? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get tenantId => $_getSZ(1);
  @$pb.TagNumber(2)
  set tenantId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasTenantId() => $_has(1);
  @$pb.TagNumber(2)
  void clearTenantId() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get partitionId => $_getSZ(2);
  @$pb.TagNumber(3)
  set partitionId($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasPartitionId() => $_has(2);
  @$pb.TagNumber(3)
  void clearPartitionId() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get profileId => $_getSZ(3);
  @$pb.TagNumber(4)
  set profileId($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasProfileId() => $_has(3);
  @$pb.TagNumber(4)
  void clearProfileId() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.String get name => $_getSZ(4);
  @$pb.TagNumber(5)
  set name($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasName() => $_has(4);
  @$pb.TagNumber(5)
  void clearName() => $_clearField(5);

  @$pb.TagNumber(6)
  $core.String get type => $_getSZ(5);
  @$pb.TagNumber(6)
  set type($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasType() => $_has(5);
  @$pb.TagNumber(6)
  void clearType() => $_clearField(6);

  @$pb.TagNumber(7)
  OAuthClient get oauthClient => $_getN(6);
  @$pb.TagNumber(7)
  set oauthClient(OAuthClient value) => $_setField(7, value);
  @$pb.TagNumber(7)
  $core.bool hasOauthClient() => $_has(6);
  @$pb.TagNumber(7)
  void clearOauthClient() => $_clearField(7);
  @$pb.TagNumber(7)
  OAuthClient ensureOauthClient() => $_ensure(6);

  @$pb.TagNumber(8)
  ServiceAuthorizationPolicy get authorizationPolicy => $_getN(7);
  @$pb.TagNumber(8)
  set authorizationPolicy(ServiceAuthorizationPolicy value) =>
      $_setField(8, value);
  @$pb.TagNumber(8)
  $core.bool hasAuthorizationPolicy() => $_has(7);
  @$pb.TagNumber(8)
  void clearAuthorizationPolicy() => $_clearField(8);
  @$pb.TagNumber(8)
  ServiceAuthorizationPolicy ensureAuthorizationPolicy() => $_ensure(7);

  @$pb.TagNumber(9)
  $0.Struct get publicKeys => $_getN(8);
  @$pb.TagNumber(9)
  set publicKeys($0.Struct value) => $_setField(9, value);
  @$pb.TagNumber(9)
  $core.bool hasPublicKeys() => $_has(8);
  @$pb.TagNumber(9)
  void clearPublicKeys() => $_clearField(9);
  @$pb.TagNumber(9)
  $0.Struct ensurePublicKeys() => $_ensure(8);

  @$pb.TagNumber(10)
  $0.Struct get properties => $_getN(9);
  @$pb.TagNumber(10)
  set properties($0.Struct value) => $_setField(10, value);
  @$pb.TagNumber(10)
  $core.bool hasProperties() => $_has(9);
  @$pb.TagNumber(10)
  void clearProperties() => $_clearField(10);
  @$pb.TagNumber(10)
  $0.Struct ensureProperties() => $_ensure(9);

  @$pb.TagNumber(11)
  $2.STATE get state => $_getN(10);
  @$pb.TagNumber(11)
  set state($2.STATE value) => $_setField(11, value);
  @$pb.TagNumber(11)
  $core.bool hasState() => $_has(10);
  @$pb.TagNumber(11)
  void clearState() => $_clearField(11);

  @$pb.TagNumber(12)
  $1.Timestamp get createdAt => $_getN(11);
  @$pb.TagNumber(12)
  set createdAt($1.Timestamp value) => $_setField(12, value);
  @$pb.TagNumber(12)
  $core.bool hasCreatedAt() => $_has(11);
  @$pb.TagNumber(12)
  void clearCreatedAt() => $_clearField(12);
  @$pb.TagNumber(12)
  $1.Timestamp ensureCreatedAt() => $_ensure(11);
}

class CreateOAuthClientRequest extends $pb.GeneratedMessage {
  factory CreateOAuthClientRequest({
    $core.String? partitionId,
    $core.String? name,
    $core.String? type,
    OAuthClientConfiguration? configuration,
  }) {
    final result = CreateOAuthClientRequest._();
    if (partitionId != null) result.partitionId = partitionId;
    if (name != null) result.name = name;
    if (type != null) result.type = type;
    if (configuration != null) result.configuration = configuration;
    return result;
  }

  CreateOAuthClientRequest._();

  factory CreateOAuthClientRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateOAuthClientRequest()..mergeFromBuffer(data, registry);
  factory CreateOAuthClientRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateOAuthClientRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateOAuthClientRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: CreateOAuthClientRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'type')
    ..aOM<OAuthClientConfiguration>(4, _omitFieldNames ? '' : 'configuration',
        subBuilder: OAuthClientConfiguration.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateOAuthClientRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateOAuthClientRequest copyWith(
          void Function(CreateOAuthClientRequest) updates) =>
      super.copyWith((message) => updates(message as CreateOAuthClientRequest))
          as CreateOAuthClientRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreateOAuthClientRequest() / CreateOAuthClientRequest.new instead')
  static CreateOAuthClientRequest create() => CreateOAuthClientRequest._();
  static $pb.GeneratedMessage $_createMessage() => CreateOAuthClientRequest._();
  @$core.override
  CreateOAuthClientRequest createEmptyInstance() =>
      CreateOAuthClientRequest._();
  @$core.pragma('dart2js:noInline')
  static CreateOAuthClientRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateOAuthClientRequest>(
          CreateOAuthClientRequest.$_createMessage);
  static CreateOAuthClientRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get partitionId => $_getSZ(0);
  @$pb.TagNumber(1)
  set partitionId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasPartitionId() => $_has(0);
  @$pb.TagNumber(1)
  void clearPartitionId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get name => $_getSZ(1);
  @$pb.TagNumber(2)
  set name($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasName() => $_has(1);
  @$pb.TagNumber(2)
  void clearName() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get type => $_getSZ(2);
  @$pb.TagNumber(3)
  set type($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasType() => $_has(2);
  @$pb.TagNumber(3)
  void clearType() => $_clearField(3);

  @$pb.TagNumber(4)
  OAuthClientConfiguration get configuration => $_getN(3);
  @$pb.TagNumber(4)
  set configuration(OAuthClientConfiguration value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasConfiguration() => $_has(3);
  @$pb.TagNumber(4)
  void clearConfiguration() => $_clearField(4);
  @$pb.TagNumber(4)
  OAuthClientConfiguration ensureConfiguration() => $_ensure(3);
}

class CreateOAuthClientResponse extends $pb.GeneratedMessage {
  factory CreateOAuthClientResponse({
    OAuthClient? data,
    $core.String? clientSecret,
  }) {
    final result = CreateOAuthClientResponse._();
    if (data != null) result.data = data;
    if (clientSecret != null) result.clientSecret = clientSecret;
    return result;
  }

  CreateOAuthClientResponse._();

  factory CreateOAuthClientResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateOAuthClientResponse()..mergeFromBuffer(data, registry);
  factory CreateOAuthClientResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateOAuthClientResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateOAuthClientResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: CreateOAuthClientResponse.$_createMessage)
    ..aOM<OAuthClient>(1, _omitFieldNames ? '' : 'data',
        subBuilder: OAuthClient.$_createMessage)
    ..aOS(2, _omitFieldNames ? '' : 'clientSecret')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateOAuthClientResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateOAuthClientResponse copyWith(
          void Function(CreateOAuthClientResponse) updates) =>
      super.copyWith((message) => updates(message as CreateOAuthClientResponse))
          as CreateOAuthClientResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreateOAuthClientResponse() / CreateOAuthClientResponse.new instead')
  static CreateOAuthClientResponse create() => CreateOAuthClientResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      CreateOAuthClientResponse._();
  @$core.override
  CreateOAuthClientResponse createEmptyInstance() =>
      CreateOAuthClientResponse._();
  @$core.pragma('dart2js:noInline')
  static CreateOAuthClientResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateOAuthClientResponse>(
          CreateOAuthClientResponse.$_createMessage);
  static CreateOAuthClientResponse? _defaultInstance;

  @$pb.TagNumber(1)
  OAuthClient get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(OAuthClient value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  OAuthClient ensureData() => $_ensure(0);

  @$pb.TagNumber(2)
  $core.String get clientSecret => $_getSZ(1);
  @$pb.TagNumber(2)
  set clientSecret($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasClientSecret() => $_has(1);
  @$pb.TagNumber(2)
  void clearClientSecret() => $_clearField(2);
}

enum GetOAuthClientRequest_Selector { id, clientId, notSet }

class GetOAuthClientRequest extends $pb.GeneratedMessage {
  factory GetOAuthClientRequest({
    $core.String? id,
    $core.String? clientId,
  }) {
    final result = GetOAuthClientRequest._();
    if (id != null) result.id = id;
    if (clientId != null) result.clientId = clientId;
    return result;
  }

  GetOAuthClientRequest._();

  factory GetOAuthClientRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetOAuthClientRequest()..mergeFromBuffer(data, registry);
  factory GetOAuthClientRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetOAuthClientRequest()..mergeFromJson(json, registry);

  static const $core.Map<$core.int, GetOAuthClientRequest_Selector>
      _GetOAuthClientRequest_SelectorByTag = {
    1: GetOAuthClientRequest_Selector.id,
    2: GetOAuthClientRequest_Selector.clientId,
    0: GetOAuthClientRequest_Selector.notSet
  };
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetOAuthClientRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: GetOAuthClientRequest.$_createMessage)
    ..oo(0, [1, 2])
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'clientId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetOAuthClientRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetOAuthClientRequest copyWith(
          void Function(GetOAuthClientRequest) updates) =>
      super.copyWith((message) => updates(message as GetOAuthClientRequest))
          as GetOAuthClientRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetOAuthClientRequest() / GetOAuthClientRequest.new instead')
  static GetOAuthClientRequest create() => GetOAuthClientRequest._();
  static $pb.GeneratedMessage $_createMessage() => GetOAuthClientRequest._();
  @$core.override
  GetOAuthClientRequest createEmptyInstance() => GetOAuthClientRequest._();
  @$core.pragma('dart2js:noInline')
  static GetOAuthClientRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetOAuthClientRequest>(
          GetOAuthClientRequest.$_createMessage);
  static GetOAuthClientRequest? _defaultInstance;

  @$pb.TagNumber(1)
  @$pb.TagNumber(2)
  GetOAuthClientRequest_Selector whichSelector() =>
      _GetOAuthClientRequest_SelectorByTag[$_whichOneof(0)]!;
  @$pb.TagNumber(1)
  @$pb.TagNumber(2)
  void clearSelector() => $_clearField($_whichOneof(0));

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get clientId => $_getSZ(1);
  @$pb.TagNumber(2)
  set clientId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasClientId() => $_has(1);
  @$pb.TagNumber(2)
  void clearClientId() => $_clearField(2);
}

class GetOAuthClientResponse extends $pb.GeneratedMessage {
  factory GetOAuthClientResponse({
    OAuthClient? data,
  }) {
    final result = GetOAuthClientResponse._();
    if (data != null) result.data = data;
    return result;
  }

  GetOAuthClientResponse._();

  factory GetOAuthClientResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetOAuthClientResponse()..mergeFromBuffer(data, registry);
  factory GetOAuthClientResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetOAuthClientResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetOAuthClientResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: GetOAuthClientResponse.$_createMessage)
    ..aOM<OAuthClient>(1, _omitFieldNames ? '' : 'data',
        subBuilder: OAuthClient.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetOAuthClientResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetOAuthClientResponse copyWith(
          void Function(GetOAuthClientResponse) updates) =>
      super.copyWith((message) => updates(message as GetOAuthClientResponse))
          as GetOAuthClientResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetOAuthClientResponse() / GetOAuthClientResponse.new instead')
  static GetOAuthClientResponse create() => GetOAuthClientResponse._();
  static $pb.GeneratedMessage $_createMessage() => GetOAuthClientResponse._();
  @$core.override
  GetOAuthClientResponse createEmptyInstance() => GetOAuthClientResponse._();
  @$core.pragma('dart2js:noInline')
  static GetOAuthClientResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetOAuthClientResponse>(
          GetOAuthClientResponse.$_createMessage);
  static GetOAuthClientResponse? _defaultInstance;

  @$pb.TagNumber(1)
  OAuthClient get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(OAuthClient value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  OAuthClient ensureData() => $_ensure(0);
}

enum ListOAuthClientsRequest_Owner { partitionId, serviceAccountId, notSet }

class ListOAuthClientsRequest extends $pb.GeneratedMessage {
  factory ListOAuthClientsRequest({
    $core.String? partitionId,
    $core.String? serviceAccountId,
    $2.PageCursor? cursor,
  }) {
    final result = ListOAuthClientsRequest._();
    if (partitionId != null) result.partitionId = partitionId;
    if (serviceAccountId != null) result.serviceAccountId = serviceAccountId;
    if (cursor != null) result.cursor = cursor;
    return result;
  }

  ListOAuthClientsRequest._();

  factory ListOAuthClientsRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListOAuthClientsRequest()..mergeFromBuffer(data, registry);
  factory ListOAuthClientsRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListOAuthClientsRequest()..mergeFromJson(json, registry);

  static const $core.Map<$core.int, ListOAuthClientsRequest_Owner>
      _ListOAuthClientsRequest_OwnerByTag = {
    1: ListOAuthClientsRequest_Owner.partitionId,
    2: ListOAuthClientsRequest_Owner.serviceAccountId,
    0: ListOAuthClientsRequest_Owner.notSet
  };
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListOAuthClientsRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: ListOAuthClientsRequest.$_createMessage)
    ..oo(0, [1, 2])
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOS(2, _omitFieldNames ? '' : 'serviceAccountId')
    ..aOM<$2.PageCursor>(3, _omitFieldNames ? '' : 'cursor',
        subBuilder: $2.PageCursor.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListOAuthClientsRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListOAuthClientsRequest copyWith(
          void Function(ListOAuthClientsRequest) updates) =>
      super.copyWith((message) => updates(message as ListOAuthClientsRequest))
          as ListOAuthClientsRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListOAuthClientsRequest() / ListOAuthClientsRequest.new instead')
  static ListOAuthClientsRequest create() => ListOAuthClientsRequest._();
  static $pb.GeneratedMessage $_createMessage() => ListOAuthClientsRequest._();
  @$core.override
  ListOAuthClientsRequest createEmptyInstance() => ListOAuthClientsRequest._();
  @$core.pragma('dart2js:noInline')
  static ListOAuthClientsRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListOAuthClientsRequest>(
          ListOAuthClientsRequest.$_createMessage);
  static ListOAuthClientsRequest? _defaultInstance;

  @$pb.TagNumber(1)
  @$pb.TagNumber(2)
  ListOAuthClientsRequest_Owner whichOwner() =>
      _ListOAuthClientsRequest_OwnerByTag[$_whichOneof(0)]!;
  @$pb.TagNumber(1)
  @$pb.TagNumber(2)
  void clearOwner() => $_clearField($_whichOneof(0));

  @$pb.TagNumber(1)
  $core.String get partitionId => $_getSZ(0);
  @$pb.TagNumber(1)
  set partitionId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasPartitionId() => $_has(0);
  @$pb.TagNumber(1)
  void clearPartitionId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get serviceAccountId => $_getSZ(1);
  @$pb.TagNumber(2)
  set serviceAccountId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasServiceAccountId() => $_has(1);
  @$pb.TagNumber(2)
  void clearServiceAccountId() => $_clearField(2);

  @$pb.TagNumber(3)
  $2.PageCursor get cursor => $_getN(2);
  @$pb.TagNumber(3)
  set cursor($2.PageCursor value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasCursor() => $_has(2);
  @$pb.TagNumber(3)
  void clearCursor() => $_clearField(3);
  @$pb.TagNumber(3)
  $2.PageCursor ensureCursor() => $_ensure(2);
}

class ListOAuthClientsResponse extends $pb.GeneratedMessage {
  factory ListOAuthClientsResponse({
    $core.Iterable<OAuthClient>? data,
  }) {
    final result = ListOAuthClientsResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  ListOAuthClientsResponse._();

  factory ListOAuthClientsResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListOAuthClientsResponse()..mergeFromBuffer(data, registry);
  factory ListOAuthClientsResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListOAuthClientsResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListOAuthClientsResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: ListOAuthClientsResponse.$_createMessage)
    ..pPM<OAuthClient>(1, _omitFieldNames ? '' : 'data',
        subBuilder: OAuthClient.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListOAuthClientsResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListOAuthClientsResponse copyWith(
          void Function(ListOAuthClientsResponse) updates) =>
      super.copyWith((message) => updates(message as ListOAuthClientsResponse))
          as ListOAuthClientsResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListOAuthClientsResponse() / ListOAuthClientsResponse.new instead')
  static ListOAuthClientsResponse create() => ListOAuthClientsResponse._();
  static $pb.GeneratedMessage $_createMessage() => ListOAuthClientsResponse._();
  @$core.override
  ListOAuthClientsResponse createEmptyInstance() =>
      ListOAuthClientsResponse._();
  @$core.pragma('dart2js:noInline')
  static ListOAuthClientsResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListOAuthClientsResponse>(
          ListOAuthClientsResponse.$_createMessage);
  static ListOAuthClientsResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<OAuthClient> get data => $_getList(0);
}

class UpdateOAuthClientRequest extends $pb.GeneratedMessage {
  factory UpdateOAuthClientRequest({
    $core.String? id,
    $core.String? name,
    OAuthClientConfiguration? configuration,
    $3.FieldMask? updateMask,
  }) {
    final result = UpdateOAuthClientRequest._();
    if (id != null) result.id = id;
    if (name != null) result.name = name;
    if (configuration != null) result.configuration = configuration;
    if (updateMask != null) result.updateMask = updateMask;
    return result;
  }

  UpdateOAuthClientRequest._();

  factory UpdateOAuthClientRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdateOAuthClientRequest()..mergeFromBuffer(data, registry);
  factory UpdateOAuthClientRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdateOAuthClientRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdateOAuthClientRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: UpdateOAuthClientRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOM<OAuthClientConfiguration>(3, _omitFieldNames ? '' : 'configuration',
        subBuilder: OAuthClientConfiguration.$_createMessage)
    ..aOM<$3.FieldMask>(4, _omitFieldNames ? '' : 'updateMask',
        subBuilder: $3.FieldMask.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdateOAuthClientRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdateOAuthClientRequest copyWith(
          void Function(UpdateOAuthClientRequest) updates) =>
      super.copyWith((message) => updates(message as UpdateOAuthClientRequest))
          as UpdateOAuthClientRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use UpdateOAuthClientRequest() / UpdateOAuthClientRequest.new instead')
  static UpdateOAuthClientRequest create() => UpdateOAuthClientRequest._();
  static $pb.GeneratedMessage $_createMessage() => UpdateOAuthClientRequest._();
  @$core.override
  UpdateOAuthClientRequest createEmptyInstance() =>
      UpdateOAuthClientRequest._();
  @$core.pragma('dart2js:noInline')
  static UpdateOAuthClientRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdateOAuthClientRequest>(
          UpdateOAuthClientRequest.$_createMessage);
  static UpdateOAuthClientRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get name => $_getSZ(1);
  @$pb.TagNumber(2)
  set name($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasName() => $_has(1);
  @$pb.TagNumber(2)
  void clearName() => $_clearField(2);

  @$pb.TagNumber(3)
  OAuthClientConfiguration get configuration => $_getN(2);
  @$pb.TagNumber(3)
  set configuration(OAuthClientConfiguration value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasConfiguration() => $_has(2);
  @$pb.TagNumber(3)
  void clearConfiguration() => $_clearField(3);
  @$pb.TagNumber(3)
  OAuthClientConfiguration ensureConfiguration() => $_ensure(2);

  @$pb.TagNumber(4)
  $3.FieldMask get updateMask => $_getN(3);
  @$pb.TagNumber(4)
  set updateMask($3.FieldMask value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasUpdateMask() => $_has(3);
  @$pb.TagNumber(4)
  void clearUpdateMask() => $_clearField(4);
  @$pb.TagNumber(4)
  $3.FieldMask ensureUpdateMask() => $_ensure(3);
}

class UpdateOAuthClientResponse extends $pb.GeneratedMessage {
  factory UpdateOAuthClientResponse({
    OAuthClient? data,
  }) {
    final result = UpdateOAuthClientResponse._();
    if (data != null) result.data = data;
    return result;
  }

  UpdateOAuthClientResponse._();

  factory UpdateOAuthClientResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdateOAuthClientResponse()..mergeFromBuffer(data, registry);
  factory UpdateOAuthClientResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdateOAuthClientResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdateOAuthClientResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: UpdateOAuthClientResponse.$_createMessage)
    ..aOM<OAuthClient>(1, _omitFieldNames ? '' : 'data',
        subBuilder: OAuthClient.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdateOAuthClientResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdateOAuthClientResponse copyWith(
          void Function(UpdateOAuthClientResponse) updates) =>
      super.copyWith((message) => updates(message as UpdateOAuthClientResponse))
          as UpdateOAuthClientResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use UpdateOAuthClientResponse() / UpdateOAuthClientResponse.new instead')
  static UpdateOAuthClientResponse create() => UpdateOAuthClientResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      UpdateOAuthClientResponse._();
  @$core.override
  UpdateOAuthClientResponse createEmptyInstance() =>
      UpdateOAuthClientResponse._();
  @$core.pragma('dart2js:noInline')
  static UpdateOAuthClientResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdateOAuthClientResponse>(
          UpdateOAuthClientResponse.$_createMessage);
  static UpdateOAuthClientResponse? _defaultInstance;

  @$pb.TagNumber(1)
  OAuthClient get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(OAuthClient value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  OAuthClient ensureData() => $_ensure(0);
}

class RemoveOAuthClientRequest extends $pb.GeneratedMessage {
  factory RemoveOAuthClientRequest({
    $core.String? id,
  }) {
    final result = RemoveOAuthClientRequest._();
    if (id != null) result.id = id;
    return result;
  }

  RemoveOAuthClientRequest._();

  factory RemoveOAuthClientRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveOAuthClientRequest()..mergeFromBuffer(data, registry);
  factory RemoveOAuthClientRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveOAuthClientRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveOAuthClientRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: RemoveOAuthClientRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveOAuthClientRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveOAuthClientRequest copyWith(
          void Function(RemoveOAuthClientRequest) updates) =>
      super.copyWith((message) => updates(message as RemoveOAuthClientRequest))
          as RemoveOAuthClientRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RemoveOAuthClientRequest() / RemoveOAuthClientRequest.new instead')
  static RemoveOAuthClientRequest create() => RemoveOAuthClientRequest._();
  static $pb.GeneratedMessage $_createMessage() => RemoveOAuthClientRequest._();
  @$core.override
  RemoveOAuthClientRequest createEmptyInstance() =>
      RemoveOAuthClientRequest._();
  @$core.pragma('dart2js:noInline')
  static RemoveOAuthClientRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveOAuthClientRequest>(
          RemoveOAuthClientRequest.$_createMessage);
  static RemoveOAuthClientRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class RemoveOAuthClientResponse extends $pb.GeneratedMessage {
  factory RemoveOAuthClientResponse({
    $core.bool? succeeded,
  }) {
    final result = RemoveOAuthClientResponse._();
    if (succeeded != null) result.succeeded = succeeded;
    return result;
  }

  RemoveOAuthClientResponse._();

  factory RemoveOAuthClientResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveOAuthClientResponse()..mergeFromBuffer(data, registry);
  factory RemoveOAuthClientResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveOAuthClientResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveOAuthClientResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: RemoveOAuthClientResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'succeeded')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveOAuthClientResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveOAuthClientResponse copyWith(
          void Function(RemoveOAuthClientResponse) updates) =>
      super.copyWith((message) => updates(message as RemoveOAuthClientResponse))
          as RemoveOAuthClientResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RemoveOAuthClientResponse() / RemoveOAuthClientResponse.new instead')
  static RemoveOAuthClientResponse create() => RemoveOAuthClientResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      RemoveOAuthClientResponse._();
  @$core.override
  RemoveOAuthClientResponse createEmptyInstance() =>
      RemoveOAuthClientResponse._();
  @$core.pragma('dart2js:noInline')
  static RemoveOAuthClientResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveOAuthClientResponse>(
          RemoveOAuthClientResponse.$_createMessage);
  static RemoveOAuthClientResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get succeeded => $_getBF(0);
  @$pb.TagNumber(1)
  set succeeded($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSucceeded() => $_has(0);
  @$pb.TagNumber(1)
  void clearSucceeded() => $_clearField(1);
}

class CreateServiceAccountRequest extends $pb.GeneratedMessage {
  factory CreateServiceAccountRequest({
    $core.String? partitionId,
    $core.String? profileId,
    $core.String? name,
    $core.String? type,
    OAuthClientConfiguration? oauthClient,
    ServiceAuthorizationPolicyInput? authorizationPolicy,
    $0.Struct? publicKeys,
    $0.Struct? properties,
  }) {
    final result = CreateServiceAccountRequest._();
    if (partitionId != null) result.partitionId = partitionId;
    if (profileId != null) result.profileId = profileId;
    if (name != null) result.name = name;
    if (type != null) result.type = type;
    if (oauthClient != null) result.oauthClient = oauthClient;
    if (authorizationPolicy != null)
      result.authorizationPolicy = authorizationPolicy;
    if (publicKeys != null) result.publicKeys = publicKeys;
    if (properties != null) result.properties = properties;
    return result;
  }

  CreateServiceAccountRequest._();

  factory CreateServiceAccountRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateServiceAccountRequest()..mergeFromBuffer(data, registry);
  factory CreateServiceAccountRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateServiceAccountRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateServiceAccountRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: CreateServiceAccountRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOS(2, _omitFieldNames ? '' : 'profileId')
    ..aOS(3, _omitFieldNames ? '' : 'name')
    ..aOS(4, _omitFieldNames ? '' : 'type')
    ..aOM<OAuthClientConfiguration>(5, _omitFieldNames ? '' : 'oauthClient',
        subBuilder: OAuthClientConfiguration.$_createMessage)
    ..aOM<ServiceAuthorizationPolicyInput>(
        6, _omitFieldNames ? '' : 'authorizationPolicy',
        subBuilder: ServiceAuthorizationPolicyInput.$_createMessage)
    ..aOM<$0.Struct>(7, _omitFieldNames ? '' : 'publicKeys',
        subBuilder: $0.Struct.$_createMessage)
    ..aOM<$0.Struct>(8, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateServiceAccountRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateServiceAccountRequest copyWith(
          void Function(CreateServiceAccountRequest) updates) =>
      super.copyWith(
              (message) => updates(message as CreateServiceAccountRequest))
          as CreateServiceAccountRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreateServiceAccountRequest() / CreateServiceAccountRequest.new instead')
  static CreateServiceAccountRequest create() =>
      CreateServiceAccountRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      CreateServiceAccountRequest._();
  @$core.override
  CreateServiceAccountRequest createEmptyInstance() =>
      CreateServiceAccountRequest._();
  @$core.pragma('dart2js:noInline')
  static CreateServiceAccountRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateServiceAccountRequest>(
          CreateServiceAccountRequest.$_createMessage);
  static CreateServiceAccountRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get partitionId => $_getSZ(0);
  @$pb.TagNumber(1)
  set partitionId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasPartitionId() => $_has(0);
  @$pb.TagNumber(1)
  void clearPartitionId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get profileId => $_getSZ(1);
  @$pb.TagNumber(2)
  set profileId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasProfileId() => $_has(1);
  @$pb.TagNumber(2)
  void clearProfileId() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get name => $_getSZ(2);
  @$pb.TagNumber(3)
  set name($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasName() => $_has(2);
  @$pb.TagNumber(3)
  void clearName() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get type => $_getSZ(3);
  @$pb.TagNumber(4)
  set type($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasType() => $_has(3);
  @$pb.TagNumber(4)
  void clearType() => $_clearField(4);

  @$pb.TagNumber(5)
  OAuthClientConfiguration get oauthClient => $_getN(4);
  @$pb.TagNumber(5)
  set oauthClient(OAuthClientConfiguration value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasOauthClient() => $_has(4);
  @$pb.TagNumber(5)
  void clearOauthClient() => $_clearField(5);
  @$pb.TagNumber(5)
  OAuthClientConfiguration ensureOauthClient() => $_ensure(4);

  @$pb.TagNumber(6)
  ServiceAuthorizationPolicyInput get authorizationPolicy => $_getN(5);
  @$pb.TagNumber(6)
  set authorizationPolicy(ServiceAuthorizationPolicyInput value) =>
      $_setField(6, value);
  @$pb.TagNumber(6)
  $core.bool hasAuthorizationPolicy() => $_has(5);
  @$pb.TagNumber(6)
  void clearAuthorizationPolicy() => $_clearField(6);
  @$pb.TagNumber(6)
  ServiceAuthorizationPolicyInput ensureAuthorizationPolicy() => $_ensure(5);

  @$pb.TagNumber(7)
  $0.Struct get publicKeys => $_getN(6);
  @$pb.TagNumber(7)
  set publicKeys($0.Struct value) => $_setField(7, value);
  @$pb.TagNumber(7)
  $core.bool hasPublicKeys() => $_has(6);
  @$pb.TagNumber(7)
  void clearPublicKeys() => $_clearField(7);
  @$pb.TagNumber(7)
  $0.Struct ensurePublicKeys() => $_ensure(6);

  @$pb.TagNumber(8)
  $0.Struct get properties => $_getN(7);
  @$pb.TagNumber(8)
  set properties($0.Struct value) => $_setField(8, value);
  @$pb.TagNumber(8)
  $core.bool hasProperties() => $_has(7);
  @$pb.TagNumber(8)
  void clearProperties() => $_clearField(8);
  @$pb.TagNumber(8)
  $0.Struct ensureProperties() => $_ensure(7);
}

class CreateServiceAccountResponse extends $pb.GeneratedMessage {
  factory CreateServiceAccountResponse({
    ServiceAccount? data,
    $core.String? clientSecret,
  }) {
    final result = CreateServiceAccountResponse._();
    if (data != null) result.data = data;
    if (clientSecret != null) result.clientSecret = clientSecret;
    return result;
  }

  CreateServiceAccountResponse._();

  factory CreateServiceAccountResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateServiceAccountResponse()..mergeFromBuffer(data, registry);
  factory CreateServiceAccountResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateServiceAccountResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateServiceAccountResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: CreateServiceAccountResponse.$_createMessage)
    ..aOM<ServiceAccount>(1, _omitFieldNames ? '' : 'data',
        subBuilder: ServiceAccount.$_createMessage)
    ..aOS(2, _omitFieldNames ? '' : 'clientSecret')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateServiceAccountResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateServiceAccountResponse copyWith(
          void Function(CreateServiceAccountResponse) updates) =>
      super.copyWith(
              (message) => updates(message as CreateServiceAccountResponse))
          as CreateServiceAccountResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreateServiceAccountResponse() / CreateServiceAccountResponse.new instead')
  static CreateServiceAccountResponse create() =>
      CreateServiceAccountResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      CreateServiceAccountResponse._();
  @$core.override
  CreateServiceAccountResponse createEmptyInstance() =>
      CreateServiceAccountResponse._();
  @$core.pragma('dart2js:noInline')
  static CreateServiceAccountResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateServiceAccountResponse>(
          CreateServiceAccountResponse.$_createMessage);
  static CreateServiceAccountResponse? _defaultInstance;

  @$pb.TagNumber(1)
  ServiceAccount get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(ServiceAccount value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  ServiceAccount ensureData() => $_ensure(0);

  @$pb.TagNumber(2)
  $core.String get clientSecret => $_getSZ(1);
  @$pb.TagNumber(2)
  set clientSecret($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasClientSecret() => $_has(1);
  @$pb.TagNumber(2)
  void clearClientSecret() => $_clearField(2);
}

enum GetServiceAccountRequest_Selector { id, clientId, notSet }

class GetServiceAccountRequest extends $pb.GeneratedMessage {
  factory GetServiceAccountRequest({
    $core.String? id,
    $core.String? clientId,
  }) {
    final result = GetServiceAccountRequest._();
    if (id != null) result.id = id;
    if (clientId != null) result.clientId = clientId;
    return result;
  }

  GetServiceAccountRequest._();

  factory GetServiceAccountRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetServiceAccountRequest()..mergeFromBuffer(data, registry);
  factory GetServiceAccountRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetServiceAccountRequest()..mergeFromJson(json, registry);

  static const $core.Map<$core.int, GetServiceAccountRequest_Selector>
      _GetServiceAccountRequest_SelectorByTag = {
    1: GetServiceAccountRequest_Selector.id,
    2: GetServiceAccountRequest_Selector.clientId,
    0: GetServiceAccountRequest_Selector.notSet
  };
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetServiceAccountRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: GetServiceAccountRequest.$_createMessage)
    ..oo(0, [1, 2])
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'clientId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetServiceAccountRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetServiceAccountRequest copyWith(
          void Function(GetServiceAccountRequest) updates) =>
      super.copyWith((message) => updates(message as GetServiceAccountRequest))
          as GetServiceAccountRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetServiceAccountRequest() / GetServiceAccountRequest.new instead')
  static GetServiceAccountRequest create() => GetServiceAccountRequest._();
  static $pb.GeneratedMessage $_createMessage() => GetServiceAccountRequest._();
  @$core.override
  GetServiceAccountRequest createEmptyInstance() =>
      GetServiceAccountRequest._();
  @$core.pragma('dart2js:noInline')
  static GetServiceAccountRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetServiceAccountRequest>(
          GetServiceAccountRequest.$_createMessage);
  static GetServiceAccountRequest? _defaultInstance;

  @$pb.TagNumber(1)
  @$pb.TagNumber(2)
  GetServiceAccountRequest_Selector whichSelector() =>
      _GetServiceAccountRequest_SelectorByTag[$_whichOneof(0)]!;
  @$pb.TagNumber(1)
  @$pb.TagNumber(2)
  void clearSelector() => $_clearField($_whichOneof(0));

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get clientId => $_getSZ(1);
  @$pb.TagNumber(2)
  set clientId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasClientId() => $_has(1);
  @$pb.TagNumber(2)
  void clearClientId() => $_clearField(2);
}

class GetServiceAccountResponse extends $pb.GeneratedMessage {
  factory GetServiceAccountResponse({
    ServiceAccount? data,
  }) {
    final result = GetServiceAccountResponse._();
    if (data != null) result.data = data;
    return result;
  }

  GetServiceAccountResponse._();

  factory GetServiceAccountResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetServiceAccountResponse()..mergeFromBuffer(data, registry);
  factory GetServiceAccountResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetServiceAccountResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetServiceAccountResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: GetServiceAccountResponse.$_createMessage)
    ..aOM<ServiceAccount>(1, _omitFieldNames ? '' : 'data',
        subBuilder: ServiceAccount.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetServiceAccountResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetServiceAccountResponse copyWith(
          void Function(GetServiceAccountResponse) updates) =>
      super.copyWith((message) => updates(message as GetServiceAccountResponse))
          as GetServiceAccountResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetServiceAccountResponse() / GetServiceAccountResponse.new instead')
  static GetServiceAccountResponse create() => GetServiceAccountResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      GetServiceAccountResponse._();
  @$core.override
  GetServiceAccountResponse createEmptyInstance() =>
      GetServiceAccountResponse._();
  @$core.pragma('dart2js:noInline')
  static GetServiceAccountResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetServiceAccountResponse>(
          GetServiceAccountResponse.$_createMessage);
  static GetServiceAccountResponse? _defaultInstance;

  @$pb.TagNumber(1)
  ServiceAccount get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(ServiceAccount value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  ServiceAccount ensureData() => $_ensure(0);
}

class ListServiceAccountsRequest extends $pb.GeneratedMessage {
  factory ListServiceAccountsRequest({
    $core.String? partitionId,
    $2.PageCursor? cursor,
  }) {
    final result = ListServiceAccountsRequest._();
    if (partitionId != null) result.partitionId = partitionId;
    if (cursor != null) result.cursor = cursor;
    return result;
  }

  ListServiceAccountsRequest._();

  factory ListServiceAccountsRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListServiceAccountsRequest()..mergeFromBuffer(data, registry);
  factory ListServiceAccountsRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListServiceAccountsRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListServiceAccountsRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: ListServiceAccountsRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOM<$2.PageCursor>(2, _omitFieldNames ? '' : 'cursor',
        subBuilder: $2.PageCursor.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListServiceAccountsRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListServiceAccountsRequest copyWith(
          void Function(ListServiceAccountsRequest) updates) =>
      super.copyWith(
              (message) => updates(message as ListServiceAccountsRequest))
          as ListServiceAccountsRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListServiceAccountsRequest() / ListServiceAccountsRequest.new instead')
  static ListServiceAccountsRequest create() => ListServiceAccountsRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      ListServiceAccountsRequest._();
  @$core.override
  ListServiceAccountsRequest createEmptyInstance() =>
      ListServiceAccountsRequest._();
  @$core.pragma('dart2js:noInline')
  static ListServiceAccountsRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListServiceAccountsRequest>(
          ListServiceAccountsRequest.$_createMessage);
  static ListServiceAccountsRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get partitionId => $_getSZ(0);
  @$pb.TagNumber(1)
  set partitionId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasPartitionId() => $_has(0);
  @$pb.TagNumber(1)
  void clearPartitionId() => $_clearField(1);

  @$pb.TagNumber(2)
  $2.PageCursor get cursor => $_getN(1);
  @$pb.TagNumber(2)
  set cursor($2.PageCursor value) => $_setField(2, value);
  @$pb.TagNumber(2)
  $core.bool hasCursor() => $_has(1);
  @$pb.TagNumber(2)
  void clearCursor() => $_clearField(2);
  @$pb.TagNumber(2)
  $2.PageCursor ensureCursor() => $_ensure(1);
}

class ListServiceAccountsResponse extends $pb.GeneratedMessage {
  factory ListServiceAccountsResponse({
    $core.Iterable<ServiceAccount>? data,
  }) {
    final result = ListServiceAccountsResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  ListServiceAccountsResponse._();

  factory ListServiceAccountsResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListServiceAccountsResponse()..mergeFromBuffer(data, registry);
  factory ListServiceAccountsResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListServiceAccountsResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListServiceAccountsResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: ListServiceAccountsResponse.$_createMessage)
    ..pPM<ServiceAccount>(1, _omitFieldNames ? '' : 'data',
        subBuilder: ServiceAccount.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListServiceAccountsResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListServiceAccountsResponse copyWith(
          void Function(ListServiceAccountsResponse) updates) =>
      super.copyWith(
              (message) => updates(message as ListServiceAccountsResponse))
          as ListServiceAccountsResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListServiceAccountsResponse() / ListServiceAccountsResponse.new instead')
  static ListServiceAccountsResponse create() =>
      ListServiceAccountsResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      ListServiceAccountsResponse._();
  @$core.override
  ListServiceAccountsResponse createEmptyInstance() =>
      ListServiceAccountsResponse._();
  @$core.pragma('dart2js:noInline')
  static ListServiceAccountsResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListServiceAccountsResponse>(
          ListServiceAccountsResponse.$_createMessage);
  static ListServiceAccountsResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<ServiceAccount> get data => $_getList(0);
}

class UpdateServiceAccountRequest extends $pb.GeneratedMessage {
  factory UpdateServiceAccountRequest({
    $core.String? id,
    $core.String? name,
    $core.String? type,
    OAuthClientConfiguration? oauthClient,
    ServiceAuthorizationPolicyInput? authorizationPolicy,
    $0.Struct? publicKeys,
    $0.Struct? properties,
    $3.FieldMask? updateMask,
  }) {
    final result = UpdateServiceAccountRequest._();
    if (id != null) result.id = id;
    if (name != null) result.name = name;
    if (type != null) result.type = type;
    if (oauthClient != null) result.oauthClient = oauthClient;
    if (authorizationPolicy != null)
      result.authorizationPolicy = authorizationPolicy;
    if (publicKeys != null) result.publicKeys = publicKeys;
    if (properties != null) result.properties = properties;
    if (updateMask != null) result.updateMask = updateMask;
    return result;
  }

  UpdateServiceAccountRequest._();

  factory UpdateServiceAccountRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdateServiceAccountRequest()..mergeFromBuffer(data, registry);
  factory UpdateServiceAccountRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdateServiceAccountRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdateServiceAccountRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: UpdateServiceAccountRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'type')
    ..aOM<OAuthClientConfiguration>(4, _omitFieldNames ? '' : 'oauthClient',
        subBuilder: OAuthClientConfiguration.$_createMessage)
    ..aOM<ServiceAuthorizationPolicyInput>(
        5, _omitFieldNames ? '' : 'authorizationPolicy',
        subBuilder: ServiceAuthorizationPolicyInput.$_createMessage)
    ..aOM<$0.Struct>(6, _omitFieldNames ? '' : 'publicKeys',
        subBuilder: $0.Struct.$_createMessage)
    ..aOM<$0.Struct>(7, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..aOM<$3.FieldMask>(8, _omitFieldNames ? '' : 'updateMask',
        subBuilder: $3.FieldMask.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdateServiceAccountRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdateServiceAccountRequest copyWith(
          void Function(UpdateServiceAccountRequest) updates) =>
      super.copyWith(
              (message) => updates(message as UpdateServiceAccountRequest))
          as UpdateServiceAccountRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use UpdateServiceAccountRequest() / UpdateServiceAccountRequest.new instead')
  static UpdateServiceAccountRequest create() =>
      UpdateServiceAccountRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      UpdateServiceAccountRequest._();
  @$core.override
  UpdateServiceAccountRequest createEmptyInstance() =>
      UpdateServiceAccountRequest._();
  @$core.pragma('dart2js:noInline')
  static UpdateServiceAccountRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdateServiceAccountRequest>(
          UpdateServiceAccountRequest.$_createMessage);
  static UpdateServiceAccountRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get name => $_getSZ(1);
  @$pb.TagNumber(2)
  set name($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasName() => $_has(1);
  @$pb.TagNumber(2)
  void clearName() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get type => $_getSZ(2);
  @$pb.TagNumber(3)
  set type($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasType() => $_has(2);
  @$pb.TagNumber(3)
  void clearType() => $_clearField(3);

  @$pb.TagNumber(4)
  OAuthClientConfiguration get oauthClient => $_getN(3);
  @$pb.TagNumber(4)
  set oauthClient(OAuthClientConfiguration value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasOauthClient() => $_has(3);
  @$pb.TagNumber(4)
  void clearOauthClient() => $_clearField(4);
  @$pb.TagNumber(4)
  OAuthClientConfiguration ensureOauthClient() => $_ensure(3);

  @$pb.TagNumber(5)
  ServiceAuthorizationPolicyInput get authorizationPolicy => $_getN(4);
  @$pb.TagNumber(5)
  set authorizationPolicy(ServiceAuthorizationPolicyInput value) =>
      $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasAuthorizationPolicy() => $_has(4);
  @$pb.TagNumber(5)
  void clearAuthorizationPolicy() => $_clearField(5);
  @$pb.TagNumber(5)
  ServiceAuthorizationPolicyInput ensureAuthorizationPolicy() => $_ensure(4);

  @$pb.TagNumber(6)
  $0.Struct get publicKeys => $_getN(5);
  @$pb.TagNumber(6)
  set publicKeys($0.Struct value) => $_setField(6, value);
  @$pb.TagNumber(6)
  $core.bool hasPublicKeys() => $_has(5);
  @$pb.TagNumber(6)
  void clearPublicKeys() => $_clearField(6);
  @$pb.TagNumber(6)
  $0.Struct ensurePublicKeys() => $_ensure(5);

  @$pb.TagNumber(7)
  $0.Struct get properties => $_getN(6);
  @$pb.TagNumber(7)
  set properties($0.Struct value) => $_setField(7, value);
  @$pb.TagNumber(7)
  $core.bool hasProperties() => $_has(6);
  @$pb.TagNumber(7)
  void clearProperties() => $_clearField(7);
  @$pb.TagNumber(7)
  $0.Struct ensureProperties() => $_ensure(6);

  @$pb.TagNumber(8)
  $3.FieldMask get updateMask => $_getN(7);
  @$pb.TagNumber(8)
  set updateMask($3.FieldMask value) => $_setField(8, value);
  @$pb.TagNumber(8)
  $core.bool hasUpdateMask() => $_has(7);
  @$pb.TagNumber(8)
  void clearUpdateMask() => $_clearField(8);
  @$pb.TagNumber(8)
  $3.FieldMask ensureUpdateMask() => $_ensure(7);
}

class UpdateServiceAccountResponse extends $pb.GeneratedMessage {
  factory UpdateServiceAccountResponse({
    ServiceAccount? data,
  }) {
    final result = UpdateServiceAccountResponse._();
    if (data != null) result.data = data;
    return result;
  }

  UpdateServiceAccountResponse._();

  factory UpdateServiceAccountResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdateServiceAccountResponse()..mergeFromBuffer(data, registry);
  factory UpdateServiceAccountResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdateServiceAccountResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdateServiceAccountResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: UpdateServiceAccountResponse.$_createMessage)
    ..aOM<ServiceAccount>(1, _omitFieldNames ? '' : 'data',
        subBuilder: ServiceAccount.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdateServiceAccountResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdateServiceAccountResponse copyWith(
          void Function(UpdateServiceAccountResponse) updates) =>
      super.copyWith(
              (message) => updates(message as UpdateServiceAccountResponse))
          as UpdateServiceAccountResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use UpdateServiceAccountResponse() / UpdateServiceAccountResponse.new instead')
  static UpdateServiceAccountResponse create() =>
      UpdateServiceAccountResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      UpdateServiceAccountResponse._();
  @$core.override
  UpdateServiceAccountResponse createEmptyInstance() =>
      UpdateServiceAccountResponse._();
  @$core.pragma('dart2js:noInline')
  static UpdateServiceAccountResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdateServiceAccountResponse>(
          UpdateServiceAccountResponse.$_createMessage);
  static UpdateServiceAccountResponse? _defaultInstance;

  @$pb.TagNumber(1)
  ServiceAccount get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(ServiceAccount value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  ServiceAccount ensureData() => $_ensure(0);
}

class RemoveServiceAccountRequest extends $pb.GeneratedMessage {
  factory RemoveServiceAccountRequest({
    $core.String? id,
  }) {
    final result = RemoveServiceAccountRequest._();
    if (id != null) result.id = id;
    return result;
  }

  RemoveServiceAccountRequest._();

  factory RemoveServiceAccountRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveServiceAccountRequest()..mergeFromBuffer(data, registry);
  factory RemoveServiceAccountRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveServiceAccountRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveServiceAccountRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: RemoveServiceAccountRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveServiceAccountRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveServiceAccountRequest copyWith(
          void Function(RemoveServiceAccountRequest) updates) =>
      super.copyWith(
              (message) => updates(message as RemoveServiceAccountRequest))
          as RemoveServiceAccountRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RemoveServiceAccountRequest() / RemoveServiceAccountRequest.new instead')
  static RemoveServiceAccountRequest create() =>
      RemoveServiceAccountRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      RemoveServiceAccountRequest._();
  @$core.override
  RemoveServiceAccountRequest createEmptyInstance() =>
      RemoveServiceAccountRequest._();
  @$core.pragma('dart2js:noInline')
  static RemoveServiceAccountRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveServiceAccountRequest>(
          RemoveServiceAccountRequest.$_createMessage);
  static RemoveServiceAccountRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class RemoveServiceAccountResponse extends $pb.GeneratedMessage {
  factory RemoveServiceAccountResponse({
    $core.bool? succeeded,
  }) {
    final result = RemoveServiceAccountResponse._();
    if (succeeded != null) result.succeeded = succeeded;
    return result;
  }

  RemoveServiceAccountResponse._();

  factory RemoveServiceAccountResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveServiceAccountResponse()..mergeFromBuffer(data, registry);
  factory RemoveServiceAccountResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveServiceAccountResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveServiceAccountResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: RemoveServiceAccountResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'succeeded')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveServiceAccountResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveServiceAccountResponse copyWith(
          void Function(RemoveServiceAccountResponse) updates) =>
      super.copyWith(
              (message) => updates(message as RemoveServiceAccountResponse))
          as RemoveServiceAccountResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RemoveServiceAccountResponse() / RemoveServiceAccountResponse.new instead')
  static RemoveServiceAccountResponse create() =>
      RemoveServiceAccountResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      RemoveServiceAccountResponse._();
  @$core.override
  RemoveServiceAccountResponse createEmptyInstance() =>
      RemoveServiceAccountResponse._();
  @$core.pragma('dart2js:noInline')
  static RemoveServiceAccountResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveServiceAccountResponse>(
          RemoveServiceAccountResponse.$_createMessage);
  static RemoveServiceAccountResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get succeeded => $_getBF(0);
  @$pb.TagNumber(1)
  set succeeded($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSucceeded() => $_has(0);
  @$pb.TagNumber(1)
  void clearSucceeded() => $_clearField(1);
}

class ReconcileServiceAccountAuthorizationRequest extends $pb.GeneratedMessage {
  factory ReconcileServiceAccountAuthorizationRequest({
    $core.String? id,
  }) {
    final result = ReconcileServiceAccountAuthorizationRequest._();
    if (id != null) result.id = id;
    return result;
  }

  ReconcileServiceAccountAuthorizationRequest._();

  factory ReconcileServiceAccountAuthorizationRequest.fromBuffer(
          $core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ReconcileServiceAccountAuthorizationRequest()
        ..mergeFromBuffer(data, registry);
  factory ReconcileServiceAccountAuthorizationRequest.fromJson(
          $core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ReconcileServiceAccountAuthorizationRequest()
        ..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ReconcileServiceAccountAuthorizationRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance:
          ReconcileServiceAccountAuthorizationRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ReconcileServiceAccountAuthorizationRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ReconcileServiceAccountAuthorizationRequest copyWith(
          void Function(ReconcileServiceAccountAuthorizationRequest) updates) =>
      super.copyWith((message) =>
              updates(message as ReconcileServiceAccountAuthorizationRequest))
          as ReconcileServiceAccountAuthorizationRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ReconcileServiceAccountAuthorizationRequest() / ReconcileServiceAccountAuthorizationRequest.new instead')
  static ReconcileServiceAccountAuthorizationRequest create() =>
      ReconcileServiceAccountAuthorizationRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      ReconcileServiceAccountAuthorizationRequest._();
  @$core.override
  ReconcileServiceAccountAuthorizationRequest createEmptyInstance() =>
      ReconcileServiceAccountAuthorizationRequest._();
  @$core.pragma('dart2js:noInline')
  static ReconcileServiceAccountAuthorizationRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<
              ReconcileServiceAccountAuthorizationRequest>(
          ReconcileServiceAccountAuthorizationRequest.$_createMessage);
  static ReconcileServiceAccountAuthorizationRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class ReconcileServiceAccountAuthorizationResponse
    extends $pb.GeneratedMessage {
  factory ReconcileServiceAccountAuthorizationResponse({
    $fixnum.Int64? generation,
  }) {
    final result = ReconcileServiceAccountAuthorizationResponse._();
    if (generation != null) result.generation = generation;
    return result;
  }

  ReconcileServiceAccountAuthorizationResponse._();

  factory ReconcileServiceAccountAuthorizationResponse.fromBuffer(
          $core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ReconcileServiceAccountAuthorizationResponse()
        ..mergeFromBuffer(data, registry);
  factory ReconcileServiceAccountAuthorizationResponse.fromJson(
          $core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ReconcileServiceAccountAuthorizationResponse()
        ..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ReconcileServiceAccountAuthorizationResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance:
          ReconcileServiceAccountAuthorizationResponse.$_createMessage)
    ..aInt64(1, _omitFieldNames ? '' : 'generation')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ReconcileServiceAccountAuthorizationResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ReconcileServiceAccountAuthorizationResponse copyWith(
          void Function(ReconcileServiceAccountAuthorizationResponse)
              updates) =>
      super.copyWith((message) =>
              updates(message as ReconcileServiceAccountAuthorizationResponse))
          as ReconcileServiceAccountAuthorizationResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ReconcileServiceAccountAuthorizationResponse() / ReconcileServiceAccountAuthorizationResponse.new instead')
  static ReconcileServiceAccountAuthorizationResponse create() =>
      ReconcileServiceAccountAuthorizationResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      ReconcileServiceAccountAuthorizationResponse._();
  @$core.override
  ReconcileServiceAccountAuthorizationResponse createEmptyInstance() =>
      ReconcileServiceAccountAuthorizationResponse._();
  @$core.pragma('dart2js:noInline')
  static ReconcileServiceAccountAuthorizationResponse getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<
              ReconcileServiceAccountAuthorizationResponse>(
          ReconcileServiceAccountAuthorizationResponse.$_createMessage);
  static ReconcileServiceAccountAuthorizationResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $fixnum.Int64 get generation => $_getI64(0);
  @$pb.TagNumber(1)
  set generation($fixnum.Int64 value) => $_setInt64(0, value);
  @$pb.TagNumber(1)
  $core.bool hasGeneration() => $_has(0);
  @$pb.TagNumber(1)
  void clearGeneration() => $_clearField(1);
}

class AuthContractServiceApi {
  final $pb.RpcClient _client;

  AuthContractServiceApi(this._client);

  $async.Future<CreateOAuthClientResponse> createOAuthClient(
          $pb.ClientContext? ctx, CreateOAuthClientRequest request) =>
      _client.invoke<CreateOAuthClientResponse>(ctx, 'AuthContractService',
          'CreateOAuthClient', request, CreateOAuthClientResponse());
  $async.Future<GetOAuthClientResponse> getOAuthClient(
          $pb.ClientContext? ctx, GetOAuthClientRequest request) =>
      _client.invoke<GetOAuthClientResponse>(ctx, 'AuthContractService',
          'GetOAuthClient', request, GetOAuthClientResponse());
  $async.Future<ListOAuthClientsResponse> listOAuthClients(
          $pb.ClientContext? ctx, ListOAuthClientsRequest request) =>
      _client.invoke<ListOAuthClientsResponse>(ctx, 'AuthContractService',
          'ListOAuthClients', request, ListOAuthClientsResponse());
  $async.Future<UpdateOAuthClientResponse> updateOAuthClient(
          $pb.ClientContext? ctx, UpdateOAuthClientRequest request) =>
      _client.invoke<UpdateOAuthClientResponse>(ctx, 'AuthContractService',
          'UpdateOAuthClient', request, UpdateOAuthClientResponse());
  $async.Future<RemoveOAuthClientResponse> removeOAuthClient(
          $pb.ClientContext? ctx, RemoveOAuthClientRequest request) =>
      _client.invoke<RemoveOAuthClientResponse>(ctx, 'AuthContractService',
          'RemoveOAuthClient', request, RemoveOAuthClientResponse());
  $async.Future<CreateServiceAccountResponse> createServiceAccount(
          $pb.ClientContext? ctx, CreateServiceAccountRequest request) =>
      _client.invoke<CreateServiceAccountResponse>(ctx, 'AuthContractService',
          'CreateServiceAccount', request, CreateServiceAccountResponse());
  $async.Future<GetServiceAccountResponse> getServiceAccount(
          $pb.ClientContext? ctx, GetServiceAccountRequest request) =>
      _client.invoke<GetServiceAccountResponse>(ctx, 'AuthContractService',
          'GetServiceAccount', request, GetServiceAccountResponse());
  $async.Future<ListServiceAccountsResponse> listServiceAccounts(
          $pb.ClientContext? ctx, ListServiceAccountsRequest request) =>
      _client.invoke<ListServiceAccountsResponse>(ctx, 'AuthContractService',
          'ListServiceAccounts', request, ListServiceAccountsResponse());
  $async.Future<UpdateServiceAccountResponse> updateServiceAccount(
          $pb.ClientContext? ctx, UpdateServiceAccountRequest request) =>
      _client.invoke<UpdateServiceAccountResponse>(ctx, 'AuthContractService',
          'UpdateServiceAccount', request, UpdateServiceAccountResponse());
  $async.Future<RemoveServiceAccountResponse> removeServiceAccount(
          $pb.ClientContext? ctx, RemoveServiceAccountRequest request) =>
      _client.invoke<RemoveServiceAccountResponse>(ctx, 'AuthContractService',
          'RemoveServiceAccount', request, RemoveServiceAccountResponse());
  $async.Future<ReconcileServiceAccountAuthorizationResponse>
      reconcileServiceAccountAuthorization($pb.ClientContext? ctx,
              ReconcileServiceAccountAuthorizationRequest request) =>
          _client.invoke<ReconcileServiceAccountAuthorizationResponse>(
              ctx,
              'AuthContractService',
              'ReconcileServiceAccountAuthorization',
              request,
              ReconcileServiceAccountAuthorizationResponse());
}

const $core.bool _omitFieldNames =
    $core.bool.fromEnvironment('protobuf.omit_field_names');
const $core.bool _omitMessageNames =
    $core.bool.fromEnvironment('protobuf.omit_message_names');
