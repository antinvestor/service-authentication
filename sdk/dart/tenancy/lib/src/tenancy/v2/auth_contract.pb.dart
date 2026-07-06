//
//  Generated code. Do not modify.
//  source: tenancy/v2/auth_contract.proto
//
// @dart = 2.12

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_final_fields
// ignore_for_file: unnecessary_import, unnecessary_this, unused_import

import 'dart:async' as $async;
import 'dart:core' as $core;

import 'package:fixnum/fixnum.dart' as $fixnum;
import 'package:protobuf/protobuf.dart' as $pb;

import '../../common/v1/common.pb.dart' as $7;
import '../../common/v1/common.pbenum.dart' as $7;
import '../../google/protobuf/field_mask.pb.dart' as $1;
import '../../google/protobuf/struct.pb.dart' as $6;
import '../../google/protobuf/timestamp.pb.dart' as $2;
import 'auth_contract.pbenum.dart';

export 'auth_contract.pbenum.dart';

class OAuthClientConfiguration extends $pb.GeneratedMessage {
  factory OAuthClientConfiguration({
    $core.Iterable<$core.String>? grantTypes,
    $core.Iterable<$core.String>? responseTypes,
    $core.Iterable<$core.String>? redirectUris,
    $core.String? scopes,
    $core.Iterable<$core.String>? resourceRecipients,
    $core.String? tokenEndpointAuthMethod,
    $6.Struct? properties,
  }) {
    final $result = create();
    if (grantTypes != null) {
      $result.grantTypes.addAll(grantTypes);
    }
    if (responseTypes != null) {
      $result.responseTypes.addAll(responseTypes);
    }
    if (redirectUris != null) {
      $result.redirectUris.addAll(redirectUris);
    }
    if (scopes != null) {
      $result.scopes = scopes;
    }
    if (resourceRecipients != null) {
      $result.resourceRecipients.addAll(resourceRecipients);
    }
    if (tokenEndpointAuthMethod != null) {
      $result.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }
    if (properties != null) {
      $result.properties = properties;
    }
    return $result;
  }
  OAuthClientConfiguration._() : super();
  factory OAuthClientConfiguration.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory OAuthClientConfiguration.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'OAuthClientConfiguration',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..pPS(1, _omitFieldNames ? '' : 'grantTypes')
    ..pPS(2, _omitFieldNames ? '' : 'responseTypes')
    ..pPS(3, _omitFieldNames ? '' : 'redirectUris')
    ..aOS(4, _omitFieldNames ? '' : 'scopes')
    ..pPS(5, _omitFieldNames ? '' : 'resourceRecipients')
    ..aOS(6, _omitFieldNames ? '' : 'tokenEndpointAuthMethod')
    ..aOM<$6.Struct>(7, _omitFieldNames ? '' : 'properties',
        subBuilder: $6.Struct.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  OAuthClientConfiguration clone() =>
      OAuthClientConfiguration()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  OAuthClientConfiguration copyWith(
          void Function(OAuthClientConfiguration) updates) =>
      super.copyWith((message) => updates(message as OAuthClientConfiguration))
          as OAuthClientConfiguration;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static OAuthClientConfiguration create() => OAuthClientConfiguration._();
  OAuthClientConfiguration createEmptyInstance() => create();
  static $pb.PbList<OAuthClientConfiguration> createRepeated() =>
      $pb.PbList<OAuthClientConfiguration>();
  @$core.pragma('dart2js:noInline')
  static OAuthClientConfiguration getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<OAuthClientConfiguration>(create);
  static OAuthClientConfiguration? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<$core.String> get grantTypes => $_getList(0);

  @$pb.TagNumber(2)
  $core.List<$core.String> get responseTypes => $_getList(1);

  @$pb.TagNumber(3)
  $core.List<$core.String> get redirectUris => $_getList(2);

  @$pb.TagNumber(4)
  $core.String get scopes => $_getSZ(3);
  @$pb.TagNumber(4)
  set scopes($core.String v) {
    $_setString(3, v);
  }

  @$pb.TagNumber(4)
  $core.bool hasScopes() => $_has(3);
  @$pb.TagNumber(4)
  void clearScopes() => clearField(4);

  @$pb.TagNumber(5)
  $core.List<$core.String> get resourceRecipients => $_getList(4);

  @$pb.TagNumber(6)
  $core.String get tokenEndpointAuthMethod => $_getSZ(5);
  @$pb.TagNumber(6)
  set tokenEndpointAuthMethod($core.String v) {
    $_setString(5, v);
  }

  @$pb.TagNumber(6)
  $core.bool hasTokenEndpointAuthMethod() => $_has(5);
  @$pb.TagNumber(6)
  void clearTokenEndpointAuthMethod() => clearField(6);

  @$pb.TagNumber(7)
  $6.Struct get properties => $_getN(6);
  @$pb.TagNumber(7)
  set properties($6.Struct v) {
    setField(7, v);
  }

  @$pb.TagNumber(7)
  $core.bool hasProperties() => $_has(6);
  @$pb.TagNumber(7)
  void clearProperties() => clearField(7);
  @$pb.TagNumber(7)
  $6.Struct ensureProperties() => $_ensure(6);
}

enum OAuthClient_Owner { partitionId, serviceAccountId, notSet }

class OAuthClient extends $pb.GeneratedMessage {
  factory OAuthClient({
    $core.String? id,
    $core.String? name,
    $core.String? clientId,
    $core.String? type,
    OAuthClientConfiguration? configuration,
    $7.STATE? state,
    $2.Timestamp? createdAt,
    $core.String? partitionId,
    $core.String? serviceAccountId,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    if (name != null) {
      $result.name = name;
    }
    if (clientId != null) {
      $result.clientId = clientId;
    }
    if (type != null) {
      $result.type = type;
    }
    if (configuration != null) {
      $result.configuration = configuration;
    }
    if (state != null) {
      $result.state = state;
    }
    if (createdAt != null) {
      $result.createdAt = createdAt;
    }
    if (partitionId != null) {
      $result.partitionId = partitionId;
    }
    if (serviceAccountId != null) {
      $result.serviceAccountId = serviceAccountId;
    }
    return $result;
  }
  OAuthClient._() : super();
  factory OAuthClient.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory OAuthClient.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static const $core.Map<$core.int, OAuthClient_Owner> _OAuthClient_OwnerByTag =
      {
    8: OAuthClient_Owner.partitionId,
    9: OAuthClient_Owner.serviceAccountId,
    0: OAuthClient_Owner.notSet
  };
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'OAuthClient',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..oo(0, [8, 9])
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'clientId')
    ..aOS(4, _omitFieldNames ? '' : 'type')
    ..aOM<OAuthClientConfiguration>(5, _omitFieldNames ? '' : 'configuration',
        subBuilder: OAuthClientConfiguration.create)
    ..e<$7.STATE>(6, _omitFieldNames ? '' : 'state', $pb.PbFieldType.OE,
        defaultOrMaker: $7.STATE.CREATED,
        valueOf: $7.STATE.valueOf,
        enumValues: $7.STATE.values)
    ..aOM<$2.Timestamp>(7, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $2.Timestamp.create)
    ..aOS(8, _omitFieldNames ? '' : 'partitionId')
    ..aOS(9, _omitFieldNames ? '' : 'serviceAccountId')
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  OAuthClient clone() => OAuthClient()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  OAuthClient copyWith(void Function(OAuthClient) updates) =>
      super.copyWith((message) => updates(message as OAuthClient))
          as OAuthClient;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static OAuthClient create() => OAuthClient._();
  OAuthClient createEmptyInstance() => create();
  static $pb.PbList<OAuthClient> createRepeated() => $pb.PbList<OAuthClient>();
  @$core.pragma('dart2js:noInline')
  static OAuthClient getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<OAuthClient>(create);
  static OAuthClient? _defaultInstance;

  OAuthClient_Owner whichOwner() => _OAuthClient_OwnerByTag[$_whichOneof(0)]!;
  void clearOwner() => clearField($_whichOneof(0));

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get name => $_getSZ(1);
  @$pb.TagNumber(2)
  set name($core.String v) {
    $_setString(1, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasName() => $_has(1);
  @$pb.TagNumber(2)
  void clearName() => clearField(2);

  @$pb.TagNumber(3)
  $core.String get clientId => $_getSZ(2);
  @$pb.TagNumber(3)
  set clientId($core.String v) {
    $_setString(2, v);
  }

  @$pb.TagNumber(3)
  $core.bool hasClientId() => $_has(2);
  @$pb.TagNumber(3)
  void clearClientId() => clearField(3);

  @$pb.TagNumber(4)
  $core.String get type => $_getSZ(3);
  @$pb.TagNumber(4)
  set type($core.String v) {
    $_setString(3, v);
  }

  @$pb.TagNumber(4)
  $core.bool hasType() => $_has(3);
  @$pb.TagNumber(4)
  void clearType() => clearField(4);

  @$pb.TagNumber(5)
  OAuthClientConfiguration get configuration => $_getN(4);
  @$pb.TagNumber(5)
  set configuration(OAuthClientConfiguration v) {
    setField(5, v);
  }

  @$pb.TagNumber(5)
  $core.bool hasConfiguration() => $_has(4);
  @$pb.TagNumber(5)
  void clearConfiguration() => clearField(5);
  @$pb.TagNumber(5)
  OAuthClientConfiguration ensureConfiguration() => $_ensure(4);

  @$pb.TagNumber(6)
  $7.STATE get state => $_getN(5);
  @$pb.TagNumber(6)
  set state($7.STATE v) {
    setField(6, v);
  }

  @$pb.TagNumber(6)
  $core.bool hasState() => $_has(5);
  @$pb.TagNumber(6)
  void clearState() => clearField(6);

  @$pb.TagNumber(7)
  $2.Timestamp get createdAt => $_getN(6);
  @$pb.TagNumber(7)
  set createdAt($2.Timestamp v) {
    setField(7, v);
  }

  @$pb.TagNumber(7)
  $core.bool hasCreatedAt() => $_has(6);
  @$pb.TagNumber(7)
  void clearCreatedAt() => clearField(7);
  @$pb.TagNumber(7)
  $2.Timestamp ensureCreatedAt() => $_ensure(6);

  @$pb.TagNumber(8)
  $core.String get partitionId => $_getSZ(7);
  @$pb.TagNumber(8)
  set partitionId($core.String v) {
    $_setString(7, v);
  }

  @$pb.TagNumber(8)
  $core.bool hasPartitionId() => $_has(7);
  @$pb.TagNumber(8)
  void clearPartitionId() => clearField(8);

  @$pb.TagNumber(9)
  $core.String get serviceAccountId => $_getSZ(8);
  @$pb.TagNumber(9)
  set serviceAccountId($core.String v) {
    $_setString(8, v);
  }

  @$pb.TagNumber(9)
  $core.bool hasServiceAccountId() => $_has(8);
  @$pb.TagNumber(9)
  void clearServiceAccountId() => clearField(9);
}

class ServiceAuthorizationGrant extends $pb.GeneratedMessage {
  factory ServiceAuthorizationGrant({
    $core.String? namespace,
    $core.Iterable<$core.String>? permissions,
    AuthorizationScope? scope,
  }) {
    final $result = create();
    if (namespace != null) {
      $result.namespace = namespace;
    }
    if (permissions != null) {
      $result.permissions.addAll(permissions);
    }
    if (scope != null) {
      $result.scope = scope;
    }
    return $result;
  }
  ServiceAuthorizationGrant._() : super();
  factory ServiceAuthorizationGrant.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory ServiceAuthorizationGrant.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ServiceAuthorizationGrant',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'namespace')
    ..pPS(2, _omitFieldNames ? '' : 'permissions')
    ..e<AuthorizationScope>(
        3, _omitFieldNames ? '' : 'scope', $pb.PbFieldType.OE,
        defaultOrMaker: AuthorizationScope.AUTHORIZATION_SCOPE_UNSPECIFIED,
        valueOf: AuthorizationScope.valueOf,
        enumValues: AuthorizationScope.values)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  ServiceAuthorizationGrant clone() =>
      ServiceAuthorizationGrant()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  ServiceAuthorizationGrant copyWith(
          void Function(ServiceAuthorizationGrant) updates) =>
      super.copyWith((message) => updates(message as ServiceAuthorizationGrant))
          as ServiceAuthorizationGrant;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ServiceAuthorizationGrant create() => ServiceAuthorizationGrant._();
  ServiceAuthorizationGrant createEmptyInstance() => create();
  static $pb.PbList<ServiceAuthorizationGrant> createRepeated() =>
      $pb.PbList<ServiceAuthorizationGrant>();
  @$core.pragma('dart2js:noInline')
  static ServiceAuthorizationGrant getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ServiceAuthorizationGrant>(create);
  static ServiceAuthorizationGrant? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get namespace => $_getSZ(0);
  @$pb.TagNumber(1)
  set namespace($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasNamespace() => $_has(0);
  @$pb.TagNumber(1)
  void clearNamespace() => clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.String> get permissions => $_getList(1);

  @$pb.TagNumber(3)
  AuthorizationScope get scope => $_getN(2);
  @$pb.TagNumber(3)
  set scope(AuthorizationScope v) {
    setField(3, v);
  }

  @$pb.TagNumber(3)
  $core.bool hasScope() => $_has(2);
  @$pb.TagNumber(3)
  void clearScope() => clearField(3);
}

class ServiceAuthorizationPolicyInput extends $pb.GeneratedMessage {
  factory ServiceAuthorizationPolicyInput({
    $core.int? schemaVersion,
    $core.Iterable<ServiceAuthorizationGrant>? grants,
  }) {
    final $result = create();
    if (schemaVersion != null) {
      $result.schemaVersion = schemaVersion;
    }
    if (grants != null) {
      $result.grants.addAll(grants);
    }
    return $result;
  }
  ServiceAuthorizationPolicyInput._() : super();
  factory ServiceAuthorizationPolicyInput.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory ServiceAuthorizationPolicyInput.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ServiceAuthorizationPolicyInput',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..a<$core.int>(
        1, _omitFieldNames ? '' : 'schemaVersion', $pb.PbFieldType.O3)
    ..pc<ServiceAuthorizationGrant>(
        2, _omitFieldNames ? '' : 'grants', $pb.PbFieldType.PM,
        subBuilder: ServiceAuthorizationGrant.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  ServiceAuthorizationPolicyInput clone() =>
      ServiceAuthorizationPolicyInput()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  ServiceAuthorizationPolicyInput copyWith(
          void Function(ServiceAuthorizationPolicyInput) updates) =>
      super.copyWith(
              (message) => updates(message as ServiceAuthorizationPolicyInput))
          as ServiceAuthorizationPolicyInput;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ServiceAuthorizationPolicyInput create() =>
      ServiceAuthorizationPolicyInput._();
  ServiceAuthorizationPolicyInput createEmptyInstance() => create();
  static $pb.PbList<ServiceAuthorizationPolicyInput> createRepeated() =>
      $pb.PbList<ServiceAuthorizationPolicyInput>();
  @$core.pragma('dart2js:noInline')
  static ServiceAuthorizationPolicyInput getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ServiceAuthorizationPolicyInput>(
          create);
  static ServiceAuthorizationPolicyInput? _defaultInstance;

  @$pb.TagNumber(1)
  $core.int get schemaVersion => $_getIZ(0);
  @$pb.TagNumber(1)
  set schemaVersion($core.int v) {
    $_setSignedInt32(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasSchemaVersion() => $_has(0);
  @$pb.TagNumber(1)
  void clearSchemaVersion() => clearField(1);

  @$pb.TagNumber(2)
  $core.List<ServiceAuthorizationGrant> get grants => $_getList(1);
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
    $2.Timestamp? nextAttemptAt,
    $2.Timestamp? syncedAt,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    if (schemaVersion != null) {
      $result.schemaVersion = schemaVersion;
    }
    if (generation != null) {
      $result.generation = generation;
    }
    if (appliedGeneration != null) {
      $result.appliedGeneration = appliedGeneration;
    }
    if (status != null) {
      $result.status = status;
    }
    if (grants != null) {
      $result.grants.addAll(grants);
    }
    if (lastErrorCode != null) {
      $result.lastErrorCode = lastErrorCode;
    }
    if (nextAttemptAt != null) {
      $result.nextAttemptAt = nextAttemptAt;
    }
    if (syncedAt != null) {
      $result.syncedAt = syncedAt;
    }
    return $result;
  }
  ServiceAuthorizationPolicy._() : super();
  factory ServiceAuthorizationPolicy.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory ServiceAuthorizationPolicy.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ServiceAuthorizationPolicy',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..a<$core.int>(
        2, _omitFieldNames ? '' : 'schemaVersion', $pb.PbFieldType.O3)
    ..aInt64(3, _omitFieldNames ? '' : 'generation')
    ..aInt64(4, _omitFieldNames ? '' : 'appliedGeneration')
    ..e<AuthorizationPolicyStatus>(
        5, _omitFieldNames ? '' : 'status', $pb.PbFieldType.OE,
        defaultOrMaker:
            AuthorizationPolicyStatus.AUTHORIZATION_POLICY_STATUS_UNSPECIFIED,
        valueOf: AuthorizationPolicyStatus.valueOf,
        enumValues: AuthorizationPolicyStatus.values)
    ..pc<ServiceAuthorizationGrant>(
        6, _omitFieldNames ? '' : 'grants', $pb.PbFieldType.PM,
        subBuilder: ServiceAuthorizationGrant.create)
    ..aOS(7, _omitFieldNames ? '' : 'lastErrorCode')
    ..aOM<$2.Timestamp>(8, _omitFieldNames ? '' : 'nextAttemptAt',
        subBuilder: $2.Timestamp.create)
    ..aOM<$2.Timestamp>(9, _omitFieldNames ? '' : 'syncedAt',
        subBuilder: $2.Timestamp.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  ServiceAuthorizationPolicy clone() =>
      ServiceAuthorizationPolicy()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  ServiceAuthorizationPolicy copyWith(
          void Function(ServiceAuthorizationPolicy) updates) =>
      super.copyWith(
              (message) => updates(message as ServiceAuthorizationPolicy))
          as ServiceAuthorizationPolicy;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ServiceAuthorizationPolicy create() => ServiceAuthorizationPolicy._();
  ServiceAuthorizationPolicy createEmptyInstance() => create();
  static $pb.PbList<ServiceAuthorizationPolicy> createRepeated() =>
      $pb.PbList<ServiceAuthorizationPolicy>();
  @$core.pragma('dart2js:noInline')
  static ServiceAuthorizationPolicy getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ServiceAuthorizationPolicy>(create);
  static ServiceAuthorizationPolicy? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);

  @$pb.TagNumber(2)
  $core.int get schemaVersion => $_getIZ(1);
  @$pb.TagNumber(2)
  set schemaVersion($core.int v) {
    $_setSignedInt32(1, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasSchemaVersion() => $_has(1);
  @$pb.TagNumber(2)
  void clearSchemaVersion() => clearField(2);

  @$pb.TagNumber(3)
  $fixnum.Int64 get generation => $_getI64(2);
  @$pb.TagNumber(3)
  set generation($fixnum.Int64 v) {
    $_setInt64(2, v);
  }

  @$pb.TagNumber(3)
  $core.bool hasGeneration() => $_has(2);
  @$pb.TagNumber(3)
  void clearGeneration() => clearField(3);

  @$pb.TagNumber(4)
  $fixnum.Int64 get appliedGeneration => $_getI64(3);
  @$pb.TagNumber(4)
  set appliedGeneration($fixnum.Int64 v) {
    $_setInt64(3, v);
  }

  @$pb.TagNumber(4)
  $core.bool hasAppliedGeneration() => $_has(3);
  @$pb.TagNumber(4)
  void clearAppliedGeneration() => clearField(4);

  @$pb.TagNumber(5)
  AuthorizationPolicyStatus get status => $_getN(4);
  @$pb.TagNumber(5)
  set status(AuthorizationPolicyStatus v) {
    setField(5, v);
  }

  @$pb.TagNumber(5)
  $core.bool hasStatus() => $_has(4);
  @$pb.TagNumber(5)
  void clearStatus() => clearField(5);

  @$pb.TagNumber(6)
  $core.List<ServiceAuthorizationGrant> get grants => $_getList(5);

  @$pb.TagNumber(7)
  $core.String get lastErrorCode => $_getSZ(6);
  @$pb.TagNumber(7)
  set lastErrorCode($core.String v) {
    $_setString(6, v);
  }

  @$pb.TagNumber(7)
  $core.bool hasLastErrorCode() => $_has(6);
  @$pb.TagNumber(7)
  void clearLastErrorCode() => clearField(7);

  @$pb.TagNumber(8)
  $2.Timestamp get nextAttemptAt => $_getN(7);
  @$pb.TagNumber(8)
  set nextAttemptAt($2.Timestamp v) {
    setField(8, v);
  }

  @$pb.TagNumber(8)
  $core.bool hasNextAttemptAt() => $_has(7);
  @$pb.TagNumber(8)
  void clearNextAttemptAt() => clearField(8);
  @$pb.TagNumber(8)
  $2.Timestamp ensureNextAttemptAt() => $_ensure(7);

  @$pb.TagNumber(9)
  $2.Timestamp get syncedAt => $_getN(8);
  @$pb.TagNumber(9)
  set syncedAt($2.Timestamp v) {
    setField(9, v);
  }

  @$pb.TagNumber(9)
  $core.bool hasSyncedAt() => $_has(8);
  @$pb.TagNumber(9)
  void clearSyncedAt() => clearField(9);
  @$pb.TagNumber(9)
  $2.Timestamp ensureSyncedAt() => $_ensure(8);
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
    $6.Struct? publicKeys,
    $6.Struct? properties,
    $7.STATE? state,
    $2.Timestamp? createdAt,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    if (tenantId != null) {
      $result.tenantId = tenantId;
    }
    if (partitionId != null) {
      $result.partitionId = partitionId;
    }
    if (profileId != null) {
      $result.profileId = profileId;
    }
    if (name != null) {
      $result.name = name;
    }
    if (type != null) {
      $result.type = type;
    }
    if (oauthClient != null) {
      $result.oauthClient = oauthClient;
    }
    if (authorizationPolicy != null) {
      $result.authorizationPolicy = authorizationPolicy;
    }
    if (publicKeys != null) {
      $result.publicKeys = publicKeys;
    }
    if (properties != null) {
      $result.properties = properties;
    }
    if (state != null) {
      $result.state = state;
    }
    if (createdAt != null) {
      $result.createdAt = createdAt;
    }
    return $result;
  }
  ServiceAccount._() : super();
  factory ServiceAccount.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory ServiceAccount.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ServiceAccount',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'tenantId')
    ..aOS(3, _omitFieldNames ? '' : 'partitionId')
    ..aOS(4, _omitFieldNames ? '' : 'profileId')
    ..aOS(5, _omitFieldNames ? '' : 'name')
    ..aOS(6, _omitFieldNames ? '' : 'type')
    ..aOM<OAuthClient>(7, _omitFieldNames ? '' : 'oauthClient',
        subBuilder: OAuthClient.create)
    ..aOM<ServiceAuthorizationPolicy>(
        8, _omitFieldNames ? '' : 'authorizationPolicy',
        subBuilder: ServiceAuthorizationPolicy.create)
    ..aOM<$6.Struct>(9, _omitFieldNames ? '' : 'publicKeys',
        subBuilder: $6.Struct.create)
    ..aOM<$6.Struct>(10, _omitFieldNames ? '' : 'properties',
        subBuilder: $6.Struct.create)
    ..e<$7.STATE>(11, _omitFieldNames ? '' : 'state', $pb.PbFieldType.OE,
        defaultOrMaker: $7.STATE.CREATED,
        valueOf: $7.STATE.valueOf,
        enumValues: $7.STATE.values)
    ..aOM<$2.Timestamp>(12, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $2.Timestamp.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  ServiceAccount clone() => ServiceAccount()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  ServiceAccount copyWith(void Function(ServiceAccount) updates) =>
      super.copyWith((message) => updates(message as ServiceAccount))
          as ServiceAccount;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ServiceAccount create() => ServiceAccount._();
  ServiceAccount createEmptyInstance() => create();
  static $pb.PbList<ServiceAccount> createRepeated() =>
      $pb.PbList<ServiceAccount>();
  @$core.pragma('dart2js:noInline')
  static ServiceAccount getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ServiceAccount>(create);
  static ServiceAccount? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get tenantId => $_getSZ(1);
  @$pb.TagNumber(2)
  set tenantId($core.String v) {
    $_setString(1, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasTenantId() => $_has(1);
  @$pb.TagNumber(2)
  void clearTenantId() => clearField(2);

  @$pb.TagNumber(3)
  $core.String get partitionId => $_getSZ(2);
  @$pb.TagNumber(3)
  set partitionId($core.String v) {
    $_setString(2, v);
  }

  @$pb.TagNumber(3)
  $core.bool hasPartitionId() => $_has(2);
  @$pb.TagNumber(3)
  void clearPartitionId() => clearField(3);

  @$pb.TagNumber(4)
  $core.String get profileId => $_getSZ(3);
  @$pb.TagNumber(4)
  set profileId($core.String v) {
    $_setString(3, v);
  }

  @$pb.TagNumber(4)
  $core.bool hasProfileId() => $_has(3);
  @$pb.TagNumber(4)
  void clearProfileId() => clearField(4);

  @$pb.TagNumber(5)
  $core.String get name => $_getSZ(4);
  @$pb.TagNumber(5)
  set name($core.String v) {
    $_setString(4, v);
  }

  @$pb.TagNumber(5)
  $core.bool hasName() => $_has(4);
  @$pb.TagNumber(5)
  void clearName() => clearField(5);

  @$pb.TagNumber(6)
  $core.String get type => $_getSZ(5);
  @$pb.TagNumber(6)
  set type($core.String v) {
    $_setString(5, v);
  }

  @$pb.TagNumber(6)
  $core.bool hasType() => $_has(5);
  @$pb.TagNumber(6)
  void clearType() => clearField(6);

  @$pb.TagNumber(7)
  OAuthClient get oauthClient => $_getN(6);
  @$pb.TagNumber(7)
  set oauthClient(OAuthClient v) {
    setField(7, v);
  }

  @$pb.TagNumber(7)
  $core.bool hasOauthClient() => $_has(6);
  @$pb.TagNumber(7)
  void clearOauthClient() => clearField(7);
  @$pb.TagNumber(7)
  OAuthClient ensureOauthClient() => $_ensure(6);

  @$pb.TagNumber(8)
  ServiceAuthorizationPolicy get authorizationPolicy => $_getN(7);
  @$pb.TagNumber(8)
  set authorizationPolicy(ServiceAuthorizationPolicy v) {
    setField(8, v);
  }

  @$pb.TagNumber(8)
  $core.bool hasAuthorizationPolicy() => $_has(7);
  @$pb.TagNumber(8)
  void clearAuthorizationPolicy() => clearField(8);
  @$pb.TagNumber(8)
  ServiceAuthorizationPolicy ensureAuthorizationPolicy() => $_ensure(7);

  @$pb.TagNumber(9)
  $6.Struct get publicKeys => $_getN(8);
  @$pb.TagNumber(9)
  set publicKeys($6.Struct v) {
    setField(9, v);
  }

  @$pb.TagNumber(9)
  $core.bool hasPublicKeys() => $_has(8);
  @$pb.TagNumber(9)
  void clearPublicKeys() => clearField(9);
  @$pb.TagNumber(9)
  $6.Struct ensurePublicKeys() => $_ensure(8);

  @$pb.TagNumber(10)
  $6.Struct get properties => $_getN(9);
  @$pb.TagNumber(10)
  set properties($6.Struct v) {
    setField(10, v);
  }

  @$pb.TagNumber(10)
  $core.bool hasProperties() => $_has(9);
  @$pb.TagNumber(10)
  void clearProperties() => clearField(10);
  @$pb.TagNumber(10)
  $6.Struct ensureProperties() => $_ensure(9);

  @$pb.TagNumber(11)
  $7.STATE get state => $_getN(10);
  @$pb.TagNumber(11)
  set state($7.STATE v) {
    setField(11, v);
  }

  @$pb.TagNumber(11)
  $core.bool hasState() => $_has(10);
  @$pb.TagNumber(11)
  void clearState() => clearField(11);

  @$pb.TagNumber(12)
  $2.Timestamp get createdAt => $_getN(11);
  @$pb.TagNumber(12)
  set createdAt($2.Timestamp v) {
    setField(12, v);
  }

  @$pb.TagNumber(12)
  $core.bool hasCreatedAt() => $_has(11);
  @$pb.TagNumber(12)
  void clearCreatedAt() => clearField(12);
  @$pb.TagNumber(12)
  $2.Timestamp ensureCreatedAt() => $_ensure(11);
}

class CreateOAuthClientRequest extends $pb.GeneratedMessage {
  factory CreateOAuthClientRequest({
    $core.String? partitionId,
    $core.String? name,
    $core.String? type,
    OAuthClientConfiguration? configuration,
  }) {
    final $result = create();
    if (partitionId != null) {
      $result.partitionId = partitionId;
    }
    if (name != null) {
      $result.name = name;
    }
    if (type != null) {
      $result.type = type;
    }
    if (configuration != null) {
      $result.configuration = configuration;
    }
    return $result;
  }
  CreateOAuthClientRequest._() : super();
  factory CreateOAuthClientRequest.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory CreateOAuthClientRequest.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateOAuthClientRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'type')
    ..aOM<OAuthClientConfiguration>(4, _omitFieldNames ? '' : 'configuration',
        subBuilder: OAuthClientConfiguration.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  CreateOAuthClientRequest clone() =>
      CreateOAuthClientRequest()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  CreateOAuthClientRequest copyWith(
          void Function(CreateOAuthClientRequest) updates) =>
      super.copyWith((message) => updates(message as CreateOAuthClientRequest))
          as CreateOAuthClientRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static CreateOAuthClientRequest create() => CreateOAuthClientRequest._();
  CreateOAuthClientRequest createEmptyInstance() => create();
  static $pb.PbList<CreateOAuthClientRequest> createRepeated() =>
      $pb.PbList<CreateOAuthClientRequest>();
  @$core.pragma('dart2js:noInline')
  static CreateOAuthClientRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateOAuthClientRequest>(create);
  static CreateOAuthClientRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get partitionId => $_getSZ(0);
  @$pb.TagNumber(1)
  set partitionId($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasPartitionId() => $_has(0);
  @$pb.TagNumber(1)
  void clearPartitionId() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get name => $_getSZ(1);
  @$pb.TagNumber(2)
  set name($core.String v) {
    $_setString(1, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasName() => $_has(1);
  @$pb.TagNumber(2)
  void clearName() => clearField(2);

  @$pb.TagNumber(3)
  $core.String get type => $_getSZ(2);
  @$pb.TagNumber(3)
  set type($core.String v) {
    $_setString(2, v);
  }

  @$pb.TagNumber(3)
  $core.bool hasType() => $_has(2);
  @$pb.TagNumber(3)
  void clearType() => clearField(3);

  @$pb.TagNumber(4)
  OAuthClientConfiguration get configuration => $_getN(3);
  @$pb.TagNumber(4)
  set configuration(OAuthClientConfiguration v) {
    setField(4, v);
  }

  @$pb.TagNumber(4)
  $core.bool hasConfiguration() => $_has(3);
  @$pb.TagNumber(4)
  void clearConfiguration() => clearField(4);
  @$pb.TagNumber(4)
  OAuthClientConfiguration ensureConfiguration() => $_ensure(3);
}

class CreateOAuthClientResponse extends $pb.GeneratedMessage {
  factory CreateOAuthClientResponse({
    OAuthClient? data,
    $core.String? clientSecret,
  }) {
    final $result = create();
    if (data != null) {
      $result.data = data;
    }
    if (clientSecret != null) {
      $result.clientSecret = clientSecret;
    }
    return $result;
  }
  CreateOAuthClientResponse._() : super();
  factory CreateOAuthClientResponse.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory CreateOAuthClientResponse.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateOAuthClientResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOM<OAuthClient>(1, _omitFieldNames ? '' : 'data',
        subBuilder: OAuthClient.create)
    ..aOS(2, _omitFieldNames ? '' : 'clientSecret')
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  CreateOAuthClientResponse clone() =>
      CreateOAuthClientResponse()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  CreateOAuthClientResponse copyWith(
          void Function(CreateOAuthClientResponse) updates) =>
      super.copyWith((message) => updates(message as CreateOAuthClientResponse))
          as CreateOAuthClientResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static CreateOAuthClientResponse create() => CreateOAuthClientResponse._();
  CreateOAuthClientResponse createEmptyInstance() => create();
  static $pb.PbList<CreateOAuthClientResponse> createRepeated() =>
      $pb.PbList<CreateOAuthClientResponse>();
  @$core.pragma('dart2js:noInline')
  static CreateOAuthClientResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateOAuthClientResponse>(create);
  static CreateOAuthClientResponse? _defaultInstance;

  @$pb.TagNumber(1)
  OAuthClient get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(OAuthClient v) {
    setField(1, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => clearField(1);
  @$pb.TagNumber(1)
  OAuthClient ensureData() => $_ensure(0);

  @$pb.TagNumber(2)
  $core.String get clientSecret => $_getSZ(1);
  @$pb.TagNumber(2)
  set clientSecret($core.String v) {
    $_setString(1, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasClientSecret() => $_has(1);
  @$pb.TagNumber(2)
  void clearClientSecret() => clearField(2);
}

enum GetOAuthClientRequest_Selector { id, clientId, notSet }

class GetOAuthClientRequest extends $pb.GeneratedMessage {
  factory GetOAuthClientRequest({
    $core.String? id,
    $core.String? clientId,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    if (clientId != null) {
      $result.clientId = clientId;
    }
    return $result;
  }
  GetOAuthClientRequest._() : super();
  factory GetOAuthClientRequest.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory GetOAuthClientRequest.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static const $core.Map<$core.int, GetOAuthClientRequest_Selector>
      _GetOAuthClientRequest_SelectorByTag = {
    1: GetOAuthClientRequest_Selector.id,
    2: GetOAuthClientRequest_Selector.clientId,
    0: GetOAuthClientRequest_Selector.notSet
  };
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetOAuthClientRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..oo(0, [1, 2])
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'clientId')
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  GetOAuthClientRequest clone() =>
      GetOAuthClientRequest()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  GetOAuthClientRequest copyWith(
          void Function(GetOAuthClientRequest) updates) =>
      super.copyWith((message) => updates(message as GetOAuthClientRequest))
          as GetOAuthClientRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetOAuthClientRequest create() => GetOAuthClientRequest._();
  GetOAuthClientRequest createEmptyInstance() => create();
  static $pb.PbList<GetOAuthClientRequest> createRepeated() =>
      $pb.PbList<GetOAuthClientRequest>();
  @$core.pragma('dart2js:noInline')
  static GetOAuthClientRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetOAuthClientRequest>(create);
  static GetOAuthClientRequest? _defaultInstance;

  GetOAuthClientRequest_Selector whichSelector() =>
      _GetOAuthClientRequest_SelectorByTag[$_whichOneof(0)]!;
  void clearSelector() => clearField($_whichOneof(0));

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get clientId => $_getSZ(1);
  @$pb.TagNumber(2)
  set clientId($core.String v) {
    $_setString(1, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasClientId() => $_has(1);
  @$pb.TagNumber(2)
  void clearClientId() => clearField(2);
}

class GetOAuthClientResponse extends $pb.GeneratedMessage {
  factory GetOAuthClientResponse({
    OAuthClient? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data = data;
    }
    return $result;
  }
  GetOAuthClientResponse._() : super();
  factory GetOAuthClientResponse.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory GetOAuthClientResponse.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetOAuthClientResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOM<OAuthClient>(1, _omitFieldNames ? '' : 'data',
        subBuilder: OAuthClient.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  GetOAuthClientResponse clone() =>
      GetOAuthClientResponse()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  GetOAuthClientResponse copyWith(
          void Function(GetOAuthClientResponse) updates) =>
      super.copyWith((message) => updates(message as GetOAuthClientResponse))
          as GetOAuthClientResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetOAuthClientResponse create() => GetOAuthClientResponse._();
  GetOAuthClientResponse createEmptyInstance() => create();
  static $pb.PbList<GetOAuthClientResponse> createRepeated() =>
      $pb.PbList<GetOAuthClientResponse>();
  @$core.pragma('dart2js:noInline')
  static GetOAuthClientResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetOAuthClientResponse>(create);
  static GetOAuthClientResponse? _defaultInstance;

  @$pb.TagNumber(1)
  OAuthClient get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(OAuthClient v) {
    setField(1, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => clearField(1);
  @$pb.TagNumber(1)
  OAuthClient ensureData() => $_ensure(0);
}

enum ListOAuthClientsRequest_Owner { partitionId, serviceAccountId, notSet }

class ListOAuthClientsRequest extends $pb.GeneratedMessage {
  factory ListOAuthClientsRequest({
    $core.String? partitionId,
    $core.String? serviceAccountId,
    $7.PageCursor? cursor,
  }) {
    final $result = create();
    if (partitionId != null) {
      $result.partitionId = partitionId;
    }
    if (serviceAccountId != null) {
      $result.serviceAccountId = serviceAccountId;
    }
    if (cursor != null) {
      $result.cursor = cursor;
    }
    return $result;
  }
  ListOAuthClientsRequest._() : super();
  factory ListOAuthClientsRequest.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory ListOAuthClientsRequest.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static const $core.Map<$core.int, ListOAuthClientsRequest_Owner>
      _ListOAuthClientsRequest_OwnerByTag = {
    1: ListOAuthClientsRequest_Owner.partitionId,
    2: ListOAuthClientsRequest_Owner.serviceAccountId,
    0: ListOAuthClientsRequest_Owner.notSet
  };
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListOAuthClientsRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..oo(0, [1, 2])
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOS(2, _omitFieldNames ? '' : 'serviceAccountId')
    ..aOM<$7.PageCursor>(3, _omitFieldNames ? '' : 'cursor',
        subBuilder: $7.PageCursor.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  ListOAuthClientsRequest clone() =>
      ListOAuthClientsRequest()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  ListOAuthClientsRequest copyWith(
          void Function(ListOAuthClientsRequest) updates) =>
      super.copyWith((message) => updates(message as ListOAuthClientsRequest))
          as ListOAuthClientsRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListOAuthClientsRequest create() => ListOAuthClientsRequest._();
  ListOAuthClientsRequest createEmptyInstance() => create();
  static $pb.PbList<ListOAuthClientsRequest> createRepeated() =>
      $pb.PbList<ListOAuthClientsRequest>();
  @$core.pragma('dart2js:noInline')
  static ListOAuthClientsRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListOAuthClientsRequest>(create);
  static ListOAuthClientsRequest? _defaultInstance;

  ListOAuthClientsRequest_Owner whichOwner() =>
      _ListOAuthClientsRequest_OwnerByTag[$_whichOneof(0)]!;
  void clearOwner() => clearField($_whichOneof(0));

  @$pb.TagNumber(1)
  $core.String get partitionId => $_getSZ(0);
  @$pb.TagNumber(1)
  set partitionId($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasPartitionId() => $_has(0);
  @$pb.TagNumber(1)
  void clearPartitionId() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get serviceAccountId => $_getSZ(1);
  @$pb.TagNumber(2)
  set serviceAccountId($core.String v) {
    $_setString(1, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasServiceAccountId() => $_has(1);
  @$pb.TagNumber(2)
  void clearServiceAccountId() => clearField(2);

  @$pb.TagNumber(3)
  $7.PageCursor get cursor => $_getN(2);
  @$pb.TagNumber(3)
  set cursor($7.PageCursor v) {
    setField(3, v);
  }

  @$pb.TagNumber(3)
  $core.bool hasCursor() => $_has(2);
  @$pb.TagNumber(3)
  void clearCursor() => clearField(3);
  @$pb.TagNumber(3)
  $7.PageCursor ensureCursor() => $_ensure(2);
}

class ListOAuthClientsResponse extends $pb.GeneratedMessage {
  factory ListOAuthClientsResponse({
    $core.Iterable<OAuthClient>? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data.addAll(data);
    }
    return $result;
  }
  ListOAuthClientsResponse._() : super();
  factory ListOAuthClientsResponse.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory ListOAuthClientsResponse.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListOAuthClientsResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..pc<OAuthClient>(1, _omitFieldNames ? '' : 'data', $pb.PbFieldType.PM,
        subBuilder: OAuthClient.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  ListOAuthClientsResponse clone() =>
      ListOAuthClientsResponse()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  ListOAuthClientsResponse copyWith(
          void Function(ListOAuthClientsResponse) updates) =>
      super.copyWith((message) => updates(message as ListOAuthClientsResponse))
          as ListOAuthClientsResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListOAuthClientsResponse create() => ListOAuthClientsResponse._();
  ListOAuthClientsResponse createEmptyInstance() => create();
  static $pb.PbList<ListOAuthClientsResponse> createRepeated() =>
      $pb.PbList<ListOAuthClientsResponse>();
  @$core.pragma('dart2js:noInline')
  static ListOAuthClientsResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListOAuthClientsResponse>(create);
  static ListOAuthClientsResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<OAuthClient> get data => $_getList(0);
}

class UpdateOAuthClientRequest extends $pb.GeneratedMessage {
  factory UpdateOAuthClientRequest({
    $core.String? id,
    $core.String? name,
    OAuthClientConfiguration? configuration,
    $1.FieldMask? updateMask,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    if (name != null) {
      $result.name = name;
    }
    if (configuration != null) {
      $result.configuration = configuration;
    }
    if (updateMask != null) {
      $result.updateMask = updateMask;
    }
    return $result;
  }
  UpdateOAuthClientRequest._() : super();
  factory UpdateOAuthClientRequest.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory UpdateOAuthClientRequest.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdateOAuthClientRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOM<OAuthClientConfiguration>(3, _omitFieldNames ? '' : 'configuration',
        subBuilder: OAuthClientConfiguration.create)
    ..aOM<$1.FieldMask>(4, _omitFieldNames ? '' : 'updateMask',
        subBuilder: $1.FieldMask.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  UpdateOAuthClientRequest clone() =>
      UpdateOAuthClientRequest()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  UpdateOAuthClientRequest copyWith(
          void Function(UpdateOAuthClientRequest) updates) =>
      super.copyWith((message) => updates(message as UpdateOAuthClientRequest))
          as UpdateOAuthClientRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static UpdateOAuthClientRequest create() => UpdateOAuthClientRequest._();
  UpdateOAuthClientRequest createEmptyInstance() => create();
  static $pb.PbList<UpdateOAuthClientRequest> createRepeated() =>
      $pb.PbList<UpdateOAuthClientRequest>();
  @$core.pragma('dart2js:noInline')
  static UpdateOAuthClientRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdateOAuthClientRequest>(create);
  static UpdateOAuthClientRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get name => $_getSZ(1);
  @$pb.TagNumber(2)
  set name($core.String v) {
    $_setString(1, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasName() => $_has(1);
  @$pb.TagNumber(2)
  void clearName() => clearField(2);

  @$pb.TagNumber(3)
  OAuthClientConfiguration get configuration => $_getN(2);
  @$pb.TagNumber(3)
  set configuration(OAuthClientConfiguration v) {
    setField(3, v);
  }

  @$pb.TagNumber(3)
  $core.bool hasConfiguration() => $_has(2);
  @$pb.TagNumber(3)
  void clearConfiguration() => clearField(3);
  @$pb.TagNumber(3)
  OAuthClientConfiguration ensureConfiguration() => $_ensure(2);

  @$pb.TagNumber(4)
  $1.FieldMask get updateMask => $_getN(3);
  @$pb.TagNumber(4)
  set updateMask($1.FieldMask v) {
    setField(4, v);
  }

  @$pb.TagNumber(4)
  $core.bool hasUpdateMask() => $_has(3);
  @$pb.TagNumber(4)
  void clearUpdateMask() => clearField(4);
  @$pb.TagNumber(4)
  $1.FieldMask ensureUpdateMask() => $_ensure(3);
}

class UpdateOAuthClientResponse extends $pb.GeneratedMessage {
  factory UpdateOAuthClientResponse({
    OAuthClient? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data = data;
    }
    return $result;
  }
  UpdateOAuthClientResponse._() : super();
  factory UpdateOAuthClientResponse.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory UpdateOAuthClientResponse.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdateOAuthClientResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOM<OAuthClient>(1, _omitFieldNames ? '' : 'data',
        subBuilder: OAuthClient.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  UpdateOAuthClientResponse clone() =>
      UpdateOAuthClientResponse()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  UpdateOAuthClientResponse copyWith(
          void Function(UpdateOAuthClientResponse) updates) =>
      super.copyWith((message) => updates(message as UpdateOAuthClientResponse))
          as UpdateOAuthClientResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static UpdateOAuthClientResponse create() => UpdateOAuthClientResponse._();
  UpdateOAuthClientResponse createEmptyInstance() => create();
  static $pb.PbList<UpdateOAuthClientResponse> createRepeated() =>
      $pb.PbList<UpdateOAuthClientResponse>();
  @$core.pragma('dart2js:noInline')
  static UpdateOAuthClientResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdateOAuthClientResponse>(create);
  static UpdateOAuthClientResponse? _defaultInstance;

  @$pb.TagNumber(1)
  OAuthClient get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(OAuthClient v) {
    setField(1, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => clearField(1);
  @$pb.TagNumber(1)
  OAuthClient ensureData() => $_ensure(0);
}

class RemoveOAuthClientRequest extends $pb.GeneratedMessage {
  factory RemoveOAuthClientRequest({
    $core.String? id,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    return $result;
  }
  RemoveOAuthClientRequest._() : super();
  factory RemoveOAuthClientRequest.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory RemoveOAuthClientRequest.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveOAuthClientRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  RemoveOAuthClientRequest clone() =>
      RemoveOAuthClientRequest()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  RemoveOAuthClientRequest copyWith(
          void Function(RemoveOAuthClientRequest) updates) =>
      super.copyWith((message) => updates(message as RemoveOAuthClientRequest))
          as RemoveOAuthClientRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static RemoveOAuthClientRequest create() => RemoveOAuthClientRequest._();
  RemoveOAuthClientRequest createEmptyInstance() => create();
  static $pb.PbList<RemoveOAuthClientRequest> createRepeated() =>
      $pb.PbList<RemoveOAuthClientRequest>();
  @$core.pragma('dart2js:noInline')
  static RemoveOAuthClientRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveOAuthClientRequest>(create);
  static RemoveOAuthClientRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);
}

class RemoveOAuthClientResponse extends $pb.GeneratedMessage {
  factory RemoveOAuthClientResponse({
    $core.bool? succeeded,
  }) {
    final $result = create();
    if (succeeded != null) {
      $result.succeeded = succeeded;
    }
    return $result;
  }
  RemoveOAuthClientResponse._() : super();
  factory RemoveOAuthClientResponse.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory RemoveOAuthClientResponse.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveOAuthClientResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'succeeded')
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  RemoveOAuthClientResponse clone() =>
      RemoveOAuthClientResponse()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  RemoveOAuthClientResponse copyWith(
          void Function(RemoveOAuthClientResponse) updates) =>
      super.copyWith((message) => updates(message as RemoveOAuthClientResponse))
          as RemoveOAuthClientResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static RemoveOAuthClientResponse create() => RemoveOAuthClientResponse._();
  RemoveOAuthClientResponse createEmptyInstance() => create();
  static $pb.PbList<RemoveOAuthClientResponse> createRepeated() =>
      $pb.PbList<RemoveOAuthClientResponse>();
  @$core.pragma('dart2js:noInline')
  static RemoveOAuthClientResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveOAuthClientResponse>(create);
  static RemoveOAuthClientResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get succeeded => $_getBF(0);
  @$pb.TagNumber(1)
  set succeeded($core.bool v) {
    $_setBool(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasSucceeded() => $_has(0);
  @$pb.TagNumber(1)
  void clearSucceeded() => clearField(1);
}

class CreateServiceAccountRequest extends $pb.GeneratedMessage {
  factory CreateServiceAccountRequest({
    $core.String? partitionId,
    $core.String? profileId,
    $core.String? name,
    $core.String? type,
    OAuthClientConfiguration? oauthClient,
    ServiceAuthorizationPolicyInput? authorizationPolicy,
    $6.Struct? publicKeys,
    $6.Struct? properties,
  }) {
    final $result = create();
    if (partitionId != null) {
      $result.partitionId = partitionId;
    }
    if (profileId != null) {
      $result.profileId = profileId;
    }
    if (name != null) {
      $result.name = name;
    }
    if (type != null) {
      $result.type = type;
    }
    if (oauthClient != null) {
      $result.oauthClient = oauthClient;
    }
    if (authorizationPolicy != null) {
      $result.authorizationPolicy = authorizationPolicy;
    }
    if (publicKeys != null) {
      $result.publicKeys = publicKeys;
    }
    if (properties != null) {
      $result.properties = properties;
    }
    return $result;
  }
  CreateServiceAccountRequest._() : super();
  factory CreateServiceAccountRequest.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory CreateServiceAccountRequest.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateServiceAccountRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOS(2, _omitFieldNames ? '' : 'profileId')
    ..aOS(3, _omitFieldNames ? '' : 'name')
    ..aOS(4, _omitFieldNames ? '' : 'type')
    ..aOM<OAuthClientConfiguration>(5, _omitFieldNames ? '' : 'oauthClient',
        subBuilder: OAuthClientConfiguration.create)
    ..aOM<ServiceAuthorizationPolicyInput>(
        6, _omitFieldNames ? '' : 'authorizationPolicy',
        subBuilder: ServiceAuthorizationPolicyInput.create)
    ..aOM<$6.Struct>(7, _omitFieldNames ? '' : 'publicKeys',
        subBuilder: $6.Struct.create)
    ..aOM<$6.Struct>(8, _omitFieldNames ? '' : 'properties',
        subBuilder: $6.Struct.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  CreateServiceAccountRequest clone() =>
      CreateServiceAccountRequest()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  CreateServiceAccountRequest copyWith(
          void Function(CreateServiceAccountRequest) updates) =>
      super.copyWith(
              (message) => updates(message as CreateServiceAccountRequest))
          as CreateServiceAccountRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static CreateServiceAccountRequest create() =>
      CreateServiceAccountRequest._();
  CreateServiceAccountRequest createEmptyInstance() => create();
  static $pb.PbList<CreateServiceAccountRequest> createRepeated() =>
      $pb.PbList<CreateServiceAccountRequest>();
  @$core.pragma('dart2js:noInline')
  static CreateServiceAccountRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateServiceAccountRequest>(create);
  static CreateServiceAccountRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get partitionId => $_getSZ(0);
  @$pb.TagNumber(1)
  set partitionId($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasPartitionId() => $_has(0);
  @$pb.TagNumber(1)
  void clearPartitionId() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get profileId => $_getSZ(1);
  @$pb.TagNumber(2)
  set profileId($core.String v) {
    $_setString(1, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasProfileId() => $_has(1);
  @$pb.TagNumber(2)
  void clearProfileId() => clearField(2);

  @$pb.TagNumber(3)
  $core.String get name => $_getSZ(2);
  @$pb.TagNumber(3)
  set name($core.String v) {
    $_setString(2, v);
  }

  @$pb.TagNumber(3)
  $core.bool hasName() => $_has(2);
  @$pb.TagNumber(3)
  void clearName() => clearField(3);

  @$pb.TagNumber(4)
  $core.String get type => $_getSZ(3);
  @$pb.TagNumber(4)
  set type($core.String v) {
    $_setString(3, v);
  }

  @$pb.TagNumber(4)
  $core.bool hasType() => $_has(3);
  @$pb.TagNumber(4)
  void clearType() => clearField(4);

  @$pb.TagNumber(5)
  OAuthClientConfiguration get oauthClient => $_getN(4);
  @$pb.TagNumber(5)
  set oauthClient(OAuthClientConfiguration v) {
    setField(5, v);
  }

  @$pb.TagNumber(5)
  $core.bool hasOauthClient() => $_has(4);
  @$pb.TagNumber(5)
  void clearOauthClient() => clearField(5);
  @$pb.TagNumber(5)
  OAuthClientConfiguration ensureOauthClient() => $_ensure(4);

  @$pb.TagNumber(6)
  ServiceAuthorizationPolicyInput get authorizationPolicy => $_getN(5);
  @$pb.TagNumber(6)
  set authorizationPolicy(ServiceAuthorizationPolicyInput v) {
    setField(6, v);
  }

  @$pb.TagNumber(6)
  $core.bool hasAuthorizationPolicy() => $_has(5);
  @$pb.TagNumber(6)
  void clearAuthorizationPolicy() => clearField(6);
  @$pb.TagNumber(6)
  ServiceAuthorizationPolicyInput ensureAuthorizationPolicy() => $_ensure(5);

  @$pb.TagNumber(7)
  $6.Struct get publicKeys => $_getN(6);
  @$pb.TagNumber(7)
  set publicKeys($6.Struct v) {
    setField(7, v);
  }

  @$pb.TagNumber(7)
  $core.bool hasPublicKeys() => $_has(6);
  @$pb.TagNumber(7)
  void clearPublicKeys() => clearField(7);
  @$pb.TagNumber(7)
  $6.Struct ensurePublicKeys() => $_ensure(6);

  @$pb.TagNumber(8)
  $6.Struct get properties => $_getN(7);
  @$pb.TagNumber(8)
  set properties($6.Struct v) {
    setField(8, v);
  }

  @$pb.TagNumber(8)
  $core.bool hasProperties() => $_has(7);
  @$pb.TagNumber(8)
  void clearProperties() => clearField(8);
  @$pb.TagNumber(8)
  $6.Struct ensureProperties() => $_ensure(7);
}

class CreateServiceAccountResponse extends $pb.GeneratedMessage {
  factory CreateServiceAccountResponse({
    ServiceAccount? data,
    $core.String? clientSecret,
  }) {
    final $result = create();
    if (data != null) {
      $result.data = data;
    }
    if (clientSecret != null) {
      $result.clientSecret = clientSecret;
    }
    return $result;
  }
  CreateServiceAccountResponse._() : super();
  factory CreateServiceAccountResponse.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory CreateServiceAccountResponse.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateServiceAccountResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOM<ServiceAccount>(1, _omitFieldNames ? '' : 'data',
        subBuilder: ServiceAccount.create)
    ..aOS(2, _omitFieldNames ? '' : 'clientSecret')
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  CreateServiceAccountResponse clone() =>
      CreateServiceAccountResponse()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  CreateServiceAccountResponse copyWith(
          void Function(CreateServiceAccountResponse) updates) =>
      super.copyWith(
              (message) => updates(message as CreateServiceAccountResponse))
          as CreateServiceAccountResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static CreateServiceAccountResponse create() =>
      CreateServiceAccountResponse._();
  CreateServiceAccountResponse createEmptyInstance() => create();
  static $pb.PbList<CreateServiceAccountResponse> createRepeated() =>
      $pb.PbList<CreateServiceAccountResponse>();
  @$core.pragma('dart2js:noInline')
  static CreateServiceAccountResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateServiceAccountResponse>(create);
  static CreateServiceAccountResponse? _defaultInstance;

  @$pb.TagNumber(1)
  ServiceAccount get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(ServiceAccount v) {
    setField(1, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => clearField(1);
  @$pb.TagNumber(1)
  ServiceAccount ensureData() => $_ensure(0);

  @$pb.TagNumber(2)
  $core.String get clientSecret => $_getSZ(1);
  @$pb.TagNumber(2)
  set clientSecret($core.String v) {
    $_setString(1, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasClientSecret() => $_has(1);
  @$pb.TagNumber(2)
  void clearClientSecret() => clearField(2);
}

enum GetServiceAccountRequest_Selector { id, clientId, notSet }

class GetServiceAccountRequest extends $pb.GeneratedMessage {
  factory GetServiceAccountRequest({
    $core.String? id,
    $core.String? clientId,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    if (clientId != null) {
      $result.clientId = clientId;
    }
    return $result;
  }
  GetServiceAccountRequest._() : super();
  factory GetServiceAccountRequest.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory GetServiceAccountRequest.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static const $core.Map<$core.int, GetServiceAccountRequest_Selector>
      _GetServiceAccountRequest_SelectorByTag = {
    1: GetServiceAccountRequest_Selector.id,
    2: GetServiceAccountRequest_Selector.clientId,
    0: GetServiceAccountRequest_Selector.notSet
  };
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetServiceAccountRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..oo(0, [1, 2])
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'clientId')
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  GetServiceAccountRequest clone() =>
      GetServiceAccountRequest()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  GetServiceAccountRequest copyWith(
          void Function(GetServiceAccountRequest) updates) =>
      super.copyWith((message) => updates(message as GetServiceAccountRequest))
          as GetServiceAccountRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetServiceAccountRequest create() => GetServiceAccountRequest._();
  GetServiceAccountRequest createEmptyInstance() => create();
  static $pb.PbList<GetServiceAccountRequest> createRepeated() =>
      $pb.PbList<GetServiceAccountRequest>();
  @$core.pragma('dart2js:noInline')
  static GetServiceAccountRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetServiceAccountRequest>(create);
  static GetServiceAccountRequest? _defaultInstance;

  GetServiceAccountRequest_Selector whichSelector() =>
      _GetServiceAccountRequest_SelectorByTag[$_whichOneof(0)]!;
  void clearSelector() => clearField($_whichOneof(0));

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get clientId => $_getSZ(1);
  @$pb.TagNumber(2)
  set clientId($core.String v) {
    $_setString(1, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasClientId() => $_has(1);
  @$pb.TagNumber(2)
  void clearClientId() => clearField(2);
}

class GetServiceAccountResponse extends $pb.GeneratedMessage {
  factory GetServiceAccountResponse({
    ServiceAccount? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data = data;
    }
    return $result;
  }
  GetServiceAccountResponse._() : super();
  factory GetServiceAccountResponse.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory GetServiceAccountResponse.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetServiceAccountResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOM<ServiceAccount>(1, _omitFieldNames ? '' : 'data',
        subBuilder: ServiceAccount.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  GetServiceAccountResponse clone() =>
      GetServiceAccountResponse()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  GetServiceAccountResponse copyWith(
          void Function(GetServiceAccountResponse) updates) =>
      super.copyWith((message) => updates(message as GetServiceAccountResponse))
          as GetServiceAccountResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetServiceAccountResponse create() => GetServiceAccountResponse._();
  GetServiceAccountResponse createEmptyInstance() => create();
  static $pb.PbList<GetServiceAccountResponse> createRepeated() =>
      $pb.PbList<GetServiceAccountResponse>();
  @$core.pragma('dart2js:noInline')
  static GetServiceAccountResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetServiceAccountResponse>(create);
  static GetServiceAccountResponse? _defaultInstance;

  @$pb.TagNumber(1)
  ServiceAccount get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(ServiceAccount v) {
    setField(1, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => clearField(1);
  @$pb.TagNumber(1)
  ServiceAccount ensureData() => $_ensure(0);
}

class ListServiceAccountsRequest extends $pb.GeneratedMessage {
  factory ListServiceAccountsRequest({
    $core.String? partitionId,
    $7.PageCursor? cursor,
  }) {
    final $result = create();
    if (partitionId != null) {
      $result.partitionId = partitionId;
    }
    if (cursor != null) {
      $result.cursor = cursor;
    }
    return $result;
  }
  ListServiceAccountsRequest._() : super();
  factory ListServiceAccountsRequest.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory ListServiceAccountsRequest.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListServiceAccountsRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOM<$7.PageCursor>(2, _omitFieldNames ? '' : 'cursor',
        subBuilder: $7.PageCursor.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  ListServiceAccountsRequest clone() =>
      ListServiceAccountsRequest()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  ListServiceAccountsRequest copyWith(
          void Function(ListServiceAccountsRequest) updates) =>
      super.copyWith(
              (message) => updates(message as ListServiceAccountsRequest))
          as ListServiceAccountsRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListServiceAccountsRequest create() => ListServiceAccountsRequest._();
  ListServiceAccountsRequest createEmptyInstance() => create();
  static $pb.PbList<ListServiceAccountsRequest> createRepeated() =>
      $pb.PbList<ListServiceAccountsRequest>();
  @$core.pragma('dart2js:noInline')
  static ListServiceAccountsRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListServiceAccountsRequest>(create);
  static ListServiceAccountsRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get partitionId => $_getSZ(0);
  @$pb.TagNumber(1)
  set partitionId($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasPartitionId() => $_has(0);
  @$pb.TagNumber(1)
  void clearPartitionId() => clearField(1);

  @$pb.TagNumber(2)
  $7.PageCursor get cursor => $_getN(1);
  @$pb.TagNumber(2)
  set cursor($7.PageCursor v) {
    setField(2, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasCursor() => $_has(1);
  @$pb.TagNumber(2)
  void clearCursor() => clearField(2);
  @$pb.TagNumber(2)
  $7.PageCursor ensureCursor() => $_ensure(1);
}

class ListServiceAccountsResponse extends $pb.GeneratedMessage {
  factory ListServiceAccountsResponse({
    $core.Iterable<ServiceAccount>? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data.addAll(data);
    }
    return $result;
  }
  ListServiceAccountsResponse._() : super();
  factory ListServiceAccountsResponse.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory ListServiceAccountsResponse.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListServiceAccountsResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..pc<ServiceAccount>(1, _omitFieldNames ? '' : 'data', $pb.PbFieldType.PM,
        subBuilder: ServiceAccount.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  ListServiceAccountsResponse clone() =>
      ListServiceAccountsResponse()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  ListServiceAccountsResponse copyWith(
          void Function(ListServiceAccountsResponse) updates) =>
      super.copyWith(
              (message) => updates(message as ListServiceAccountsResponse))
          as ListServiceAccountsResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListServiceAccountsResponse create() =>
      ListServiceAccountsResponse._();
  ListServiceAccountsResponse createEmptyInstance() => create();
  static $pb.PbList<ListServiceAccountsResponse> createRepeated() =>
      $pb.PbList<ListServiceAccountsResponse>();
  @$core.pragma('dart2js:noInline')
  static ListServiceAccountsResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListServiceAccountsResponse>(create);
  static ListServiceAccountsResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<ServiceAccount> get data => $_getList(0);
}

class UpdateServiceAccountRequest extends $pb.GeneratedMessage {
  factory UpdateServiceAccountRequest({
    $core.String? id,
    $core.String? name,
    $core.String? type,
    OAuthClientConfiguration? oauthClient,
    ServiceAuthorizationPolicyInput? authorizationPolicy,
    $6.Struct? publicKeys,
    $6.Struct? properties,
    $1.FieldMask? updateMask,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    if (name != null) {
      $result.name = name;
    }
    if (type != null) {
      $result.type = type;
    }
    if (oauthClient != null) {
      $result.oauthClient = oauthClient;
    }
    if (authorizationPolicy != null) {
      $result.authorizationPolicy = authorizationPolicy;
    }
    if (publicKeys != null) {
      $result.publicKeys = publicKeys;
    }
    if (properties != null) {
      $result.properties = properties;
    }
    if (updateMask != null) {
      $result.updateMask = updateMask;
    }
    return $result;
  }
  UpdateServiceAccountRequest._() : super();
  factory UpdateServiceAccountRequest.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory UpdateServiceAccountRequest.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdateServiceAccountRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'type')
    ..aOM<OAuthClientConfiguration>(4, _omitFieldNames ? '' : 'oauthClient',
        subBuilder: OAuthClientConfiguration.create)
    ..aOM<ServiceAuthorizationPolicyInput>(
        5, _omitFieldNames ? '' : 'authorizationPolicy',
        subBuilder: ServiceAuthorizationPolicyInput.create)
    ..aOM<$6.Struct>(6, _omitFieldNames ? '' : 'publicKeys',
        subBuilder: $6.Struct.create)
    ..aOM<$6.Struct>(7, _omitFieldNames ? '' : 'properties',
        subBuilder: $6.Struct.create)
    ..aOM<$1.FieldMask>(8, _omitFieldNames ? '' : 'updateMask',
        subBuilder: $1.FieldMask.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  UpdateServiceAccountRequest clone() =>
      UpdateServiceAccountRequest()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  UpdateServiceAccountRequest copyWith(
          void Function(UpdateServiceAccountRequest) updates) =>
      super.copyWith(
              (message) => updates(message as UpdateServiceAccountRequest))
          as UpdateServiceAccountRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static UpdateServiceAccountRequest create() =>
      UpdateServiceAccountRequest._();
  UpdateServiceAccountRequest createEmptyInstance() => create();
  static $pb.PbList<UpdateServiceAccountRequest> createRepeated() =>
      $pb.PbList<UpdateServiceAccountRequest>();
  @$core.pragma('dart2js:noInline')
  static UpdateServiceAccountRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdateServiceAccountRequest>(create);
  static UpdateServiceAccountRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get name => $_getSZ(1);
  @$pb.TagNumber(2)
  set name($core.String v) {
    $_setString(1, v);
  }

  @$pb.TagNumber(2)
  $core.bool hasName() => $_has(1);
  @$pb.TagNumber(2)
  void clearName() => clearField(2);

  @$pb.TagNumber(3)
  $core.String get type => $_getSZ(2);
  @$pb.TagNumber(3)
  set type($core.String v) {
    $_setString(2, v);
  }

  @$pb.TagNumber(3)
  $core.bool hasType() => $_has(2);
  @$pb.TagNumber(3)
  void clearType() => clearField(3);

  @$pb.TagNumber(4)
  OAuthClientConfiguration get oauthClient => $_getN(3);
  @$pb.TagNumber(4)
  set oauthClient(OAuthClientConfiguration v) {
    setField(4, v);
  }

  @$pb.TagNumber(4)
  $core.bool hasOauthClient() => $_has(3);
  @$pb.TagNumber(4)
  void clearOauthClient() => clearField(4);
  @$pb.TagNumber(4)
  OAuthClientConfiguration ensureOauthClient() => $_ensure(3);

  @$pb.TagNumber(5)
  ServiceAuthorizationPolicyInput get authorizationPolicy => $_getN(4);
  @$pb.TagNumber(5)
  set authorizationPolicy(ServiceAuthorizationPolicyInput v) {
    setField(5, v);
  }

  @$pb.TagNumber(5)
  $core.bool hasAuthorizationPolicy() => $_has(4);
  @$pb.TagNumber(5)
  void clearAuthorizationPolicy() => clearField(5);
  @$pb.TagNumber(5)
  ServiceAuthorizationPolicyInput ensureAuthorizationPolicy() => $_ensure(4);

  @$pb.TagNumber(6)
  $6.Struct get publicKeys => $_getN(5);
  @$pb.TagNumber(6)
  set publicKeys($6.Struct v) {
    setField(6, v);
  }

  @$pb.TagNumber(6)
  $core.bool hasPublicKeys() => $_has(5);
  @$pb.TagNumber(6)
  void clearPublicKeys() => clearField(6);
  @$pb.TagNumber(6)
  $6.Struct ensurePublicKeys() => $_ensure(5);

  @$pb.TagNumber(7)
  $6.Struct get properties => $_getN(6);
  @$pb.TagNumber(7)
  set properties($6.Struct v) {
    setField(7, v);
  }

  @$pb.TagNumber(7)
  $core.bool hasProperties() => $_has(6);
  @$pb.TagNumber(7)
  void clearProperties() => clearField(7);
  @$pb.TagNumber(7)
  $6.Struct ensureProperties() => $_ensure(6);

  @$pb.TagNumber(8)
  $1.FieldMask get updateMask => $_getN(7);
  @$pb.TagNumber(8)
  set updateMask($1.FieldMask v) {
    setField(8, v);
  }

  @$pb.TagNumber(8)
  $core.bool hasUpdateMask() => $_has(7);
  @$pb.TagNumber(8)
  void clearUpdateMask() => clearField(8);
  @$pb.TagNumber(8)
  $1.FieldMask ensureUpdateMask() => $_ensure(7);
}

class UpdateServiceAccountResponse extends $pb.GeneratedMessage {
  factory UpdateServiceAccountResponse({
    ServiceAccount? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data = data;
    }
    return $result;
  }
  UpdateServiceAccountResponse._() : super();
  factory UpdateServiceAccountResponse.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory UpdateServiceAccountResponse.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdateServiceAccountResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOM<ServiceAccount>(1, _omitFieldNames ? '' : 'data',
        subBuilder: ServiceAccount.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  UpdateServiceAccountResponse clone() =>
      UpdateServiceAccountResponse()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  UpdateServiceAccountResponse copyWith(
          void Function(UpdateServiceAccountResponse) updates) =>
      super.copyWith(
              (message) => updates(message as UpdateServiceAccountResponse))
          as UpdateServiceAccountResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static UpdateServiceAccountResponse create() =>
      UpdateServiceAccountResponse._();
  UpdateServiceAccountResponse createEmptyInstance() => create();
  static $pb.PbList<UpdateServiceAccountResponse> createRepeated() =>
      $pb.PbList<UpdateServiceAccountResponse>();
  @$core.pragma('dart2js:noInline')
  static UpdateServiceAccountResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdateServiceAccountResponse>(create);
  static UpdateServiceAccountResponse? _defaultInstance;

  @$pb.TagNumber(1)
  ServiceAccount get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(ServiceAccount v) {
    setField(1, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => clearField(1);
  @$pb.TagNumber(1)
  ServiceAccount ensureData() => $_ensure(0);
}

class RemoveServiceAccountRequest extends $pb.GeneratedMessage {
  factory RemoveServiceAccountRequest({
    $core.String? id,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    return $result;
  }
  RemoveServiceAccountRequest._() : super();
  factory RemoveServiceAccountRequest.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory RemoveServiceAccountRequest.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveServiceAccountRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  RemoveServiceAccountRequest clone() =>
      RemoveServiceAccountRequest()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  RemoveServiceAccountRequest copyWith(
          void Function(RemoveServiceAccountRequest) updates) =>
      super.copyWith(
              (message) => updates(message as RemoveServiceAccountRequest))
          as RemoveServiceAccountRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static RemoveServiceAccountRequest create() =>
      RemoveServiceAccountRequest._();
  RemoveServiceAccountRequest createEmptyInstance() => create();
  static $pb.PbList<RemoveServiceAccountRequest> createRepeated() =>
      $pb.PbList<RemoveServiceAccountRequest>();
  @$core.pragma('dart2js:noInline')
  static RemoveServiceAccountRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveServiceAccountRequest>(create);
  static RemoveServiceAccountRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);
}

class RemoveServiceAccountResponse extends $pb.GeneratedMessage {
  factory RemoveServiceAccountResponse({
    $core.bool? succeeded,
  }) {
    final $result = create();
    if (succeeded != null) {
      $result.succeeded = succeeded;
    }
    return $result;
  }
  RemoveServiceAccountResponse._() : super();
  factory RemoveServiceAccountResponse.fromBuffer($core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory RemoveServiceAccountResponse.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveServiceAccountResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'succeeded')
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  RemoveServiceAccountResponse clone() =>
      RemoveServiceAccountResponse()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  RemoveServiceAccountResponse copyWith(
          void Function(RemoveServiceAccountResponse) updates) =>
      super.copyWith(
              (message) => updates(message as RemoveServiceAccountResponse))
          as RemoveServiceAccountResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static RemoveServiceAccountResponse create() =>
      RemoveServiceAccountResponse._();
  RemoveServiceAccountResponse createEmptyInstance() => create();
  static $pb.PbList<RemoveServiceAccountResponse> createRepeated() =>
      $pb.PbList<RemoveServiceAccountResponse>();
  @$core.pragma('dart2js:noInline')
  static RemoveServiceAccountResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveServiceAccountResponse>(create);
  static RemoveServiceAccountResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get succeeded => $_getBF(0);
  @$pb.TagNumber(1)
  set succeeded($core.bool v) {
    $_setBool(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasSucceeded() => $_has(0);
  @$pb.TagNumber(1)
  void clearSucceeded() => clearField(1);
}

class ReconcileServiceAccountAuthorizationRequest extends $pb.GeneratedMessage {
  factory ReconcileServiceAccountAuthorizationRequest({
    $core.String? id,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    return $result;
  }
  ReconcileServiceAccountAuthorizationRequest._() : super();
  factory ReconcileServiceAccountAuthorizationRequest.fromBuffer(
          $core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory ReconcileServiceAccountAuthorizationRequest.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ReconcileServiceAccountAuthorizationRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  ReconcileServiceAccountAuthorizationRequest clone() =>
      ReconcileServiceAccountAuthorizationRequest()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  ReconcileServiceAccountAuthorizationRequest copyWith(
          void Function(ReconcileServiceAccountAuthorizationRequest) updates) =>
      super.copyWith((message) =>
              updates(message as ReconcileServiceAccountAuthorizationRequest))
          as ReconcileServiceAccountAuthorizationRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ReconcileServiceAccountAuthorizationRequest create() =>
      ReconcileServiceAccountAuthorizationRequest._();
  ReconcileServiceAccountAuthorizationRequest createEmptyInstance() => create();
  static $pb.PbList<ReconcileServiceAccountAuthorizationRequest>
      createRepeated() =>
          $pb.PbList<ReconcileServiceAccountAuthorizationRequest>();
  @$core.pragma('dart2js:noInline')
  static ReconcileServiceAccountAuthorizationRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<
          ReconcileServiceAccountAuthorizationRequest>(create);
  static ReconcileServiceAccountAuthorizationRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) {
    $_setString(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);
}

class ReconcileServiceAccountAuthorizationResponse
    extends $pb.GeneratedMessage {
  factory ReconcileServiceAccountAuthorizationResponse({
    $fixnum.Int64? generation,
  }) {
    final $result = create();
    if (generation != null) {
      $result.generation = generation;
    }
    return $result;
  }
  ReconcileServiceAccountAuthorizationResponse._() : super();
  factory ReconcileServiceAccountAuthorizationResponse.fromBuffer(
          $core.List<$core.int> i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(i, r);
  factory ReconcileServiceAccountAuthorizationResponse.fromJson($core.String i,
          [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ReconcileServiceAccountAuthorizationResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v2'),
      createEmptyInstance: create)
    ..aInt64(1, _omitFieldNames ? '' : 'generation')
    ..hasRequiredFields = false;

  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
      'Will be removed in next major version')
  ReconcileServiceAccountAuthorizationResponse clone() =>
      ReconcileServiceAccountAuthorizationResponse()..mergeFromMessage(this);
  @$core.Deprecated('Using this can add significant overhead to your binary. '
      'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
      'Will be removed in next major version')
  ReconcileServiceAccountAuthorizationResponse copyWith(
          void Function(ReconcileServiceAccountAuthorizationResponse)
              updates) =>
      super.copyWith((message) =>
              updates(message as ReconcileServiceAccountAuthorizationResponse))
          as ReconcileServiceAccountAuthorizationResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ReconcileServiceAccountAuthorizationResponse create() =>
      ReconcileServiceAccountAuthorizationResponse._();
  ReconcileServiceAccountAuthorizationResponse createEmptyInstance() =>
      create();
  static $pb.PbList<ReconcileServiceAccountAuthorizationResponse>
      createRepeated() =>
          $pb.PbList<ReconcileServiceAccountAuthorizationResponse>();
  @$core.pragma('dart2js:noInline')
  static ReconcileServiceAccountAuthorizationResponse getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<
          ReconcileServiceAccountAuthorizationResponse>(create);
  static ReconcileServiceAccountAuthorizationResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $fixnum.Int64 get generation => $_getI64(0);
  @$pb.TagNumber(1)
  set generation($fixnum.Int64 v) {
    $_setInt64(0, v);
  }

  @$pb.TagNumber(1)
  $core.bool hasGeneration() => $_has(0);
  @$pb.TagNumber(1)
  void clearGeneration() => clearField(1);
}

class AuthContractServiceApi {
  $pb.RpcClient _client;
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

const _omitFieldNames = $core.bool.fromEnvironment('protobuf.omit_field_names');
const _omitMessageNames =
    $core.bool.fromEnvironment('protobuf.omit_message_names');
