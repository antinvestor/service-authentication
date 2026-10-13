// This is a generated file - do not edit.
//
// Generated from tenancy/v1/tenancy.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports

import 'dart:async' as $async;
import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;
import 'package:protobuf/well_known_types/google/protobuf/struct.pb.dart' as $0;
import 'package:protobuf/well_known_types/google/protobuf/timestamp.pb.dart'
    as $1;

import '../../common/v1/common.pb.dart' as $2;
import 'tenancy.pbenum.dart';

export 'package:protobuf/protobuf.dart' show GeneratedMessageGenericExtensions;

export 'tenancy.pbenum.dart';

/// TenantObject represents a top-level organizational unit.
class TenantObject extends $pb.GeneratedMessage {
  factory TenantObject({
    $core.String? id,
    $core.String? name,
    $core.String? description,
    $0.Struct? properties,
    $1.Timestamp? createdAt,
    $2.STATE? state,
    TenantEnvironment? environment,
  }) {
    final result = TenantObject._();
    if (id != null) result.id = id;
    if (name != null) result.name = name;
    if (description != null) result.description = description;
    if (properties != null) result.properties = properties;
    if (createdAt != null) result.createdAt = createdAt;
    if (state != null) result.state = state;
    if (environment != null) result.environment = environment;
    return result;
  }

  TenantObject._();

  factory TenantObject.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      TenantObject()..mergeFromBuffer(data, registry);
  factory TenantObject.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      TenantObject()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'TenantObject',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: TenantObject.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'description')
    ..aOM<$0.Struct>(4, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..aOM<$1.Timestamp>(5, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aE<$2.STATE>(6, _omitFieldNames ? '' : 'state',
        enumValues: $2.STATE.values)
    ..aE<TenantEnvironment>(7, _omitFieldNames ? '' : 'environment',
        enumValues: TenantEnvironment.values)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TenantObject clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TenantObject copyWith(void Function(TenantObject) updates) =>
      super.copyWith((message) => updates(message as TenantObject))
          as TenantObject;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use TenantObject() / TenantObject.new instead')
  static TenantObject create() => TenantObject._();
  static $pb.GeneratedMessage $_createMessage() => TenantObject._();
  @$core.override
  TenantObject createEmptyInstance() => TenantObject._();
  @$core.pragma('dart2js:noInline')
  static TenantObject getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<TenantObject>(
          TenantObject.$_createMessage);
  static TenantObject? _defaultInstance;

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
  $core.String get description => $_getSZ(2);
  @$pb.TagNumber(3)
  set description($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasDescription() => $_has(2);
  @$pb.TagNumber(3)
  void clearDescription() => $_clearField(3);

  @$pb.TagNumber(4)
  $0.Struct get properties => $_getN(3);
  @$pb.TagNumber(4)
  set properties($0.Struct value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasProperties() => $_has(3);
  @$pb.TagNumber(4)
  void clearProperties() => $_clearField(4);
  @$pb.TagNumber(4)
  $0.Struct ensureProperties() => $_ensure(3);

  @$pb.TagNumber(5)
  $1.Timestamp get createdAt => $_getN(4);
  @$pb.TagNumber(5)
  set createdAt($1.Timestamp value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasCreatedAt() => $_has(4);
  @$pb.TagNumber(5)
  void clearCreatedAt() => $_clearField(5);
  @$pb.TagNumber(5)
  $1.Timestamp ensureCreatedAt() => $_ensure(4);

  @$pb.TagNumber(6)
  $2.STATE get state => $_getN(5);
  @$pb.TagNumber(6)
  set state($2.STATE value) => $_setField(6, value);
  @$pb.TagNumber(6)
  $core.bool hasState() => $_has(5);
  @$pb.TagNumber(6)
  void clearState() => $_clearField(6);

  @$pb.TagNumber(7)
  TenantEnvironment get environment => $_getN(6);
  @$pb.TagNumber(7)
  set environment(TenantEnvironment value) => $_setField(7, value);
  @$pb.TagNumber(7)
  $core.bool hasEnvironment() => $_has(6);
  @$pb.TagNumber(7)
  void clearEnvironment() => $_clearField(7);
}

/// PartitionObject represents a data partition within a tenant.
class PartitionObject extends $pb.GeneratedMessage {
  factory PartitionObject({
    $core.String? id,
    $core.String? name,
    $core.String? tenantId,
    $core.String? parentId,
    $core.String? description,
    $2.STATE? state,
    $0.Struct? properties,
    $1.Timestamp? createdAt,
    $core.String? domain,
  }) {
    final result = PartitionObject._();
    if (id != null) result.id = id;
    if (name != null) result.name = name;
    if (tenantId != null) result.tenantId = tenantId;
    if (parentId != null) result.parentId = parentId;
    if (description != null) result.description = description;
    if (state != null) result.state = state;
    if (properties != null) result.properties = properties;
    if (createdAt != null) result.createdAt = createdAt;
    if (domain != null) result.domain = domain;
    return result;
  }

  PartitionObject._();

  factory PartitionObject.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      PartitionObject()..mergeFromBuffer(data, registry);
  factory PartitionObject.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      PartitionObject()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'PartitionObject',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: PartitionObject.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'tenantId')
    ..aOS(4, _omitFieldNames ? '' : 'parentId')
    ..aOS(5, _omitFieldNames ? '' : 'description')
    ..aE<$2.STATE>(6, _omitFieldNames ? '' : 'state',
        enumValues: $2.STATE.values)
    ..aOM<$0.Struct>(7, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..aOM<$1.Timestamp>(8, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOS(9, _omitFieldNames ? '' : 'domain')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PartitionObject clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PartitionObject copyWith(void Function(PartitionObject) updates) =>
      super.copyWith((message) => updates(message as PartitionObject))
          as PartitionObject;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use PartitionObject() / PartitionObject.new instead')
  static PartitionObject create() => PartitionObject._();
  static $pb.GeneratedMessage $_createMessage() => PartitionObject._();
  @$core.override
  PartitionObject createEmptyInstance() => PartitionObject._();
  @$core.pragma('dart2js:noInline')
  static PartitionObject getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<PartitionObject>(
          PartitionObject.$_createMessage);
  static PartitionObject? _defaultInstance;

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
  $core.String get tenantId => $_getSZ(2);
  @$pb.TagNumber(3)
  set tenantId($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasTenantId() => $_has(2);
  @$pb.TagNumber(3)
  void clearTenantId() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get parentId => $_getSZ(3);
  @$pb.TagNumber(4)
  set parentId($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasParentId() => $_has(3);
  @$pb.TagNumber(4)
  void clearParentId() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.String get description => $_getSZ(4);
  @$pb.TagNumber(5)
  set description($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasDescription() => $_has(4);
  @$pb.TagNumber(5)
  void clearDescription() => $_clearField(5);

  @$pb.TagNumber(6)
  $2.STATE get state => $_getN(5);
  @$pb.TagNumber(6)
  set state($2.STATE value) => $_setField(6, value);
  @$pb.TagNumber(6)
  $core.bool hasState() => $_has(5);
  @$pb.TagNumber(6)
  void clearState() => $_clearField(6);

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
  $1.Timestamp get createdAt => $_getN(7);
  @$pb.TagNumber(8)
  set createdAt($1.Timestamp value) => $_setField(8, value);
  @$pb.TagNumber(8)
  $core.bool hasCreatedAt() => $_has(7);
  @$pb.TagNumber(8)
  void clearCreatedAt() => $_clearField(8);
  @$pb.TagNumber(8)
  $1.Timestamp ensureCreatedAt() => $_ensure(7);

  @$pb.TagNumber(9)
  $core.String get domain => $_getSZ(8);
  @$pb.TagNumber(9)
  set domain($core.String value) => $_setString(8, value);
  @$pb.TagNumber(9)
  $core.bool hasDomain() => $_has(8);
  @$pb.TagNumber(9)
  void clearDomain() => $_clearField(9);
}

/// PartitionRoleObject represents a role within a partition.
class PartitionRoleObject extends $pb.GeneratedMessage {
  factory PartitionRoleObject({
    $core.String? id,
    $core.String? partitionId,
    $core.String? name,
    $0.Struct? properties,
    $1.Timestamp? createdAt,
    $2.STATE? state,
  }) {
    final result = PartitionRoleObject._();
    if (id != null) result.id = id;
    if (partitionId != null) result.partitionId = partitionId;
    if (name != null) result.name = name;
    if (properties != null) result.properties = properties;
    if (createdAt != null) result.createdAt = createdAt;
    if (state != null) result.state = state;
    return result;
  }

  PartitionRoleObject._();

  factory PartitionRoleObject.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      PartitionRoleObject()..mergeFromBuffer(data, registry);
  factory PartitionRoleObject.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      PartitionRoleObject()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'PartitionRoleObject',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: PartitionRoleObject.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'partitionId')
    ..aOS(3, _omitFieldNames ? '' : 'name')
    ..aOM<$0.Struct>(4, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..aOM<$1.Timestamp>(5, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aE<$2.STATE>(6, _omitFieldNames ? '' : 'state',
        enumValues: $2.STATE.values)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PartitionRoleObject clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PartitionRoleObject copyWith(void Function(PartitionRoleObject) updates) =>
      super.copyWith((message) => updates(message as PartitionRoleObject))
          as PartitionRoleObject;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core
      .Deprecated('Use PartitionRoleObject() / PartitionRoleObject.new instead')
  static PartitionRoleObject create() => PartitionRoleObject._();
  static $pb.GeneratedMessage $_createMessage() => PartitionRoleObject._();
  @$core.override
  PartitionRoleObject createEmptyInstance() => PartitionRoleObject._();
  @$core.pragma('dart2js:noInline')
  static PartitionRoleObject getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<PartitionRoleObject>(
          PartitionRoleObject.$_createMessage);
  static PartitionRoleObject? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get partitionId => $_getSZ(1);
  @$pb.TagNumber(2)
  set partitionId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasPartitionId() => $_has(1);
  @$pb.TagNumber(2)
  void clearPartitionId() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get name => $_getSZ(2);
  @$pb.TagNumber(3)
  set name($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasName() => $_has(2);
  @$pb.TagNumber(3)
  void clearName() => $_clearField(3);

  @$pb.TagNumber(4)
  $0.Struct get properties => $_getN(3);
  @$pb.TagNumber(4)
  set properties($0.Struct value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasProperties() => $_has(3);
  @$pb.TagNumber(4)
  void clearProperties() => $_clearField(4);
  @$pb.TagNumber(4)
  $0.Struct ensureProperties() => $_ensure(3);

  @$pb.TagNumber(5)
  $1.Timestamp get createdAt => $_getN(4);
  @$pb.TagNumber(5)
  set createdAt($1.Timestamp value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasCreatedAt() => $_has(4);
  @$pb.TagNumber(5)
  void clearCreatedAt() => $_clearField(5);
  @$pb.TagNumber(5)
  $1.Timestamp ensureCreatedAt() => $_ensure(4);

  @$pb.TagNumber(6)
  $2.STATE get state => $_getN(5);
  @$pb.TagNumber(6)
  set state($2.STATE value) => $_setField(6, value);
  @$pb.TagNumber(6)
  $core.bool hasState() => $_has(5);
  @$pb.TagNumber(6)
  void clearState() => $_clearField(6);
}

/// PageObject represents a custom UI page for a partition.
class PageObject extends $pb.GeneratedMessage {
  factory PageObject({
    $core.String? id,
    $core.String? name,
    $core.String? html,
    $2.STATE? state,
    $1.Timestamp? createdAt,
    $0.Struct? properties,
    $core.String? partitionId,
  }) {
    final result = PageObject._();
    if (id != null) result.id = id;
    if (name != null) result.name = name;
    if (html != null) result.html = html;
    if (state != null) result.state = state;
    if (createdAt != null) result.createdAt = createdAt;
    if (properties != null) result.properties = properties;
    if (partitionId != null) result.partitionId = partitionId;
    return result;
  }

  PageObject._();

  factory PageObject.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      PageObject()..mergeFromBuffer(data, registry);
  factory PageObject.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      PageObject()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'PageObject',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: PageObject.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'html')
    ..aE<$2.STATE>(4, _omitFieldNames ? '' : 'state',
        enumValues: $2.STATE.values)
    ..aOM<$1.Timestamp>(5, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOM<$0.Struct>(6, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..aOS(7, _omitFieldNames ? '' : 'partitionId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PageObject clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PageObject copyWith(void Function(PageObject) updates) =>
      super.copyWith((message) => updates(message as PageObject)) as PageObject;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use PageObject() / PageObject.new instead')
  static PageObject create() => PageObject._();
  static $pb.GeneratedMessage $_createMessage() => PageObject._();
  @$core.override
  PageObject createEmptyInstance() => PageObject._();
  @$core.pragma('dart2js:noInline')
  static PageObject getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<PageObject>(PageObject.$_createMessage);
  static PageObject? _defaultInstance;

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
  $core.String get html => $_getSZ(2);
  @$pb.TagNumber(3)
  set html($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasHtml() => $_has(2);
  @$pb.TagNumber(3)
  void clearHtml() => $_clearField(3);

  @$pb.TagNumber(4)
  $2.STATE get state => $_getN(3);
  @$pb.TagNumber(4)
  set state($2.STATE value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasState() => $_has(3);
  @$pb.TagNumber(4)
  void clearState() => $_clearField(4);

  @$pb.TagNumber(5)
  $1.Timestamp get createdAt => $_getN(4);
  @$pb.TagNumber(5)
  set createdAt($1.Timestamp value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasCreatedAt() => $_has(4);
  @$pb.TagNumber(5)
  void clearCreatedAt() => $_clearField(5);
  @$pb.TagNumber(5)
  $1.Timestamp ensureCreatedAt() => $_ensure(4);

  @$pb.TagNumber(6)
  $0.Struct get properties => $_getN(5);
  @$pb.TagNumber(6)
  set properties($0.Struct value) => $_setField(6, value);
  @$pb.TagNumber(6)
  $core.bool hasProperties() => $_has(5);
  @$pb.TagNumber(6)
  void clearProperties() => $_clearField(6);
  @$pb.TagNumber(6)
  $0.Struct ensureProperties() => $_ensure(5);

  @$pb.TagNumber(7)
  $core.String get partitionId => $_getSZ(6);
  @$pb.TagNumber(7)
  set partitionId($core.String value) => $_setString(6, value);
  @$pb.TagNumber(7)
  $core.bool hasPartitionId() => $_has(6);
  @$pb.TagNumber(7)
  void clearPartitionId() => $_clearField(7);
}

/// AccessObject represents a profile's access to a partition.
class AccessObject extends $pb.GeneratedMessage {
  factory AccessObject({
    $core.String? id,
    $core.String? profileId,
    PartitionObject? partition,
    $2.STATE? state,
    $1.Timestamp? createdAt,
  }) {
    final result = AccessObject._();
    if (id != null) result.id = id;
    if (profileId != null) result.profileId = profileId;
    if (partition != null) result.partition = partition;
    if (state != null) result.state = state;
    if (createdAt != null) result.createdAt = createdAt;
    return result;
  }

  AccessObject._();

  factory AccessObject.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AccessObject()..mergeFromBuffer(data, registry);
  factory AccessObject.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AccessObject()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'AccessObject',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: AccessObject.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'profileId')
    ..aOM<PartitionObject>(3, _omitFieldNames ? '' : 'partition',
        subBuilder: PartitionObject.$_createMessage)
    ..aE<$2.STATE>(4, _omitFieldNames ? '' : 'state',
        enumValues: $2.STATE.values)
    ..aOM<$1.Timestamp>(5, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AccessObject clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AccessObject copyWith(void Function(AccessObject) updates) =>
      super.copyWith((message) => updates(message as AccessObject))
          as AccessObject;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use AccessObject() / AccessObject.new instead')
  static AccessObject create() => AccessObject._();
  static $pb.GeneratedMessage $_createMessage() => AccessObject._();
  @$core.override
  AccessObject createEmptyInstance() => AccessObject._();
  @$core.pragma('dart2js:noInline')
  static AccessObject getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<AccessObject>(
          AccessObject.$_createMessage);
  static AccessObject? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get profileId => $_getSZ(1);
  @$pb.TagNumber(2)
  set profileId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasProfileId() => $_has(1);
  @$pb.TagNumber(2)
  void clearProfileId() => $_clearField(2);

  @$pb.TagNumber(3)
  PartitionObject get partition => $_getN(2);
  @$pb.TagNumber(3)
  set partition(PartitionObject value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasPartition() => $_has(2);
  @$pb.TagNumber(3)
  void clearPartition() => $_clearField(3);
  @$pb.TagNumber(3)
  PartitionObject ensurePartition() => $_ensure(2);

  @$pb.TagNumber(4)
  $2.STATE get state => $_getN(3);
  @$pb.TagNumber(4)
  set state($2.STATE value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasState() => $_has(3);
  @$pb.TagNumber(4)
  void clearState() => $_clearField(4);

  @$pb.TagNumber(5)
  $1.Timestamp get createdAt => $_getN(4);
  @$pb.TagNumber(5)
  set createdAt($1.Timestamp value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasCreatedAt() => $_has(4);
  @$pb.TagNumber(5)
  void clearCreatedAt() => $_clearField(5);
  @$pb.TagNumber(5)
  $1.Timestamp ensureCreatedAt() => $_ensure(4);
}

/// AccessRoleObject links an access grant to a partition role.
class AccessRoleObject extends $pb.GeneratedMessage {
  factory AccessRoleObject({
    $core.String? id,
    $core.String? accessId,
    PartitionRoleObject? role,
  }) {
    final result = AccessRoleObject._();
    if (id != null) result.id = id;
    if (accessId != null) result.accessId = accessId;
    if (role != null) result.role = role;
    return result;
  }

  AccessRoleObject._();

  factory AccessRoleObject.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AccessRoleObject()..mergeFromBuffer(data, registry);
  factory AccessRoleObject.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AccessRoleObject()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'AccessRoleObject',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: AccessRoleObject.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'accessId')
    ..aOM<PartitionRoleObject>(3, _omitFieldNames ? '' : 'role',
        subBuilder: PartitionRoleObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AccessRoleObject clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AccessRoleObject copyWith(void Function(AccessRoleObject) updates) =>
      super.copyWith((message) => updates(message as AccessRoleObject))
          as AccessRoleObject;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use AccessRoleObject() / AccessRoleObject.new instead')
  static AccessRoleObject create() => AccessRoleObject._();
  static $pb.GeneratedMessage $_createMessage() => AccessRoleObject._();
  @$core.override
  AccessRoleObject createEmptyInstance() => AccessRoleObject._();
  @$core.pragma('dart2js:noInline')
  static AccessRoleObject getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<AccessRoleObject>(
          AccessRoleObject.$_createMessage);
  static AccessRoleObject? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get accessId => $_getSZ(1);
  @$pb.TagNumber(2)
  set accessId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasAccessId() => $_has(1);
  @$pb.TagNumber(2)
  void clearAccessId() => $_clearField(2);

  @$pb.TagNumber(3)
  PartitionRoleObject get role => $_getN(2);
  @$pb.TagNumber(3)
  set role(PartitionRoleObject value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasRole() => $_has(2);
  @$pb.TagNumber(3)
  void clearRole() => $_clearField(3);
  @$pb.TagNumber(3)
  PartitionRoleObject ensureRole() => $_ensure(2);
}

class GetTenantRequest extends $pb.GeneratedMessage {
  factory GetTenantRequest({
    $core.String? id,
  }) {
    final result = GetTenantRequest._();
    if (id != null) result.id = id;
    return result;
  }

  GetTenantRequest._();

  factory GetTenantRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetTenantRequest()..mergeFromBuffer(data, registry);
  factory GetTenantRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetTenantRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetTenantRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: GetTenantRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetTenantRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetTenantRequest copyWith(void Function(GetTenantRequest) updates) =>
      super.copyWith((message) => updates(message as GetTenantRequest))
          as GetTenantRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use GetTenantRequest() / GetTenantRequest.new instead')
  static GetTenantRequest create() => GetTenantRequest._();
  static $pb.GeneratedMessage $_createMessage() => GetTenantRequest._();
  @$core.override
  GetTenantRequest createEmptyInstance() => GetTenantRequest._();
  @$core.pragma('dart2js:noInline')
  static GetTenantRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetTenantRequest>(
          GetTenantRequest.$_createMessage);
  static GetTenantRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class GetTenantResponse extends $pb.GeneratedMessage {
  factory GetTenantResponse({
    TenantObject? data,
  }) {
    final result = GetTenantResponse._();
    if (data != null) result.data = data;
    return result;
  }

  GetTenantResponse._();

  factory GetTenantResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetTenantResponse()..mergeFromBuffer(data, registry);
  factory GetTenantResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetTenantResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetTenantResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: GetTenantResponse.$_createMessage)
    ..aOM<TenantObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: TenantObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetTenantResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetTenantResponse copyWith(void Function(GetTenantResponse) updates) =>
      super.copyWith((message) => updates(message as GetTenantResponse))
          as GetTenantResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use GetTenantResponse() / GetTenantResponse.new instead')
  static GetTenantResponse create() => GetTenantResponse._();
  static $pb.GeneratedMessage $_createMessage() => GetTenantResponse._();
  @$core.override
  GetTenantResponse createEmptyInstance() => GetTenantResponse._();
  @$core.pragma('dart2js:noInline')
  static GetTenantResponse getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetTenantResponse>(
          GetTenantResponse.$_createMessage);
  static GetTenantResponse? _defaultInstance;

  @$pb.TagNumber(1)
  TenantObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(TenantObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  TenantObject ensureData() => $_ensure(0);
}

class ListTenantRequest extends $pb.GeneratedMessage {
  factory ListTenantRequest({
    $core.String? query,
    $2.PageCursor? cursor,
    $core.String? startDate,
    $core.String? endDate,
    $core.Iterable<$core.String>? properties,
    $0.Struct? extras,
    TenantEnvironment? environment,
  }) {
    final result = ListTenantRequest._();
    if (query != null) result.query = query;
    if (cursor != null) result.cursor = cursor;
    if (startDate != null) result.startDate = startDate;
    if (endDate != null) result.endDate = endDate;
    if (properties != null) result.properties.addAll(properties);
    if (extras != null) result.extras = extras;
    if (environment != null) result.environment = environment;
    return result;
  }

  ListTenantRequest._();

  factory ListTenantRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListTenantRequest()..mergeFromBuffer(data, registry);
  factory ListTenantRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListTenantRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListTenantRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListTenantRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'query')
    ..aOM<$2.PageCursor>(2, _omitFieldNames ? '' : 'cursor',
        subBuilder: $2.PageCursor.$_createMessage)
    ..aOS(4, _omitFieldNames ? '' : 'startDate')
    ..aOS(5, _omitFieldNames ? '' : 'endDate')
    ..pPS(6, _omitFieldNames ? '' : 'properties')
    ..aOM<$0.Struct>(7, _omitFieldNames ? '' : 'extras',
        subBuilder: $0.Struct.$_createMessage)
    ..aE<TenantEnvironment>(8, _omitFieldNames ? '' : 'environment',
        enumValues: TenantEnvironment.values)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListTenantRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListTenantRequest copyWith(void Function(ListTenantRequest) updates) =>
      super.copyWith((message) => updates(message as ListTenantRequest))
          as ListTenantRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use ListTenantRequest() / ListTenantRequest.new instead')
  static ListTenantRequest create() => ListTenantRequest._();
  static $pb.GeneratedMessage $_createMessage() => ListTenantRequest._();
  @$core.override
  ListTenantRequest createEmptyInstance() => ListTenantRequest._();
  @$core.pragma('dart2js:noInline')
  static ListTenantRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ListTenantRequest>(
          ListTenantRequest.$_createMessage);
  static ListTenantRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get query => $_getSZ(0);
  @$pb.TagNumber(1)
  set query($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasQuery() => $_has(0);
  @$pb.TagNumber(1)
  void clearQuery() => $_clearField(1);

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

  @$pb.TagNumber(4)
  $core.String get startDate => $_getSZ(2);
  @$pb.TagNumber(4)
  set startDate($core.String value) => $_setString(2, value);
  @$pb.TagNumber(4)
  $core.bool hasStartDate() => $_has(2);
  @$pb.TagNumber(4)
  void clearStartDate() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.String get endDate => $_getSZ(3);
  @$pb.TagNumber(5)
  set endDate($core.String value) => $_setString(3, value);
  @$pb.TagNumber(5)
  $core.bool hasEndDate() => $_has(3);
  @$pb.TagNumber(5)
  void clearEndDate() => $_clearField(5);

  @$pb.TagNumber(6)
  $pb.PbList<$core.String> get properties => $_getList(4);

  @$pb.TagNumber(7)
  $0.Struct get extras => $_getN(5);
  @$pb.TagNumber(7)
  set extras($0.Struct value) => $_setField(7, value);
  @$pb.TagNumber(7)
  $core.bool hasExtras() => $_has(5);
  @$pb.TagNumber(7)
  void clearExtras() => $_clearField(7);
  @$pb.TagNumber(7)
  $0.Struct ensureExtras() => $_ensure(5);

  @$pb.TagNumber(8)
  TenantEnvironment get environment => $_getN(6);
  @$pb.TagNumber(8)
  set environment(TenantEnvironment value) => $_setField(8, value);
  @$pb.TagNumber(8)
  $core.bool hasEnvironment() => $_has(6);
  @$pb.TagNumber(8)
  void clearEnvironment() => $_clearField(8);
}

class ListTenantResponse extends $pb.GeneratedMessage {
  factory ListTenantResponse({
    $core.Iterable<TenantObject>? data,
  }) {
    final result = ListTenantResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  ListTenantResponse._();

  factory ListTenantResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListTenantResponse()..mergeFromBuffer(data, registry);
  factory ListTenantResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListTenantResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListTenantResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListTenantResponse.$_createMessage)
    ..pPM<TenantObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: TenantObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListTenantResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListTenantResponse copyWith(void Function(ListTenantResponse) updates) =>
      super.copyWith((message) => updates(message as ListTenantResponse))
          as ListTenantResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use ListTenantResponse() / ListTenantResponse.new instead')
  static ListTenantResponse create() => ListTenantResponse._();
  static $pb.GeneratedMessage $_createMessage() => ListTenantResponse._();
  @$core.override
  ListTenantResponse createEmptyInstance() => ListTenantResponse._();
  @$core.pragma('dart2js:noInline')
  static ListTenantResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListTenantResponse>(
          ListTenantResponse.$_createMessage);
  static ListTenantResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<TenantObject> get data => $_getList(0);
}

class CreateTenantRequest extends $pb.GeneratedMessage {
  factory CreateTenantRequest({
    $core.String? name,
    $core.String? description,
    $0.Struct? properties,
    TenantEnvironment? environment,
  }) {
    final result = CreateTenantRequest._();
    if (name != null) result.name = name;
    if (description != null) result.description = description;
    if (properties != null) result.properties = properties;
    if (environment != null) result.environment = environment;
    return result;
  }

  CreateTenantRequest._();

  factory CreateTenantRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateTenantRequest()..mergeFromBuffer(data, registry);
  factory CreateTenantRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateTenantRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateTenantRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: CreateTenantRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'name')
    ..aOS(2, _omitFieldNames ? '' : 'description')
    ..aOM<$0.Struct>(3, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..aE<TenantEnvironment>(4, _omitFieldNames ? '' : 'environment',
        enumValues: TenantEnvironment.values)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateTenantRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateTenantRequest copyWith(void Function(CreateTenantRequest) updates) =>
      super.copyWith((message) => updates(message as CreateTenantRequest))
          as CreateTenantRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core
      .Deprecated('Use CreateTenantRequest() / CreateTenantRequest.new instead')
  static CreateTenantRequest create() => CreateTenantRequest._();
  static $pb.GeneratedMessage $_createMessage() => CreateTenantRequest._();
  @$core.override
  CreateTenantRequest createEmptyInstance() => CreateTenantRequest._();
  @$core.pragma('dart2js:noInline')
  static CreateTenantRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateTenantRequest>(
          CreateTenantRequest.$_createMessage);
  static CreateTenantRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get name => $_getSZ(0);
  @$pb.TagNumber(1)
  set name($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasName() => $_has(0);
  @$pb.TagNumber(1)
  void clearName() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get description => $_getSZ(1);
  @$pb.TagNumber(2)
  set description($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasDescription() => $_has(1);
  @$pb.TagNumber(2)
  void clearDescription() => $_clearField(2);

  @$pb.TagNumber(3)
  $0.Struct get properties => $_getN(2);
  @$pb.TagNumber(3)
  set properties($0.Struct value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasProperties() => $_has(2);
  @$pb.TagNumber(3)
  void clearProperties() => $_clearField(3);
  @$pb.TagNumber(3)
  $0.Struct ensureProperties() => $_ensure(2);

  @$pb.TagNumber(4)
  TenantEnvironment get environment => $_getN(3);
  @$pb.TagNumber(4)
  set environment(TenantEnvironment value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasEnvironment() => $_has(3);
  @$pb.TagNumber(4)
  void clearEnvironment() => $_clearField(4);
}

class CreateTenantResponse extends $pb.GeneratedMessage {
  factory CreateTenantResponse({
    TenantObject? data,
  }) {
    final result = CreateTenantResponse._();
    if (data != null) result.data = data;
    return result;
  }

  CreateTenantResponse._();

  factory CreateTenantResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateTenantResponse()..mergeFromBuffer(data, registry);
  factory CreateTenantResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateTenantResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateTenantResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: CreateTenantResponse.$_createMessage)
    ..aOM<TenantObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: TenantObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateTenantResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateTenantResponse copyWith(void Function(CreateTenantResponse) updates) =>
      super.copyWith((message) => updates(message as CreateTenantResponse))
          as CreateTenantResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreateTenantResponse() / CreateTenantResponse.new instead')
  static CreateTenantResponse create() => CreateTenantResponse._();
  static $pb.GeneratedMessage $_createMessage() => CreateTenantResponse._();
  @$core.override
  CreateTenantResponse createEmptyInstance() => CreateTenantResponse._();
  @$core.pragma('dart2js:noInline')
  static CreateTenantResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateTenantResponse>(
          CreateTenantResponse.$_createMessage);
  static CreateTenantResponse? _defaultInstance;

  @$pb.TagNumber(1)
  TenantObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(TenantObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  TenantObject ensureData() => $_ensure(0);
}

class UpdateTenantRequest extends $pb.GeneratedMessage {
  factory UpdateTenantRequest({
    $core.String? id,
    $core.String? name,
    $core.String? description,
    $2.STATE? state,
    $0.Struct? properties,
    TenantEnvironment? environment,
  }) {
    final result = UpdateTenantRequest._();
    if (id != null) result.id = id;
    if (name != null) result.name = name;
    if (description != null) result.description = description;
    if (state != null) result.state = state;
    if (properties != null) result.properties = properties;
    if (environment != null) result.environment = environment;
    return result;
  }

  UpdateTenantRequest._();

  factory UpdateTenantRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdateTenantRequest()..mergeFromBuffer(data, registry);
  factory UpdateTenantRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdateTenantRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdateTenantRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: UpdateTenantRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'description')
    ..aE<$2.STATE>(4, _omitFieldNames ? '' : 'state',
        enumValues: $2.STATE.values)
    ..aOM<$0.Struct>(5, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..aE<TenantEnvironment>(6, _omitFieldNames ? '' : 'environment',
        enumValues: TenantEnvironment.values)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdateTenantRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdateTenantRequest copyWith(void Function(UpdateTenantRequest) updates) =>
      super.copyWith((message) => updates(message as UpdateTenantRequest))
          as UpdateTenantRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core
      .Deprecated('Use UpdateTenantRequest() / UpdateTenantRequest.new instead')
  static UpdateTenantRequest create() => UpdateTenantRequest._();
  static $pb.GeneratedMessage $_createMessage() => UpdateTenantRequest._();
  @$core.override
  UpdateTenantRequest createEmptyInstance() => UpdateTenantRequest._();
  @$core.pragma('dart2js:noInline')
  static UpdateTenantRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdateTenantRequest>(
          UpdateTenantRequest.$_createMessage);
  static UpdateTenantRequest? _defaultInstance;

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
  $core.String get description => $_getSZ(2);
  @$pb.TagNumber(3)
  set description($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasDescription() => $_has(2);
  @$pb.TagNumber(3)
  void clearDescription() => $_clearField(3);

  @$pb.TagNumber(4)
  $2.STATE get state => $_getN(3);
  @$pb.TagNumber(4)
  set state($2.STATE value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasState() => $_has(3);
  @$pb.TagNumber(4)
  void clearState() => $_clearField(4);

  @$pb.TagNumber(5)
  $0.Struct get properties => $_getN(4);
  @$pb.TagNumber(5)
  set properties($0.Struct value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasProperties() => $_has(4);
  @$pb.TagNumber(5)
  void clearProperties() => $_clearField(5);
  @$pb.TagNumber(5)
  $0.Struct ensureProperties() => $_ensure(4);

  @$pb.TagNumber(6)
  TenantEnvironment get environment => $_getN(5);
  @$pb.TagNumber(6)
  set environment(TenantEnvironment value) => $_setField(6, value);
  @$pb.TagNumber(6)
  $core.bool hasEnvironment() => $_has(5);
  @$pb.TagNumber(6)
  void clearEnvironment() => $_clearField(6);
}

class UpdateTenantResponse extends $pb.GeneratedMessage {
  factory UpdateTenantResponse({
    TenantObject? data,
  }) {
    final result = UpdateTenantResponse._();
    if (data != null) result.data = data;
    return result;
  }

  UpdateTenantResponse._();

  factory UpdateTenantResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdateTenantResponse()..mergeFromBuffer(data, registry);
  factory UpdateTenantResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdateTenantResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdateTenantResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: UpdateTenantResponse.$_createMessage)
    ..aOM<TenantObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: TenantObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdateTenantResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdateTenantResponse copyWith(void Function(UpdateTenantResponse) updates) =>
      super.copyWith((message) => updates(message as UpdateTenantResponse))
          as UpdateTenantResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use UpdateTenantResponse() / UpdateTenantResponse.new instead')
  static UpdateTenantResponse create() => UpdateTenantResponse._();
  static $pb.GeneratedMessage $_createMessage() => UpdateTenantResponse._();
  @$core.override
  UpdateTenantResponse createEmptyInstance() => UpdateTenantResponse._();
  @$core.pragma('dart2js:noInline')
  static UpdateTenantResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdateTenantResponse>(
          UpdateTenantResponse.$_createMessage);
  static UpdateTenantResponse? _defaultInstance;

  @$pb.TagNumber(1)
  TenantObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(TenantObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  TenantObject ensureData() => $_ensure(0);
}

class RemoveTenantRequest extends $pb.GeneratedMessage {
  factory RemoveTenantRequest({
    $core.String? id,
  }) {
    final result = RemoveTenantRequest._();
    if (id != null) result.id = id;
    return result;
  }

  RemoveTenantRequest._();

  factory RemoveTenantRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveTenantRequest()..mergeFromBuffer(data, registry);
  factory RemoveTenantRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveTenantRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveTenantRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RemoveTenantRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveTenantRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveTenantRequest copyWith(void Function(RemoveTenantRequest) updates) =>
      super.copyWith((message) => updates(message as RemoveTenantRequest))
          as RemoveTenantRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core
      .Deprecated('Use RemoveTenantRequest() / RemoveTenantRequest.new instead')
  static RemoveTenantRequest create() => RemoveTenantRequest._();
  static $pb.GeneratedMessage $_createMessage() => RemoveTenantRequest._();
  @$core.override
  RemoveTenantRequest createEmptyInstance() => RemoveTenantRequest._();
  @$core.pragma('dart2js:noInline')
  static RemoveTenantRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveTenantRequest>(
          RemoveTenantRequest.$_createMessage);
  static RemoveTenantRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class RemoveTenantResponse extends $pb.GeneratedMessage {
  factory RemoveTenantResponse({
    $core.bool? succeeded,
  }) {
    final result = RemoveTenantResponse._();
    if (succeeded != null) result.succeeded = succeeded;
    return result;
  }

  RemoveTenantResponse._();

  factory RemoveTenantResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveTenantResponse()..mergeFromBuffer(data, registry);
  factory RemoveTenantResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveTenantResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveTenantResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RemoveTenantResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'succeeded')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveTenantResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveTenantResponse copyWith(void Function(RemoveTenantResponse) updates) =>
      super.copyWith((message) => updates(message as RemoveTenantResponse))
          as RemoveTenantResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RemoveTenantResponse() / RemoveTenantResponse.new instead')
  static RemoveTenantResponse create() => RemoveTenantResponse._();
  static $pb.GeneratedMessage $_createMessage() => RemoveTenantResponse._();
  @$core.override
  RemoveTenantResponse createEmptyInstance() => RemoveTenantResponse._();
  @$core.pragma('dart2js:noInline')
  static RemoveTenantResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveTenantResponse>(
          RemoveTenantResponse.$_createMessage);
  static RemoveTenantResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get succeeded => $_getBF(0);
  @$pb.TagNumber(1)
  set succeeded($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSucceeded() => $_has(0);
  @$pb.TagNumber(1)
  void clearSucceeded() => $_clearField(1);
}

class GetPartitionRequest extends $pb.GeneratedMessage {
  factory GetPartitionRequest({
    $core.String? id,
    $core.String? domain,
  }) {
    final result = GetPartitionRequest._();
    if (id != null) result.id = id;
    if (domain != null) result.domain = domain;
    return result;
  }

  GetPartitionRequest._();

  factory GetPartitionRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetPartitionRequest()..mergeFromBuffer(data, registry);
  factory GetPartitionRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetPartitionRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetPartitionRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: GetPartitionRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'domain')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPartitionRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPartitionRequest copyWith(void Function(GetPartitionRequest) updates) =>
      super.copyWith((message) => updates(message as GetPartitionRequest))
          as GetPartitionRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core
      .Deprecated('Use GetPartitionRequest() / GetPartitionRequest.new instead')
  static GetPartitionRequest create() => GetPartitionRequest._();
  static $pb.GeneratedMessage $_createMessage() => GetPartitionRequest._();
  @$core.override
  GetPartitionRequest createEmptyInstance() => GetPartitionRequest._();
  @$core.pragma('dart2js:noInline')
  static GetPartitionRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetPartitionRequest>(
          GetPartitionRequest.$_createMessage);
  static GetPartitionRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get domain => $_getSZ(1);
  @$pb.TagNumber(2)
  set domain($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasDomain() => $_has(1);
  @$pb.TagNumber(2)
  void clearDomain() => $_clearField(2);
}

class GetPartitionResponse extends $pb.GeneratedMessage {
  factory GetPartitionResponse({
    PartitionObject? data,
  }) {
    final result = GetPartitionResponse._();
    if (data != null) result.data = data;
    return result;
  }

  GetPartitionResponse._();

  factory GetPartitionResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetPartitionResponse()..mergeFromBuffer(data, registry);
  factory GetPartitionResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetPartitionResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetPartitionResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: GetPartitionResponse.$_createMessage)
    ..aOM<PartitionObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: PartitionObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPartitionResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPartitionResponse copyWith(void Function(GetPartitionResponse) updates) =>
      super.copyWith((message) => updates(message as GetPartitionResponse))
          as GetPartitionResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetPartitionResponse() / GetPartitionResponse.new instead')
  static GetPartitionResponse create() => GetPartitionResponse._();
  static $pb.GeneratedMessage $_createMessage() => GetPartitionResponse._();
  @$core.override
  GetPartitionResponse createEmptyInstance() => GetPartitionResponse._();
  @$core.pragma('dart2js:noInline')
  static GetPartitionResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetPartitionResponse>(
          GetPartitionResponse.$_createMessage);
  static GetPartitionResponse? _defaultInstance;

  @$pb.TagNumber(1)
  PartitionObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(PartitionObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  PartitionObject ensureData() => $_ensure(0);
}

class GetPartitionParentsRequest extends $pb.GeneratedMessage {
  factory GetPartitionParentsRequest({
    $core.String? id,
  }) {
    final result = GetPartitionParentsRequest._();
    if (id != null) result.id = id;
    return result;
  }

  GetPartitionParentsRequest._();

  factory GetPartitionParentsRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetPartitionParentsRequest()..mergeFromBuffer(data, registry);
  factory GetPartitionParentsRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetPartitionParentsRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetPartitionParentsRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: GetPartitionParentsRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPartitionParentsRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPartitionParentsRequest copyWith(
          void Function(GetPartitionParentsRequest) updates) =>
      super.copyWith(
              (message) => updates(message as GetPartitionParentsRequest))
          as GetPartitionParentsRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetPartitionParentsRequest() / GetPartitionParentsRequest.new instead')
  static GetPartitionParentsRequest create() => GetPartitionParentsRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      GetPartitionParentsRequest._();
  @$core.override
  GetPartitionParentsRequest createEmptyInstance() =>
      GetPartitionParentsRequest._();
  @$core.pragma('dart2js:noInline')
  static GetPartitionParentsRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetPartitionParentsRequest>(
          GetPartitionParentsRequest.$_createMessage);
  static GetPartitionParentsRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class GetPartitionParentsResponse extends $pb.GeneratedMessage {
  factory GetPartitionParentsResponse({
    $core.Iterable<PartitionObject>? data,
  }) {
    final result = GetPartitionParentsResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  GetPartitionParentsResponse._();

  factory GetPartitionParentsResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetPartitionParentsResponse()..mergeFromBuffer(data, registry);
  factory GetPartitionParentsResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetPartitionParentsResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetPartitionParentsResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: GetPartitionParentsResponse.$_createMessage)
    ..pPM<PartitionObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: PartitionObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPartitionParentsResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPartitionParentsResponse copyWith(
          void Function(GetPartitionParentsResponse) updates) =>
      super.copyWith(
              (message) => updates(message as GetPartitionParentsResponse))
          as GetPartitionParentsResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetPartitionParentsResponse() / GetPartitionParentsResponse.new instead')
  static GetPartitionParentsResponse create() =>
      GetPartitionParentsResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      GetPartitionParentsResponse._();
  @$core.override
  GetPartitionParentsResponse createEmptyInstance() =>
      GetPartitionParentsResponse._();
  @$core.pragma('dart2js:noInline')
  static GetPartitionParentsResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetPartitionParentsResponse>(
          GetPartitionParentsResponse.$_createMessage);
  static GetPartitionParentsResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<PartitionObject> get data => $_getList(0);
}

class ListPartitionRequest extends $pb.GeneratedMessage {
  factory ListPartitionRequest({
    $core.String? query,
    $2.PageCursor? cursor,
    $core.String? startDate,
    $core.String? endDate,
    $core.Iterable<$core.String>? properties,
    $0.Struct? extras,
  }) {
    final result = ListPartitionRequest._();
    if (query != null) result.query = query;
    if (cursor != null) result.cursor = cursor;
    if (startDate != null) result.startDate = startDate;
    if (endDate != null) result.endDate = endDate;
    if (properties != null) result.properties.addAll(properties);
    if (extras != null) result.extras = extras;
    return result;
  }

  ListPartitionRequest._();

  factory ListPartitionRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListPartitionRequest()..mergeFromBuffer(data, registry);
  factory ListPartitionRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListPartitionRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListPartitionRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListPartitionRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'query')
    ..aOM<$2.PageCursor>(2, _omitFieldNames ? '' : 'cursor',
        subBuilder: $2.PageCursor.$_createMessage)
    ..aOS(4, _omitFieldNames ? '' : 'startDate')
    ..aOS(5, _omitFieldNames ? '' : 'endDate')
    ..pPS(6, _omitFieldNames ? '' : 'properties')
    ..aOM<$0.Struct>(7, _omitFieldNames ? '' : 'extras',
        subBuilder: $0.Struct.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListPartitionRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListPartitionRequest copyWith(void Function(ListPartitionRequest) updates) =>
      super.copyWith((message) => updates(message as ListPartitionRequest))
          as ListPartitionRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListPartitionRequest() / ListPartitionRequest.new instead')
  static ListPartitionRequest create() => ListPartitionRequest._();
  static $pb.GeneratedMessage $_createMessage() => ListPartitionRequest._();
  @$core.override
  ListPartitionRequest createEmptyInstance() => ListPartitionRequest._();
  @$core.pragma('dart2js:noInline')
  static ListPartitionRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListPartitionRequest>(
          ListPartitionRequest.$_createMessage);
  static ListPartitionRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get query => $_getSZ(0);
  @$pb.TagNumber(1)
  set query($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasQuery() => $_has(0);
  @$pb.TagNumber(1)
  void clearQuery() => $_clearField(1);

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

  @$pb.TagNumber(4)
  $core.String get startDate => $_getSZ(2);
  @$pb.TagNumber(4)
  set startDate($core.String value) => $_setString(2, value);
  @$pb.TagNumber(4)
  $core.bool hasStartDate() => $_has(2);
  @$pb.TagNumber(4)
  void clearStartDate() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.String get endDate => $_getSZ(3);
  @$pb.TagNumber(5)
  set endDate($core.String value) => $_setString(3, value);
  @$pb.TagNumber(5)
  $core.bool hasEndDate() => $_has(3);
  @$pb.TagNumber(5)
  void clearEndDate() => $_clearField(5);

  @$pb.TagNumber(6)
  $pb.PbList<$core.String> get properties => $_getList(4);

  @$pb.TagNumber(7)
  $0.Struct get extras => $_getN(5);
  @$pb.TagNumber(7)
  set extras($0.Struct value) => $_setField(7, value);
  @$pb.TagNumber(7)
  $core.bool hasExtras() => $_has(5);
  @$pb.TagNumber(7)
  void clearExtras() => $_clearField(7);
  @$pb.TagNumber(7)
  $0.Struct ensureExtras() => $_ensure(5);
}

class ListPartitionResponse extends $pb.GeneratedMessage {
  factory ListPartitionResponse({
    $core.Iterable<PartitionObject>? data,
  }) {
    final result = ListPartitionResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  ListPartitionResponse._();

  factory ListPartitionResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListPartitionResponse()..mergeFromBuffer(data, registry);
  factory ListPartitionResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListPartitionResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListPartitionResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListPartitionResponse.$_createMessage)
    ..pPM<PartitionObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: PartitionObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListPartitionResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListPartitionResponse copyWith(
          void Function(ListPartitionResponse) updates) =>
      super.copyWith((message) => updates(message as ListPartitionResponse))
          as ListPartitionResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListPartitionResponse() / ListPartitionResponse.new instead')
  static ListPartitionResponse create() => ListPartitionResponse._();
  static $pb.GeneratedMessage $_createMessage() => ListPartitionResponse._();
  @$core.override
  ListPartitionResponse createEmptyInstance() => ListPartitionResponse._();
  @$core.pragma('dart2js:noInline')
  static ListPartitionResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListPartitionResponse>(
          ListPartitionResponse.$_createMessage);
  static ListPartitionResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<PartitionObject> get data => $_getList(0);
}

class CreatePartitionRequest extends $pb.GeneratedMessage {
  factory CreatePartitionRequest({
    $core.String? tenantId,
    $core.String? parentId,
    $core.String? name,
    $core.String? description,
    $0.Struct? properties,
    $core.String? domain,
  }) {
    final result = CreatePartitionRequest._();
    if (tenantId != null) result.tenantId = tenantId;
    if (parentId != null) result.parentId = parentId;
    if (name != null) result.name = name;
    if (description != null) result.description = description;
    if (properties != null) result.properties = properties;
    if (domain != null) result.domain = domain;
    return result;
  }

  CreatePartitionRequest._();

  factory CreatePartitionRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreatePartitionRequest()..mergeFromBuffer(data, registry);
  factory CreatePartitionRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreatePartitionRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreatePartitionRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: CreatePartitionRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'tenantId')
    ..aOS(2, _omitFieldNames ? '' : 'parentId')
    ..aOS(3, _omitFieldNames ? '' : 'name')
    ..aOS(4, _omitFieldNames ? '' : 'description')
    ..aOM<$0.Struct>(5, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..aOS(6, _omitFieldNames ? '' : 'domain')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreatePartitionRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreatePartitionRequest copyWith(
          void Function(CreatePartitionRequest) updates) =>
      super.copyWith((message) => updates(message as CreatePartitionRequest))
          as CreatePartitionRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreatePartitionRequest() / CreatePartitionRequest.new instead')
  static CreatePartitionRequest create() => CreatePartitionRequest._();
  static $pb.GeneratedMessage $_createMessage() => CreatePartitionRequest._();
  @$core.override
  CreatePartitionRequest createEmptyInstance() => CreatePartitionRequest._();
  @$core.pragma('dart2js:noInline')
  static CreatePartitionRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreatePartitionRequest>(
          CreatePartitionRequest.$_createMessage);
  static CreatePartitionRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get tenantId => $_getSZ(0);
  @$pb.TagNumber(1)
  set tenantId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasTenantId() => $_has(0);
  @$pb.TagNumber(1)
  void clearTenantId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get parentId => $_getSZ(1);
  @$pb.TagNumber(2)
  set parentId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasParentId() => $_has(1);
  @$pb.TagNumber(2)
  void clearParentId() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get name => $_getSZ(2);
  @$pb.TagNumber(3)
  set name($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasName() => $_has(2);
  @$pb.TagNumber(3)
  void clearName() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get description => $_getSZ(3);
  @$pb.TagNumber(4)
  set description($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasDescription() => $_has(3);
  @$pb.TagNumber(4)
  void clearDescription() => $_clearField(4);

  @$pb.TagNumber(5)
  $0.Struct get properties => $_getN(4);
  @$pb.TagNumber(5)
  set properties($0.Struct value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasProperties() => $_has(4);
  @$pb.TagNumber(5)
  void clearProperties() => $_clearField(5);
  @$pb.TagNumber(5)
  $0.Struct ensureProperties() => $_ensure(4);

  @$pb.TagNumber(6)
  $core.String get domain => $_getSZ(5);
  @$pb.TagNumber(6)
  set domain($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasDomain() => $_has(5);
  @$pb.TagNumber(6)
  void clearDomain() => $_clearField(6);
}

class CreatePartitionResponse extends $pb.GeneratedMessage {
  factory CreatePartitionResponse({
    PartitionObject? data,
  }) {
    final result = CreatePartitionResponse._();
    if (data != null) result.data = data;
    return result;
  }

  CreatePartitionResponse._();

  factory CreatePartitionResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreatePartitionResponse()..mergeFromBuffer(data, registry);
  factory CreatePartitionResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreatePartitionResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreatePartitionResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: CreatePartitionResponse.$_createMessage)
    ..aOM<PartitionObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: PartitionObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreatePartitionResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreatePartitionResponse copyWith(
          void Function(CreatePartitionResponse) updates) =>
      super.copyWith((message) => updates(message as CreatePartitionResponse))
          as CreatePartitionResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreatePartitionResponse() / CreatePartitionResponse.new instead')
  static CreatePartitionResponse create() => CreatePartitionResponse._();
  static $pb.GeneratedMessage $_createMessage() => CreatePartitionResponse._();
  @$core.override
  CreatePartitionResponse createEmptyInstance() => CreatePartitionResponse._();
  @$core.pragma('dart2js:noInline')
  static CreatePartitionResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreatePartitionResponse>(
          CreatePartitionResponse.$_createMessage);
  static CreatePartitionResponse? _defaultInstance;

  @$pb.TagNumber(1)
  PartitionObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(PartitionObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  PartitionObject ensureData() => $_ensure(0);
}

class UpdatePartitionRequest extends $pb.GeneratedMessage {
  factory UpdatePartitionRequest({
    $core.String? id,
    $core.String? name,
    $core.String? description,
    $2.STATE? state,
    $0.Struct? properties,
    $core.String? domain,
  }) {
    final result = UpdatePartitionRequest._();
    if (id != null) result.id = id;
    if (name != null) result.name = name;
    if (description != null) result.description = description;
    if (state != null) result.state = state;
    if (properties != null) result.properties = properties;
    if (domain != null) result.domain = domain;
    return result;
  }

  UpdatePartitionRequest._();

  factory UpdatePartitionRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdatePartitionRequest()..mergeFromBuffer(data, registry);
  factory UpdatePartitionRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdatePartitionRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdatePartitionRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: UpdatePartitionRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'description')
    ..aE<$2.STATE>(4, _omitFieldNames ? '' : 'state',
        enumValues: $2.STATE.values)
    ..aOM<$0.Struct>(5, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..aOS(6, _omitFieldNames ? '' : 'domain')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdatePartitionRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdatePartitionRequest copyWith(
          void Function(UpdatePartitionRequest) updates) =>
      super.copyWith((message) => updates(message as UpdatePartitionRequest))
          as UpdatePartitionRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use UpdatePartitionRequest() / UpdatePartitionRequest.new instead')
  static UpdatePartitionRequest create() => UpdatePartitionRequest._();
  static $pb.GeneratedMessage $_createMessage() => UpdatePartitionRequest._();
  @$core.override
  UpdatePartitionRequest createEmptyInstance() => UpdatePartitionRequest._();
  @$core.pragma('dart2js:noInline')
  static UpdatePartitionRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdatePartitionRequest>(
          UpdatePartitionRequest.$_createMessage);
  static UpdatePartitionRequest? _defaultInstance;

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
  $core.String get description => $_getSZ(2);
  @$pb.TagNumber(3)
  set description($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasDescription() => $_has(2);
  @$pb.TagNumber(3)
  void clearDescription() => $_clearField(3);

  @$pb.TagNumber(4)
  $2.STATE get state => $_getN(3);
  @$pb.TagNumber(4)
  set state($2.STATE value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasState() => $_has(3);
  @$pb.TagNumber(4)
  void clearState() => $_clearField(4);

  @$pb.TagNumber(5)
  $0.Struct get properties => $_getN(4);
  @$pb.TagNumber(5)
  set properties($0.Struct value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasProperties() => $_has(4);
  @$pb.TagNumber(5)
  void clearProperties() => $_clearField(5);
  @$pb.TagNumber(5)
  $0.Struct ensureProperties() => $_ensure(4);

  @$pb.TagNumber(6)
  $core.String get domain => $_getSZ(5);
  @$pb.TagNumber(6)
  set domain($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasDomain() => $_has(5);
  @$pb.TagNumber(6)
  void clearDomain() => $_clearField(6);
}

class UpdatePartitionResponse extends $pb.GeneratedMessage {
  factory UpdatePartitionResponse({
    PartitionObject? data,
  }) {
    final result = UpdatePartitionResponse._();
    if (data != null) result.data = data;
    return result;
  }

  UpdatePartitionResponse._();

  factory UpdatePartitionResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdatePartitionResponse()..mergeFromBuffer(data, registry);
  factory UpdatePartitionResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdatePartitionResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdatePartitionResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: UpdatePartitionResponse.$_createMessage)
    ..aOM<PartitionObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: PartitionObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdatePartitionResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdatePartitionResponse copyWith(
          void Function(UpdatePartitionResponse) updates) =>
      super.copyWith((message) => updates(message as UpdatePartitionResponse))
          as UpdatePartitionResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use UpdatePartitionResponse() / UpdatePartitionResponse.new instead')
  static UpdatePartitionResponse create() => UpdatePartitionResponse._();
  static $pb.GeneratedMessage $_createMessage() => UpdatePartitionResponse._();
  @$core.override
  UpdatePartitionResponse createEmptyInstance() => UpdatePartitionResponse._();
  @$core.pragma('dart2js:noInline')
  static UpdatePartitionResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdatePartitionResponse>(
          UpdatePartitionResponse.$_createMessage);
  static UpdatePartitionResponse? _defaultInstance;

  @$pb.TagNumber(1)
  PartitionObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(PartitionObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  PartitionObject ensureData() => $_ensure(0);
}

class RemovePartitionRequest extends $pb.GeneratedMessage {
  factory RemovePartitionRequest({
    $core.String? id,
  }) {
    final result = RemovePartitionRequest._();
    if (id != null) result.id = id;
    return result;
  }

  RemovePartitionRequest._();

  factory RemovePartitionRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemovePartitionRequest()..mergeFromBuffer(data, registry);
  factory RemovePartitionRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemovePartitionRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemovePartitionRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RemovePartitionRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemovePartitionRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemovePartitionRequest copyWith(
          void Function(RemovePartitionRequest) updates) =>
      super.copyWith((message) => updates(message as RemovePartitionRequest))
          as RemovePartitionRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RemovePartitionRequest() / RemovePartitionRequest.new instead')
  static RemovePartitionRequest create() => RemovePartitionRequest._();
  static $pb.GeneratedMessage $_createMessage() => RemovePartitionRequest._();
  @$core.override
  RemovePartitionRequest createEmptyInstance() => RemovePartitionRequest._();
  @$core.pragma('dart2js:noInline')
  static RemovePartitionRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemovePartitionRequest>(
          RemovePartitionRequest.$_createMessage);
  static RemovePartitionRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class RemovePartitionResponse extends $pb.GeneratedMessage {
  factory RemovePartitionResponse({
    $core.bool? succeeded,
  }) {
    final result = RemovePartitionResponse._();
    if (succeeded != null) result.succeeded = succeeded;
    return result;
  }

  RemovePartitionResponse._();

  factory RemovePartitionResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemovePartitionResponse()..mergeFromBuffer(data, registry);
  factory RemovePartitionResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemovePartitionResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemovePartitionResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RemovePartitionResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'succeeded')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemovePartitionResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemovePartitionResponse copyWith(
          void Function(RemovePartitionResponse) updates) =>
      super.copyWith((message) => updates(message as RemovePartitionResponse))
          as RemovePartitionResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RemovePartitionResponse() / RemovePartitionResponse.new instead')
  static RemovePartitionResponse create() => RemovePartitionResponse._();
  static $pb.GeneratedMessage $_createMessage() => RemovePartitionResponse._();
  @$core.override
  RemovePartitionResponse createEmptyInstance() => RemovePartitionResponse._();
  @$core.pragma('dart2js:noInline')
  static RemovePartitionResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemovePartitionResponse>(
          RemovePartitionResponse.$_createMessage);
  static RemovePartitionResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get succeeded => $_getBF(0);
  @$pb.TagNumber(1)
  set succeeded($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSucceeded() => $_has(0);
  @$pb.TagNumber(1)
  void clearSucceeded() => $_clearField(1);
}

class CreatePartitionRoleRequest extends $pb.GeneratedMessage {
  factory CreatePartitionRoleRequest({
    $core.String? partitionId,
    $core.String? name,
    $0.Struct? properties,
  }) {
    final result = CreatePartitionRoleRequest._();
    if (partitionId != null) result.partitionId = partitionId;
    if (name != null) result.name = name;
    if (properties != null) result.properties = properties;
    return result;
  }

  CreatePartitionRoleRequest._();

  factory CreatePartitionRoleRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreatePartitionRoleRequest()..mergeFromBuffer(data, registry);
  factory CreatePartitionRoleRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreatePartitionRoleRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreatePartitionRoleRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: CreatePartitionRoleRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOM<$0.Struct>(3, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreatePartitionRoleRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreatePartitionRoleRequest copyWith(
          void Function(CreatePartitionRoleRequest) updates) =>
      super.copyWith(
              (message) => updates(message as CreatePartitionRoleRequest))
          as CreatePartitionRoleRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreatePartitionRoleRequest() / CreatePartitionRoleRequest.new instead')
  static CreatePartitionRoleRequest create() => CreatePartitionRoleRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      CreatePartitionRoleRequest._();
  @$core.override
  CreatePartitionRoleRequest createEmptyInstance() =>
      CreatePartitionRoleRequest._();
  @$core.pragma('dart2js:noInline')
  static CreatePartitionRoleRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreatePartitionRoleRequest>(
          CreatePartitionRoleRequest.$_createMessage);
  static CreatePartitionRoleRequest? _defaultInstance;

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
  $0.Struct get properties => $_getN(2);
  @$pb.TagNumber(3)
  set properties($0.Struct value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasProperties() => $_has(2);
  @$pb.TagNumber(3)
  void clearProperties() => $_clearField(3);
  @$pb.TagNumber(3)
  $0.Struct ensureProperties() => $_ensure(2);
}

class CreatePartitionRoleResponse extends $pb.GeneratedMessage {
  factory CreatePartitionRoleResponse({
    PartitionRoleObject? data,
  }) {
    final result = CreatePartitionRoleResponse._();
    if (data != null) result.data = data;
    return result;
  }

  CreatePartitionRoleResponse._();

  factory CreatePartitionRoleResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreatePartitionRoleResponse()..mergeFromBuffer(data, registry);
  factory CreatePartitionRoleResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreatePartitionRoleResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreatePartitionRoleResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: CreatePartitionRoleResponse.$_createMessage)
    ..aOM<PartitionRoleObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: PartitionRoleObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreatePartitionRoleResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreatePartitionRoleResponse copyWith(
          void Function(CreatePartitionRoleResponse) updates) =>
      super.copyWith(
              (message) => updates(message as CreatePartitionRoleResponse))
          as CreatePartitionRoleResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreatePartitionRoleResponse() / CreatePartitionRoleResponse.new instead')
  static CreatePartitionRoleResponse create() =>
      CreatePartitionRoleResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      CreatePartitionRoleResponse._();
  @$core.override
  CreatePartitionRoleResponse createEmptyInstance() =>
      CreatePartitionRoleResponse._();
  @$core.pragma('dart2js:noInline')
  static CreatePartitionRoleResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreatePartitionRoleResponse>(
          CreatePartitionRoleResponse.$_createMessage);
  static CreatePartitionRoleResponse? _defaultInstance;

  @$pb.TagNumber(1)
  PartitionRoleObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(PartitionRoleObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  PartitionRoleObject ensureData() => $_ensure(0);
}

class UpdatePartitionRoleRequest extends $pb.GeneratedMessage {
  factory UpdatePartitionRoleRequest({
    $core.String? id,
    $core.String? name,
    $0.Struct? properties,
    $2.STATE? state,
  }) {
    final result = UpdatePartitionRoleRequest._();
    if (id != null) result.id = id;
    if (name != null) result.name = name;
    if (properties != null) result.properties = properties;
    if (state != null) result.state = state;
    return result;
  }

  UpdatePartitionRoleRequest._();

  factory UpdatePartitionRoleRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdatePartitionRoleRequest()..mergeFromBuffer(data, registry);
  factory UpdatePartitionRoleRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdatePartitionRoleRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdatePartitionRoleRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: UpdatePartitionRoleRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOM<$0.Struct>(3, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..aE<$2.STATE>(4, _omitFieldNames ? '' : 'state',
        enumValues: $2.STATE.values)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdatePartitionRoleRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdatePartitionRoleRequest copyWith(
          void Function(UpdatePartitionRoleRequest) updates) =>
      super.copyWith(
              (message) => updates(message as UpdatePartitionRoleRequest))
          as UpdatePartitionRoleRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use UpdatePartitionRoleRequest() / UpdatePartitionRoleRequest.new instead')
  static UpdatePartitionRoleRequest create() => UpdatePartitionRoleRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      UpdatePartitionRoleRequest._();
  @$core.override
  UpdatePartitionRoleRequest createEmptyInstance() =>
      UpdatePartitionRoleRequest._();
  @$core.pragma('dart2js:noInline')
  static UpdatePartitionRoleRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdatePartitionRoleRequest>(
          UpdatePartitionRoleRequest.$_createMessage);
  static UpdatePartitionRoleRequest? _defaultInstance;

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
  $0.Struct get properties => $_getN(2);
  @$pb.TagNumber(3)
  set properties($0.Struct value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasProperties() => $_has(2);
  @$pb.TagNumber(3)
  void clearProperties() => $_clearField(3);
  @$pb.TagNumber(3)
  $0.Struct ensureProperties() => $_ensure(2);

  @$pb.TagNumber(4)
  $2.STATE get state => $_getN(3);
  @$pb.TagNumber(4)
  set state($2.STATE value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasState() => $_has(3);
  @$pb.TagNumber(4)
  void clearState() => $_clearField(4);
}

class UpdatePartitionRoleResponse extends $pb.GeneratedMessage {
  factory UpdatePartitionRoleResponse({
    PartitionRoleObject? data,
  }) {
    final result = UpdatePartitionRoleResponse._();
    if (data != null) result.data = data;
    return result;
  }

  UpdatePartitionRoleResponse._();

  factory UpdatePartitionRoleResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdatePartitionRoleResponse()..mergeFromBuffer(data, registry);
  factory UpdatePartitionRoleResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdatePartitionRoleResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdatePartitionRoleResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: UpdatePartitionRoleResponse.$_createMessage)
    ..aOM<PartitionRoleObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: PartitionRoleObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdatePartitionRoleResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdatePartitionRoleResponse copyWith(
          void Function(UpdatePartitionRoleResponse) updates) =>
      super.copyWith(
              (message) => updates(message as UpdatePartitionRoleResponse))
          as UpdatePartitionRoleResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use UpdatePartitionRoleResponse() / UpdatePartitionRoleResponse.new instead')
  static UpdatePartitionRoleResponse create() =>
      UpdatePartitionRoleResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      UpdatePartitionRoleResponse._();
  @$core.override
  UpdatePartitionRoleResponse createEmptyInstance() =>
      UpdatePartitionRoleResponse._();
  @$core.pragma('dart2js:noInline')
  static UpdatePartitionRoleResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdatePartitionRoleResponse>(
          UpdatePartitionRoleResponse.$_createMessage);
  static UpdatePartitionRoleResponse? _defaultInstance;

  @$pb.TagNumber(1)
  PartitionRoleObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(PartitionRoleObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  PartitionRoleObject ensureData() => $_ensure(0);
}

class RemovePartitionRoleRequest extends $pb.GeneratedMessage {
  factory RemovePartitionRoleRequest({
    $core.String? id,
  }) {
    final result = RemovePartitionRoleRequest._();
    if (id != null) result.id = id;
    return result;
  }

  RemovePartitionRoleRequest._();

  factory RemovePartitionRoleRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemovePartitionRoleRequest()..mergeFromBuffer(data, registry);
  factory RemovePartitionRoleRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemovePartitionRoleRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemovePartitionRoleRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RemovePartitionRoleRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemovePartitionRoleRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemovePartitionRoleRequest copyWith(
          void Function(RemovePartitionRoleRequest) updates) =>
      super.copyWith(
              (message) => updates(message as RemovePartitionRoleRequest))
          as RemovePartitionRoleRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RemovePartitionRoleRequest() / RemovePartitionRoleRequest.new instead')
  static RemovePartitionRoleRequest create() => RemovePartitionRoleRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      RemovePartitionRoleRequest._();
  @$core.override
  RemovePartitionRoleRequest createEmptyInstance() =>
      RemovePartitionRoleRequest._();
  @$core.pragma('dart2js:noInline')
  static RemovePartitionRoleRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemovePartitionRoleRequest>(
          RemovePartitionRoleRequest.$_createMessage);
  static RemovePartitionRoleRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class RemovePartitionRoleResponse extends $pb.GeneratedMessage {
  factory RemovePartitionRoleResponse({
    $core.bool? succeeded,
  }) {
    final result = RemovePartitionRoleResponse._();
    if (succeeded != null) result.succeeded = succeeded;
    return result;
  }

  RemovePartitionRoleResponse._();

  factory RemovePartitionRoleResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemovePartitionRoleResponse()..mergeFromBuffer(data, registry);
  factory RemovePartitionRoleResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemovePartitionRoleResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemovePartitionRoleResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RemovePartitionRoleResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'succeeded')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemovePartitionRoleResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemovePartitionRoleResponse copyWith(
          void Function(RemovePartitionRoleResponse) updates) =>
      super.copyWith(
              (message) => updates(message as RemovePartitionRoleResponse))
          as RemovePartitionRoleResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RemovePartitionRoleResponse() / RemovePartitionRoleResponse.new instead')
  static RemovePartitionRoleResponse create() =>
      RemovePartitionRoleResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      RemovePartitionRoleResponse._();
  @$core.override
  RemovePartitionRoleResponse createEmptyInstance() =>
      RemovePartitionRoleResponse._();
  @$core.pragma('dart2js:noInline')
  static RemovePartitionRoleResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemovePartitionRoleResponse>(
          RemovePartitionRoleResponse.$_createMessage);
  static RemovePartitionRoleResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get succeeded => $_getBF(0);
  @$pb.TagNumber(1)
  set succeeded($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSucceeded() => $_has(0);
  @$pb.TagNumber(1)
  void clearSucceeded() => $_clearField(1);
}

class ListPartitionRoleRequest extends $pb.GeneratedMessage {
  factory ListPartitionRoleRequest({
    $core.String? partitionId,
    $2.PageCursor? cursor,
  }) {
    final result = ListPartitionRoleRequest._();
    if (partitionId != null) result.partitionId = partitionId;
    if (cursor != null) result.cursor = cursor;
    return result;
  }

  ListPartitionRoleRequest._();

  factory ListPartitionRoleRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListPartitionRoleRequest()..mergeFromBuffer(data, registry);
  factory ListPartitionRoleRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListPartitionRoleRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListPartitionRoleRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListPartitionRoleRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOM<$2.PageCursor>(2, _omitFieldNames ? '' : 'cursor',
        subBuilder: $2.PageCursor.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListPartitionRoleRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListPartitionRoleRequest copyWith(
          void Function(ListPartitionRoleRequest) updates) =>
      super.copyWith((message) => updates(message as ListPartitionRoleRequest))
          as ListPartitionRoleRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListPartitionRoleRequest() / ListPartitionRoleRequest.new instead')
  static ListPartitionRoleRequest create() => ListPartitionRoleRequest._();
  static $pb.GeneratedMessage $_createMessage() => ListPartitionRoleRequest._();
  @$core.override
  ListPartitionRoleRequest createEmptyInstance() =>
      ListPartitionRoleRequest._();
  @$core.pragma('dart2js:noInline')
  static ListPartitionRoleRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListPartitionRoleRequest>(
          ListPartitionRoleRequest.$_createMessage);
  static ListPartitionRoleRequest? _defaultInstance;

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

class ListPartitionRoleResponse extends $pb.GeneratedMessage {
  factory ListPartitionRoleResponse({
    $core.Iterable<PartitionRoleObject>? data,
  }) {
    final result = ListPartitionRoleResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  ListPartitionRoleResponse._();

  factory ListPartitionRoleResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListPartitionRoleResponse()..mergeFromBuffer(data, registry);
  factory ListPartitionRoleResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListPartitionRoleResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListPartitionRoleResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListPartitionRoleResponse.$_createMessage)
    ..pPM<PartitionRoleObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: PartitionRoleObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListPartitionRoleResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListPartitionRoleResponse copyWith(
          void Function(ListPartitionRoleResponse) updates) =>
      super.copyWith((message) => updates(message as ListPartitionRoleResponse))
          as ListPartitionRoleResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListPartitionRoleResponse() / ListPartitionRoleResponse.new instead')
  static ListPartitionRoleResponse create() => ListPartitionRoleResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      ListPartitionRoleResponse._();
  @$core.override
  ListPartitionRoleResponse createEmptyInstance() =>
      ListPartitionRoleResponse._();
  @$core.pragma('dart2js:noInline')
  static ListPartitionRoleResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListPartitionRoleResponse>(
          ListPartitionRoleResponse.$_createMessage);
  static ListPartitionRoleResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<PartitionRoleObject> get data => $_getList(0);
}

class CreatePageRequest extends $pb.GeneratedMessage {
  factory CreatePageRequest({
    $core.String? partitionId,
    $core.String? name,
    $core.String? html,
    $0.Struct? properties,
  }) {
    final result = CreatePageRequest._();
    if (partitionId != null) result.partitionId = partitionId;
    if (name != null) result.name = name;
    if (html != null) result.html = html;
    if (properties != null) result.properties = properties;
    return result;
  }

  CreatePageRequest._();

  factory CreatePageRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreatePageRequest()..mergeFromBuffer(data, registry);
  factory CreatePageRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreatePageRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreatePageRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: CreatePageRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'html')
    ..aOM<$0.Struct>(4, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreatePageRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreatePageRequest copyWith(void Function(CreatePageRequest) updates) =>
      super.copyWith((message) => updates(message as CreatePageRequest))
          as CreatePageRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use CreatePageRequest() / CreatePageRequest.new instead')
  static CreatePageRequest create() => CreatePageRequest._();
  static $pb.GeneratedMessage $_createMessage() => CreatePageRequest._();
  @$core.override
  CreatePageRequest createEmptyInstance() => CreatePageRequest._();
  @$core.pragma('dart2js:noInline')
  static CreatePageRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<CreatePageRequest>(
          CreatePageRequest.$_createMessage);
  static CreatePageRequest? _defaultInstance;

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
  $core.String get html => $_getSZ(2);
  @$pb.TagNumber(3)
  set html($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasHtml() => $_has(2);
  @$pb.TagNumber(3)
  void clearHtml() => $_clearField(3);

  @$pb.TagNumber(4)
  $0.Struct get properties => $_getN(3);
  @$pb.TagNumber(4)
  set properties($0.Struct value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasProperties() => $_has(3);
  @$pb.TagNumber(4)
  void clearProperties() => $_clearField(4);
  @$pb.TagNumber(4)
  $0.Struct ensureProperties() => $_ensure(3);
}

class CreatePageResponse extends $pb.GeneratedMessage {
  factory CreatePageResponse({
    PageObject? data,
  }) {
    final result = CreatePageResponse._();
    if (data != null) result.data = data;
    return result;
  }

  CreatePageResponse._();

  factory CreatePageResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreatePageResponse()..mergeFromBuffer(data, registry);
  factory CreatePageResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreatePageResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreatePageResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: CreatePageResponse.$_createMessage)
    ..aOM<PageObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: PageObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreatePageResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreatePageResponse copyWith(void Function(CreatePageResponse) updates) =>
      super.copyWith((message) => updates(message as CreatePageResponse))
          as CreatePageResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use CreatePageResponse() / CreatePageResponse.new instead')
  static CreatePageResponse create() => CreatePageResponse._();
  static $pb.GeneratedMessage $_createMessage() => CreatePageResponse._();
  @$core.override
  CreatePageResponse createEmptyInstance() => CreatePageResponse._();
  @$core.pragma('dart2js:noInline')
  static CreatePageResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreatePageResponse>(
          CreatePageResponse.$_createMessage);
  static CreatePageResponse? _defaultInstance;

  @$pb.TagNumber(1)
  PageObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(PageObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  PageObject ensureData() => $_ensure(0);
}

class GetPageRequest extends $pb.GeneratedMessage {
  factory GetPageRequest({
    $core.String? pageId,
    $core.String? partitionId,
    $core.String? name,
  }) {
    final result = GetPageRequest._();
    if (pageId != null) result.pageId = pageId;
    if (partitionId != null) result.partitionId = partitionId;
    if (name != null) result.name = name;
    return result;
  }

  GetPageRequest._();

  factory GetPageRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetPageRequest()..mergeFromBuffer(data, registry);
  factory GetPageRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetPageRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetPageRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: GetPageRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'pageId')
    ..aOS(2, _omitFieldNames ? '' : 'partitionId')
    ..aOS(3, _omitFieldNames ? '' : 'name')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPageRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPageRequest copyWith(void Function(GetPageRequest) updates) =>
      super.copyWith((message) => updates(message as GetPageRequest))
          as GetPageRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use GetPageRequest() / GetPageRequest.new instead')
  static GetPageRequest create() => GetPageRequest._();
  static $pb.GeneratedMessage $_createMessage() => GetPageRequest._();
  @$core.override
  GetPageRequest createEmptyInstance() => GetPageRequest._();
  @$core.pragma('dart2js:noInline')
  static GetPageRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetPageRequest>(
          GetPageRequest.$_createMessage);
  static GetPageRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get pageId => $_getSZ(0);
  @$pb.TagNumber(1)
  set pageId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasPageId() => $_has(0);
  @$pb.TagNumber(1)
  void clearPageId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get partitionId => $_getSZ(1);
  @$pb.TagNumber(2)
  set partitionId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasPartitionId() => $_has(1);
  @$pb.TagNumber(2)
  void clearPartitionId() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get name => $_getSZ(2);
  @$pb.TagNumber(3)
  set name($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasName() => $_has(2);
  @$pb.TagNumber(3)
  void clearName() => $_clearField(3);
}

class GetPageResponse extends $pb.GeneratedMessage {
  factory GetPageResponse({
    PageObject? data,
  }) {
    final result = GetPageResponse._();
    if (data != null) result.data = data;
    return result;
  }

  GetPageResponse._();

  factory GetPageResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetPageResponse()..mergeFromBuffer(data, registry);
  factory GetPageResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetPageResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetPageResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: GetPageResponse.$_createMessage)
    ..aOM<PageObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: PageObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPageResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPageResponse copyWith(void Function(GetPageResponse) updates) =>
      super.copyWith((message) => updates(message as GetPageResponse))
          as GetPageResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use GetPageResponse() / GetPageResponse.new instead')
  static GetPageResponse create() => GetPageResponse._();
  static $pb.GeneratedMessage $_createMessage() => GetPageResponse._();
  @$core.override
  GetPageResponse createEmptyInstance() => GetPageResponse._();
  @$core.pragma('dart2js:noInline')
  static GetPageResponse getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetPageResponse>(
          GetPageResponse.$_createMessage);
  static GetPageResponse? _defaultInstance;

  @$pb.TagNumber(1)
  PageObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(PageObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  PageObject ensureData() => $_ensure(0);
}

class UpdatePageRequest extends $pb.GeneratedMessage {
  factory UpdatePageRequest({
    $core.String? id,
    $core.String? name,
    $core.String? html,
    $2.STATE? state,
    $0.Struct? properties,
  }) {
    final result = UpdatePageRequest._();
    if (id != null) result.id = id;
    if (name != null) result.name = name;
    if (html != null) result.html = html;
    if (state != null) result.state = state;
    if (properties != null) result.properties = properties;
    return result;
  }

  UpdatePageRequest._();

  factory UpdatePageRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdatePageRequest()..mergeFromBuffer(data, registry);
  factory UpdatePageRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdatePageRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdatePageRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: UpdatePageRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'name')
    ..aOS(3, _omitFieldNames ? '' : 'html')
    ..aE<$2.STATE>(4, _omitFieldNames ? '' : 'state',
        enumValues: $2.STATE.values)
    ..aOM<$0.Struct>(5, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdatePageRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdatePageRequest copyWith(void Function(UpdatePageRequest) updates) =>
      super.copyWith((message) => updates(message as UpdatePageRequest))
          as UpdatePageRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use UpdatePageRequest() / UpdatePageRequest.new instead')
  static UpdatePageRequest create() => UpdatePageRequest._();
  static $pb.GeneratedMessage $_createMessage() => UpdatePageRequest._();
  @$core.override
  UpdatePageRequest createEmptyInstance() => UpdatePageRequest._();
  @$core.pragma('dart2js:noInline')
  static UpdatePageRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<UpdatePageRequest>(
          UpdatePageRequest.$_createMessage);
  static UpdatePageRequest? _defaultInstance;

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
  $core.String get html => $_getSZ(2);
  @$pb.TagNumber(3)
  set html($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasHtml() => $_has(2);
  @$pb.TagNumber(3)
  void clearHtml() => $_clearField(3);

  @$pb.TagNumber(4)
  $2.STATE get state => $_getN(3);
  @$pb.TagNumber(4)
  set state($2.STATE value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasState() => $_has(3);
  @$pb.TagNumber(4)
  void clearState() => $_clearField(4);

  @$pb.TagNumber(5)
  $0.Struct get properties => $_getN(4);
  @$pb.TagNumber(5)
  set properties($0.Struct value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasProperties() => $_has(4);
  @$pb.TagNumber(5)
  void clearProperties() => $_clearField(5);
  @$pb.TagNumber(5)
  $0.Struct ensureProperties() => $_ensure(4);
}

class UpdatePageResponse extends $pb.GeneratedMessage {
  factory UpdatePageResponse({
    PageObject? data,
  }) {
    final result = UpdatePageResponse._();
    if (data != null) result.data = data;
    return result;
  }

  UpdatePageResponse._();

  factory UpdatePageResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdatePageResponse()..mergeFromBuffer(data, registry);
  factory UpdatePageResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      UpdatePageResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpdatePageResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: UpdatePageResponse.$_createMessage)
    ..aOM<PageObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: PageObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdatePageResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpdatePageResponse copyWith(void Function(UpdatePageResponse) updates) =>
      super.copyWith((message) => updates(message as UpdatePageResponse))
          as UpdatePageResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use UpdatePageResponse() / UpdatePageResponse.new instead')
  static UpdatePageResponse create() => UpdatePageResponse._();
  static $pb.GeneratedMessage $_createMessage() => UpdatePageResponse._();
  @$core.override
  UpdatePageResponse createEmptyInstance() => UpdatePageResponse._();
  @$core.pragma('dart2js:noInline')
  static UpdatePageResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpdatePageResponse>(
          UpdatePageResponse.$_createMessage);
  static UpdatePageResponse? _defaultInstance;

  @$pb.TagNumber(1)
  PageObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(PageObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  PageObject ensureData() => $_ensure(0);
}

class ListPageRequest extends $pb.GeneratedMessage {
  factory ListPageRequest({
    $core.String? partitionId,
    $2.PageCursor? cursor,
  }) {
    final result = ListPageRequest._();
    if (partitionId != null) result.partitionId = partitionId;
    if (cursor != null) result.cursor = cursor;
    return result;
  }

  ListPageRequest._();

  factory ListPageRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListPageRequest()..mergeFromBuffer(data, registry);
  factory ListPageRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListPageRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListPageRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListPageRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOM<$2.PageCursor>(2, _omitFieldNames ? '' : 'cursor',
        subBuilder: $2.PageCursor.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListPageRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListPageRequest copyWith(void Function(ListPageRequest) updates) =>
      super.copyWith((message) => updates(message as ListPageRequest))
          as ListPageRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use ListPageRequest() / ListPageRequest.new instead')
  static ListPageRequest create() => ListPageRequest._();
  static $pb.GeneratedMessage $_createMessage() => ListPageRequest._();
  @$core.override
  ListPageRequest createEmptyInstance() => ListPageRequest._();
  @$core.pragma('dart2js:noInline')
  static ListPageRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ListPageRequest>(
          ListPageRequest.$_createMessage);
  static ListPageRequest? _defaultInstance;

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

class ListPageResponse extends $pb.GeneratedMessage {
  factory ListPageResponse({
    $core.Iterable<PageObject>? data,
  }) {
    final result = ListPageResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  ListPageResponse._();

  factory ListPageResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListPageResponse()..mergeFromBuffer(data, registry);
  factory ListPageResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListPageResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListPageResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListPageResponse.$_createMessage)
    ..pPM<PageObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: PageObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListPageResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListPageResponse copyWith(void Function(ListPageResponse) updates) =>
      super.copyWith((message) => updates(message as ListPageResponse))
          as ListPageResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use ListPageResponse() / ListPageResponse.new instead')
  static ListPageResponse create() => ListPageResponse._();
  static $pb.GeneratedMessage $_createMessage() => ListPageResponse._();
  @$core.override
  ListPageResponse createEmptyInstance() => ListPageResponse._();
  @$core.pragma('dart2js:noInline')
  static ListPageResponse getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ListPageResponse>(
          ListPageResponse.$_createMessage);
  static ListPageResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<PageObject> get data => $_getList(0);
}

class RemovePageRequest extends $pb.GeneratedMessage {
  factory RemovePageRequest({
    $core.String? id,
  }) {
    final result = RemovePageRequest._();
    if (id != null) result.id = id;
    return result;
  }

  RemovePageRequest._();

  factory RemovePageRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemovePageRequest()..mergeFromBuffer(data, registry);
  factory RemovePageRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemovePageRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemovePageRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RemovePageRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemovePageRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemovePageRequest copyWith(void Function(RemovePageRequest) updates) =>
      super.copyWith((message) => updates(message as RemovePageRequest))
          as RemovePageRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use RemovePageRequest() / RemovePageRequest.new instead')
  static RemovePageRequest create() => RemovePageRequest._();
  static $pb.GeneratedMessage $_createMessage() => RemovePageRequest._();
  @$core.override
  RemovePageRequest createEmptyInstance() => RemovePageRequest._();
  @$core.pragma('dart2js:noInline')
  static RemovePageRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<RemovePageRequest>(
          RemovePageRequest.$_createMessage);
  static RemovePageRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class RemovePageResponse extends $pb.GeneratedMessage {
  factory RemovePageResponse({
    $core.bool? succeeded,
  }) {
    final result = RemovePageResponse._();
    if (succeeded != null) result.succeeded = succeeded;
    return result;
  }

  RemovePageResponse._();

  factory RemovePageResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemovePageResponse()..mergeFromBuffer(data, registry);
  factory RemovePageResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemovePageResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemovePageResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RemovePageResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'succeeded')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemovePageResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemovePageResponse copyWith(void Function(RemovePageResponse) updates) =>
      super.copyWith((message) => updates(message as RemovePageResponse))
          as RemovePageResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use RemovePageResponse() / RemovePageResponse.new instead')
  static RemovePageResponse create() => RemovePageResponse._();
  static $pb.GeneratedMessage $_createMessage() => RemovePageResponse._();
  @$core.override
  RemovePageResponse createEmptyInstance() => RemovePageResponse._();
  @$core.pragma('dart2js:noInline')
  static RemovePageResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemovePageResponse>(
          RemovePageResponse.$_createMessage);
  static RemovePageResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get succeeded => $_getBF(0);
  @$pb.TagNumber(1)
  set succeeded($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSucceeded() => $_has(0);
  @$pb.TagNumber(1)
  void clearSucceeded() => $_clearField(1);
}

class CreateAccessRequest extends $pb.GeneratedMessage {
  factory CreateAccessRequest({
    $core.String? partitionId,
    $core.String? profileId,
  }) {
    final result = CreateAccessRequest._();
    if (partitionId != null) result.partitionId = partitionId;
    if (profileId != null) result.profileId = profileId;
    return result;
  }

  CreateAccessRequest._();

  factory CreateAccessRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateAccessRequest()..mergeFromBuffer(data, registry);
  factory CreateAccessRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateAccessRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateAccessRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: CreateAccessRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOS(2, _omitFieldNames ? '' : 'profileId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateAccessRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateAccessRequest copyWith(void Function(CreateAccessRequest) updates) =>
      super.copyWith((message) => updates(message as CreateAccessRequest))
          as CreateAccessRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core
      .Deprecated('Use CreateAccessRequest() / CreateAccessRequest.new instead')
  static CreateAccessRequest create() => CreateAccessRequest._();
  static $pb.GeneratedMessage $_createMessage() => CreateAccessRequest._();
  @$core.override
  CreateAccessRequest createEmptyInstance() => CreateAccessRequest._();
  @$core.pragma('dart2js:noInline')
  static CreateAccessRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateAccessRequest>(
          CreateAccessRequest.$_createMessage);
  static CreateAccessRequest? _defaultInstance;

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
}

class CreateAccessResponse extends $pb.GeneratedMessage {
  factory CreateAccessResponse({
    AccessObject? data,
  }) {
    final result = CreateAccessResponse._();
    if (data != null) result.data = data;
    return result;
  }

  CreateAccessResponse._();

  factory CreateAccessResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateAccessResponse()..mergeFromBuffer(data, registry);
  factory CreateAccessResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateAccessResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateAccessResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: CreateAccessResponse.$_createMessage)
    ..aOM<AccessObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: AccessObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateAccessResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateAccessResponse copyWith(void Function(CreateAccessResponse) updates) =>
      super.copyWith((message) => updates(message as CreateAccessResponse))
          as CreateAccessResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreateAccessResponse() / CreateAccessResponse.new instead')
  static CreateAccessResponse create() => CreateAccessResponse._();
  static $pb.GeneratedMessage $_createMessage() => CreateAccessResponse._();
  @$core.override
  CreateAccessResponse createEmptyInstance() => CreateAccessResponse._();
  @$core.pragma('dart2js:noInline')
  static CreateAccessResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateAccessResponse>(
          CreateAccessResponse.$_createMessage);
  static CreateAccessResponse? _defaultInstance;

  @$pb.TagNumber(1)
  AccessObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(AccessObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  AccessObject ensureData() => $_ensure(0);
}

class GetAccessRequest extends $pb.GeneratedMessage {
  factory GetAccessRequest({
    $core.String? accessId,
    $core.String? partitionId,
    $core.String? profileId,
  }) {
    final result = GetAccessRequest._();
    if (accessId != null) result.accessId = accessId;
    if (partitionId != null) result.partitionId = partitionId;
    if (profileId != null) result.profileId = profileId;
    return result;
  }

  GetAccessRequest._();

  factory GetAccessRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetAccessRequest()..mergeFromBuffer(data, registry);
  factory GetAccessRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetAccessRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetAccessRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: GetAccessRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'accessId')
    ..aOS(2, _omitFieldNames ? '' : 'partitionId')
    ..aOS(4, _omitFieldNames ? '' : 'profileId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetAccessRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetAccessRequest copyWith(void Function(GetAccessRequest) updates) =>
      super.copyWith((message) => updates(message as GetAccessRequest))
          as GetAccessRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use GetAccessRequest() / GetAccessRequest.new instead')
  static GetAccessRequest create() => GetAccessRequest._();
  static $pb.GeneratedMessage $_createMessage() => GetAccessRequest._();
  @$core.override
  GetAccessRequest createEmptyInstance() => GetAccessRequest._();
  @$core.pragma('dart2js:noInline')
  static GetAccessRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetAccessRequest>(
          GetAccessRequest.$_createMessage);
  static GetAccessRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get accessId => $_getSZ(0);
  @$pb.TagNumber(1)
  set accessId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasAccessId() => $_has(0);
  @$pb.TagNumber(1)
  void clearAccessId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get partitionId => $_getSZ(1);
  @$pb.TagNumber(2)
  set partitionId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasPartitionId() => $_has(1);
  @$pb.TagNumber(2)
  void clearPartitionId() => $_clearField(2);

  @$pb.TagNumber(4)
  $core.String get profileId => $_getSZ(2);
  @$pb.TagNumber(4)
  set profileId($core.String value) => $_setString(2, value);
  @$pb.TagNumber(4)
  $core.bool hasProfileId() => $_has(2);
  @$pb.TagNumber(4)
  void clearProfileId() => $_clearField(4);
}

class GetAccessResponse extends $pb.GeneratedMessage {
  factory GetAccessResponse({
    AccessObject? data,
  }) {
    final result = GetAccessResponse._();
    if (data != null) result.data = data;
    return result;
  }

  GetAccessResponse._();

  factory GetAccessResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetAccessResponse()..mergeFromBuffer(data, registry);
  factory GetAccessResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetAccessResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetAccessResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: GetAccessResponse.$_createMessage)
    ..aOM<AccessObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: AccessObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetAccessResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetAccessResponse copyWith(void Function(GetAccessResponse) updates) =>
      super.copyWith((message) => updates(message as GetAccessResponse))
          as GetAccessResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use GetAccessResponse() / GetAccessResponse.new instead')
  static GetAccessResponse create() => GetAccessResponse._();
  static $pb.GeneratedMessage $_createMessage() => GetAccessResponse._();
  @$core.override
  GetAccessResponse createEmptyInstance() => GetAccessResponse._();
  @$core.pragma('dart2js:noInline')
  static GetAccessResponse getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetAccessResponse>(
          GetAccessResponse.$_createMessage);
  static GetAccessResponse? _defaultInstance;

  @$pb.TagNumber(1)
  AccessObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(AccessObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  AccessObject ensureData() => $_ensure(0);
}

enum ListAccessRequest_Scope { partitionId, profileId, notSet }

class ListAccessRequest extends $pb.GeneratedMessage {
  factory ListAccessRequest({
    $core.String? partitionId,
    $core.String? profileId,
    $2.PageCursor? cursor,
  }) {
    final result = ListAccessRequest._();
    if (partitionId != null) result.partitionId = partitionId;
    if (profileId != null) result.profileId = profileId;
    if (cursor != null) result.cursor = cursor;
    return result;
  }

  ListAccessRequest._();

  factory ListAccessRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListAccessRequest()..mergeFromBuffer(data, registry);
  factory ListAccessRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListAccessRequest()..mergeFromJson(json, registry);

  static const $core.Map<$core.int, ListAccessRequest_Scope>
      _ListAccessRequest_ScopeByTag = {
    1: ListAccessRequest_Scope.partitionId,
    2: ListAccessRequest_Scope.profileId,
    0: ListAccessRequest_Scope.notSet
  };
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListAccessRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListAccessRequest.$_createMessage)
    ..oo(0, [1, 2])
    ..aOS(1, _omitFieldNames ? '' : 'partitionId')
    ..aOS(2, _omitFieldNames ? '' : 'profileId')
    ..aOM<$2.PageCursor>(3, _omitFieldNames ? '' : 'cursor',
        subBuilder: $2.PageCursor.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListAccessRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListAccessRequest copyWith(void Function(ListAccessRequest) updates) =>
      super.copyWith((message) => updates(message as ListAccessRequest))
          as ListAccessRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use ListAccessRequest() / ListAccessRequest.new instead')
  static ListAccessRequest create() => ListAccessRequest._();
  static $pb.GeneratedMessage $_createMessage() => ListAccessRequest._();
  @$core.override
  ListAccessRequest createEmptyInstance() => ListAccessRequest._();
  @$core.pragma('dart2js:noInline')
  static ListAccessRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ListAccessRequest>(
          ListAccessRequest.$_createMessage);
  static ListAccessRequest? _defaultInstance;

  @$pb.TagNumber(1)
  @$pb.TagNumber(2)
  ListAccessRequest_Scope whichScope() =>
      _ListAccessRequest_ScopeByTag[$_whichOneof(0)]!;
  @$pb.TagNumber(1)
  @$pb.TagNumber(2)
  void clearScope() => $_clearField($_whichOneof(0));

  /// List all access grants for a partition
  @$pb.TagNumber(1)
  $core.String get partitionId => $_getSZ(0);
  @$pb.TagNumber(1)
  set partitionId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasPartitionId() => $_has(0);
  @$pb.TagNumber(1)
  void clearPartitionId() => $_clearField(1);

  /// List all access grants for a profile
  @$pb.TagNumber(2)
  $core.String get profileId => $_getSZ(1);
  @$pb.TagNumber(2)
  set profileId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasProfileId() => $_has(1);
  @$pb.TagNumber(2)
  void clearProfileId() => $_clearField(2);

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

class ListAccessResponse extends $pb.GeneratedMessage {
  factory ListAccessResponse({
    $core.Iterable<AccessObject>? data,
  }) {
    final result = ListAccessResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  ListAccessResponse._();

  factory ListAccessResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListAccessResponse()..mergeFromBuffer(data, registry);
  factory ListAccessResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListAccessResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListAccessResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListAccessResponse.$_createMessage)
    ..pPM<AccessObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: AccessObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListAccessResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListAccessResponse copyWith(void Function(ListAccessResponse) updates) =>
      super.copyWith((message) => updates(message as ListAccessResponse))
          as ListAccessResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use ListAccessResponse() / ListAccessResponse.new instead')
  static ListAccessResponse create() => ListAccessResponse._();
  static $pb.GeneratedMessage $_createMessage() => ListAccessResponse._();
  @$core.override
  ListAccessResponse createEmptyInstance() => ListAccessResponse._();
  @$core.pragma('dart2js:noInline')
  static ListAccessResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListAccessResponse>(
          ListAccessResponse.$_createMessage);
  static ListAccessResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<AccessObject> get data => $_getList(0);
}

class RemoveAccessRequest extends $pb.GeneratedMessage {
  factory RemoveAccessRequest({
    $core.String? id,
  }) {
    final result = RemoveAccessRequest._();
    if (id != null) result.id = id;
    return result;
  }

  RemoveAccessRequest._();

  factory RemoveAccessRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveAccessRequest()..mergeFromBuffer(data, registry);
  factory RemoveAccessRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveAccessRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveAccessRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RemoveAccessRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveAccessRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveAccessRequest copyWith(void Function(RemoveAccessRequest) updates) =>
      super.copyWith((message) => updates(message as RemoveAccessRequest))
          as RemoveAccessRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core
      .Deprecated('Use RemoveAccessRequest() / RemoveAccessRequest.new instead')
  static RemoveAccessRequest create() => RemoveAccessRequest._();
  static $pb.GeneratedMessage $_createMessage() => RemoveAccessRequest._();
  @$core.override
  RemoveAccessRequest createEmptyInstance() => RemoveAccessRequest._();
  @$core.pragma('dart2js:noInline')
  static RemoveAccessRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveAccessRequest>(
          RemoveAccessRequest.$_createMessage);
  static RemoveAccessRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class RemoveAccessResponse extends $pb.GeneratedMessage {
  factory RemoveAccessResponse({
    $core.bool? succeeded,
  }) {
    final result = RemoveAccessResponse._();
    if (succeeded != null) result.succeeded = succeeded;
    return result;
  }

  RemoveAccessResponse._();

  factory RemoveAccessResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveAccessResponse()..mergeFromBuffer(data, registry);
  factory RemoveAccessResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveAccessResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveAccessResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RemoveAccessResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'succeeded')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveAccessResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveAccessResponse copyWith(void Function(RemoveAccessResponse) updates) =>
      super.copyWith((message) => updates(message as RemoveAccessResponse))
          as RemoveAccessResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RemoveAccessResponse() / RemoveAccessResponse.new instead')
  static RemoveAccessResponse create() => RemoveAccessResponse._();
  static $pb.GeneratedMessage $_createMessage() => RemoveAccessResponse._();
  @$core.override
  RemoveAccessResponse createEmptyInstance() => RemoveAccessResponse._();
  @$core.pragma('dart2js:noInline')
  static RemoveAccessResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveAccessResponse>(
          RemoveAccessResponse.$_createMessage);
  static RemoveAccessResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get succeeded => $_getBF(0);
  @$pb.TagNumber(1)
  set succeeded($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSucceeded() => $_has(0);
  @$pb.TagNumber(1)
  void clearSucceeded() => $_clearField(1);
}

class CreateAccessRoleRequest extends $pb.GeneratedMessage {
  factory CreateAccessRoleRequest({
    $core.String? accessId,
    $core.String? partitionRoleId,
  }) {
    final result = CreateAccessRoleRequest._();
    if (accessId != null) result.accessId = accessId;
    if (partitionRoleId != null) result.partitionRoleId = partitionRoleId;
    return result;
  }

  CreateAccessRoleRequest._();

  factory CreateAccessRoleRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateAccessRoleRequest()..mergeFromBuffer(data, registry);
  factory CreateAccessRoleRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateAccessRoleRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateAccessRoleRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: CreateAccessRoleRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'accessId')
    ..aOS(2, _omitFieldNames ? '' : 'partitionRoleId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateAccessRoleRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateAccessRoleRequest copyWith(
          void Function(CreateAccessRoleRequest) updates) =>
      super.copyWith((message) => updates(message as CreateAccessRoleRequest))
          as CreateAccessRoleRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreateAccessRoleRequest() / CreateAccessRoleRequest.new instead')
  static CreateAccessRoleRequest create() => CreateAccessRoleRequest._();
  static $pb.GeneratedMessage $_createMessage() => CreateAccessRoleRequest._();
  @$core.override
  CreateAccessRoleRequest createEmptyInstance() => CreateAccessRoleRequest._();
  @$core.pragma('dart2js:noInline')
  static CreateAccessRoleRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateAccessRoleRequest>(
          CreateAccessRoleRequest.$_createMessage);
  static CreateAccessRoleRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get accessId => $_getSZ(0);
  @$pb.TagNumber(1)
  set accessId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasAccessId() => $_has(0);
  @$pb.TagNumber(1)
  void clearAccessId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get partitionRoleId => $_getSZ(1);
  @$pb.TagNumber(2)
  set partitionRoleId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasPartitionRoleId() => $_has(1);
  @$pb.TagNumber(2)
  void clearPartitionRoleId() => $_clearField(2);
}

class CreateAccessRoleResponse extends $pb.GeneratedMessage {
  factory CreateAccessRoleResponse({
    AccessRoleObject? data,
  }) {
    final result = CreateAccessRoleResponse._();
    if (data != null) result.data = data;
    return result;
  }

  CreateAccessRoleResponse._();

  factory CreateAccessRoleResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateAccessRoleResponse()..mergeFromBuffer(data, registry);
  factory CreateAccessRoleResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateAccessRoleResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateAccessRoleResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: CreateAccessRoleResponse.$_createMessage)
    ..aOM<AccessRoleObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: AccessRoleObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateAccessRoleResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateAccessRoleResponse copyWith(
          void Function(CreateAccessRoleResponse) updates) =>
      super.copyWith((message) => updates(message as CreateAccessRoleResponse))
          as CreateAccessRoleResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreateAccessRoleResponse() / CreateAccessRoleResponse.new instead')
  static CreateAccessRoleResponse create() => CreateAccessRoleResponse._();
  static $pb.GeneratedMessage $_createMessage() => CreateAccessRoleResponse._();
  @$core.override
  CreateAccessRoleResponse createEmptyInstance() =>
      CreateAccessRoleResponse._();
  @$core.pragma('dart2js:noInline')
  static CreateAccessRoleResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateAccessRoleResponse>(
          CreateAccessRoleResponse.$_createMessage);
  static CreateAccessRoleResponse? _defaultInstance;

  @$pb.TagNumber(1)
  AccessRoleObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(AccessRoleObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  AccessRoleObject ensureData() => $_ensure(0);
}

class RemoveAccessRoleRequest extends $pb.GeneratedMessage {
  factory RemoveAccessRoleRequest({
    $core.String? id,
  }) {
    final result = RemoveAccessRoleRequest._();
    if (id != null) result.id = id;
    return result;
  }

  RemoveAccessRoleRequest._();

  factory RemoveAccessRoleRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveAccessRoleRequest()..mergeFromBuffer(data, registry);
  factory RemoveAccessRoleRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveAccessRoleRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveAccessRoleRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RemoveAccessRoleRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveAccessRoleRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveAccessRoleRequest copyWith(
          void Function(RemoveAccessRoleRequest) updates) =>
      super.copyWith((message) => updates(message as RemoveAccessRoleRequest))
          as RemoveAccessRoleRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RemoveAccessRoleRequest() / RemoveAccessRoleRequest.new instead')
  static RemoveAccessRoleRequest create() => RemoveAccessRoleRequest._();
  static $pb.GeneratedMessage $_createMessage() => RemoveAccessRoleRequest._();
  @$core.override
  RemoveAccessRoleRequest createEmptyInstance() => RemoveAccessRoleRequest._();
  @$core.pragma('dart2js:noInline')
  static RemoveAccessRoleRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveAccessRoleRequest>(
          RemoveAccessRoleRequest.$_createMessage);
  static RemoveAccessRoleRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class RemoveAccessRoleResponse extends $pb.GeneratedMessage {
  factory RemoveAccessRoleResponse({
    $core.bool? succeeded,
  }) {
    final result = RemoveAccessRoleResponse._();
    if (succeeded != null) result.succeeded = succeeded;
    return result;
  }

  RemoveAccessRoleResponse._();

  factory RemoveAccessRoleResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveAccessRoleResponse()..mergeFromBuffer(data, registry);
  factory RemoveAccessRoleResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RemoveAccessRoleResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveAccessRoleResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RemoveAccessRoleResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'succeeded')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveAccessRoleResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveAccessRoleResponse copyWith(
          void Function(RemoveAccessRoleResponse) updates) =>
      super.copyWith((message) => updates(message as RemoveAccessRoleResponse))
          as RemoveAccessRoleResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RemoveAccessRoleResponse() / RemoveAccessRoleResponse.new instead')
  static RemoveAccessRoleResponse create() => RemoveAccessRoleResponse._();
  static $pb.GeneratedMessage $_createMessage() => RemoveAccessRoleResponse._();
  @$core.override
  RemoveAccessRoleResponse createEmptyInstance() =>
      RemoveAccessRoleResponse._();
  @$core.pragma('dart2js:noInline')
  static RemoveAccessRoleResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveAccessRoleResponse>(
          RemoveAccessRoleResponse.$_createMessage);
  static RemoveAccessRoleResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get succeeded => $_getBF(0);
  @$pb.TagNumber(1)
  set succeeded($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSucceeded() => $_has(0);
  @$pb.TagNumber(1)
  void clearSucceeded() => $_clearField(1);
}

class ListAccessRoleRequest extends $pb.GeneratedMessage {
  factory ListAccessRoleRequest({
    $core.String? accessId,
    $2.PageCursor? cursor,
  }) {
    final result = ListAccessRoleRequest._();
    if (accessId != null) result.accessId = accessId;
    if (cursor != null) result.cursor = cursor;
    return result;
  }

  ListAccessRoleRequest._();

  factory ListAccessRoleRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListAccessRoleRequest()..mergeFromBuffer(data, registry);
  factory ListAccessRoleRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListAccessRoleRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListAccessRoleRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListAccessRoleRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'accessId')
    ..aOM<$2.PageCursor>(2, _omitFieldNames ? '' : 'cursor',
        subBuilder: $2.PageCursor.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListAccessRoleRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListAccessRoleRequest copyWith(
          void Function(ListAccessRoleRequest) updates) =>
      super.copyWith((message) => updates(message as ListAccessRoleRequest))
          as ListAccessRoleRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListAccessRoleRequest() / ListAccessRoleRequest.new instead')
  static ListAccessRoleRequest create() => ListAccessRoleRequest._();
  static $pb.GeneratedMessage $_createMessage() => ListAccessRoleRequest._();
  @$core.override
  ListAccessRoleRequest createEmptyInstance() => ListAccessRoleRequest._();
  @$core.pragma('dart2js:noInline')
  static ListAccessRoleRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListAccessRoleRequest>(
          ListAccessRoleRequest.$_createMessage);
  static ListAccessRoleRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get accessId => $_getSZ(0);
  @$pb.TagNumber(1)
  set accessId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasAccessId() => $_has(0);
  @$pb.TagNumber(1)
  void clearAccessId() => $_clearField(1);

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

class ListAccessRoleResponse extends $pb.GeneratedMessage {
  factory ListAccessRoleResponse({
    $core.Iterable<AccessRoleObject>? data,
  }) {
    final result = ListAccessRoleResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  ListAccessRoleResponse._();

  factory ListAccessRoleResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListAccessRoleResponse()..mergeFromBuffer(data, registry);
  factory ListAccessRoleResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListAccessRoleResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListAccessRoleResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListAccessRoleResponse.$_createMessage)
    ..pPM<AccessRoleObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: AccessRoleObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListAccessRoleResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListAccessRoleResponse copyWith(
          void Function(ListAccessRoleResponse) updates) =>
      super.copyWith((message) => updates(message as ListAccessRoleResponse))
          as ListAccessRoleResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListAccessRoleResponse() / ListAccessRoleResponse.new instead')
  static ListAccessRoleResponse create() => ListAccessRoleResponse._();
  static $pb.GeneratedMessage $_createMessage() => ListAccessRoleResponse._();
  @$core.override
  ListAccessRoleResponse createEmptyInstance() => ListAccessRoleResponse._();
  @$core.pragma('dart2js:noInline')
  static ListAccessRoleResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListAccessRoleResponse>(
          ListAccessRoleResponse.$_createMessage);
  static ListAccessRoleResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<AccessRoleObject> get data => $_getList(0);
}

/// ServiceNamespaceObject represents a registered service's permission namespace.
class ServiceNamespaceObject extends $pb.GeneratedMessage {
  factory ServiceNamespaceObject({
    $core.String? namespace,
    $core.Iterable<$core.String>? permissions,
    $core.Iterable<$core.MapEntry<$core.String, RolePermissionList>>?
        roleBindings,
    $1.Timestamp? registeredAt,
  }) {
    final result = ServiceNamespaceObject._();
    if (namespace != null) result.namespace = namespace;
    if (permissions != null) result.permissions.addAll(permissions);
    if (roleBindings != null) result.roleBindings.addEntries(roleBindings);
    if (registeredAt != null) result.registeredAt = registeredAt;
    return result;
  }

  ServiceNamespaceObject._();

  factory ServiceNamespaceObject.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ServiceNamespaceObject()..mergeFromBuffer(data, registry);
  factory ServiceNamespaceObject.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ServiceNamespaceObject()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ServiceNamespaceObject',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ServiceNamespaceObject.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'namespace')
    ..pPS(2, _omitFieldNames ? '' : 'permissions')
    ..m<$core.String, RolePermissionList>(
        3, _omitFieldNames ? '' : 'roleBindings',
        entryClassName: 'ServiceNamespaceObject.RoleBindingsEntry',
        keyFieldType: $pb.PbFieldType.OS,
        valueFieldType: $pb.PbFieldType.OM,
        valueCreator: RolePermissionList.$_createMessage,
        valueDefaultOrMaker: RolePermissionList.getDefault,
        packageName: const $pb.PackageName('tenancy.v1'))
    ..aOM<$1.Timestamp>(4, _omitFieldNames ? '' : 'registeredAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ServiceNamespaceObject clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ServiceNamespaceObject copyWith(
          void Function(ServiceNamespaceObject) updates) =>
      super.copyWith((message) => updates(message as ServiceNamespaceObject))
          as ServiceNamespaceObject;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ServiceNamespaceObject() / ServiceNamespaceObject.new instead')
  static ServiceNamespaceObject create() => ServiceNamespaceObject._();
  static $pb.GeneratedMessage $_createMessage() => ServiceNamespaceObject._();
  @$core.override
  ServiceNamespaceObject createEmptyInstance() => ServiceNamespaceObject._();
  @$core.pragma('dart2js:noInline')
  static ServiceNamespaceObject getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ServiceNamespaceObject>(
          ServiceNamespaceObject.$_createMessage);
  static ServiceNamespaceObject? _defaultInstance;

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
  $pb.PbMap<$core.String, RolePermissionList> get roleBindings => $_getMap(2);

  @$pb.TagNumber(4)
  $1.Timestamp get registeredAt => $_getN(3);
  @$pb.TagNumber(4)
  set registeredAt($1.Timestamp value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasRegisteredAt() => $_has(3);
  @$pb.TagNumber(4)
  void clearRegisteredAt() => $_clearField(4);
  @$pb.TagNumber(4)
  $1.Timestamp ensureRegisteredAt() => $_ensure(3);
}

/// RolePermissionList holds the permissions granted to a role.
class RolePermissionList extends $pb.GeneratedMessage {
  factory RolePermissionList({
    $core.Iterable<$core.String>? permissions,
  }) {
    final result = RolePermissionList._();
    if (permissions != null) result.permissions.addAll(permissions);
    return result;
  }

  RolePermissionList._();

  factory RolePermissionList.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RolePermissionList()..mergeFromBuffer(data, registry);
  factory RolePermissionList.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RolePermissionList()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RolePermissionList',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RolePermissionList.$_createMessage)
    ..pPS(1, _omitFieldNames ? '' : 'permissions')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RolePermissionList clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RolePermissionList copyWith(void Function(RolePermissionList) updates) =>
      super.copyWith((message) => updates(message as RolePermissionList))
          as RolePermissionList;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use RolePermissionList() / RolePermissionList.new instead')
  static RolePermissionList create() => RolePermissionList._();
  static $pb.GeneratedMessage $_createMessage() => RolePermissionList._();
  @$core.override
  RolePermissionList createEmptyInstance() => RolePermissionList._();
  @$core.pragma('dart2js:noInline')
  static RolePermissionList getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RolePermissionList>(
          RolePermissionList.$_createMessage);
  static RolePermissionList? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<$core.String> get permissions => $_getList(0);
}

class ListServiceNamespacesRequest extends $pb.GeneratedMessage {
  factory ListServiceNamespacesRequest() => ListServiceNamespacesRequest._();

  ListServiceNamespacesRequest._();

  factory ListServiceNamespacesRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListServiceNamespacesRequest()..mergeFromBuffer(data, registry);
  factory ListServiceNamespacesRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListServiceNamespacesRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListServiceNamespacesRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListServiceNamespacesRequest.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListServiceNamespacesRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListServiceNamespacesRequest copyWith(
          void Function(ListServiceNamespacesRequest) updates) =>
      super.copyWith(
              (message) => updates(message as ListServiceNamespacesRequest))
          as ListServiceNamespacesRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListServiceNamespacesRequest() / ListServiceNamespacesRequest.new instead')
  static ListServiceNamespacesRequest create() =>
      ListServiceNamespacesRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      ListServiceNamespacesRequest._();
  @$core.override
  ListServiceNamespacesRequest createEmptyInstance() =>
      ListServiceNamespacesRequest._();
  @$core.pragma('dart2js:noInline')
  static ListServiceNamespacesRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListServiceNamespacesRequest>(
          ListServiceNamespacesRequest.$_createMessage);
  static ListServiceNamespacesRequest? _defaultInstance;
}

class ListServiceNamespacesResponse extends $pb.GeneratedMessage {
  factory ListServiceNamespacesResponse({
    $core.Iterable<ServiceNamespaceObject>? data,
  }) {
    final result = ListServiceNamespacesResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  ListServiceNamespacesResponse._();

  factory ListServiceNamespacesResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListServiceNamespacesResponse()..mergeFromBuffer(data, registry);
  factory ListServiceNamespacesResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListServiceNamespacesResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListServiceNamespacesResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: ListServiceNamespacesResponse.$_createMessage)
    ..pPM<ServiceNamespaceObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: ServiceNamespaceObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListServiceNamespacesResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListServiceNamespacesResponse copyWith(
          void Function(ListServiceNamespacesResponse) updates) =>
      super.copyWith(
              (message) => updates(message as ListServiceNamespacesResponse))
          as ListServiceNamespacesResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListServiceNamespacesResponse() / ListServiceNamespacesResponse.new instead')
  static ListServiceNamespacesResponse create() =>
      ListServiceNamespacesResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      ListServiceNamespacesResponse._();
  @$core.override
  ListServiceNamespacesResponse createEmptyInstance() =>
      ListServiceNamespacesResponse._();
  @$core.pragma('dart2js:noInline')
  static ListServiceNamespacesResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListServiceNamespacesResponse>(
          ListServiceNamespacesResponse.$_createMessage);
  static ListServiceNamespacesResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<ServiceNamespaceObject> get data => $_getList(0);
}

class GrantPermissionRequest extends $pb.GeneratedMessage {
  factory GrantPermissionRequest({
    $core.String? namespace,
    $core.String? permission,
    $core.String? profileId,
  }) {
    final result = GrantPermissionRequest._();
    if (namespace != null) result.namespace = namespace;
    if (permission != null) result.permission = permission;
    if (profileId != null) result.profileId = profileId;
    return result;
  }

  GrantPermissionRequest._();

  factory GrantPermissionRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GrantPermissionRequest()..mergeFromBuffer(data, registry);
  factory GrantPermissionRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GrantPermissionRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GrantPermissionRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: GrantPermissionRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'namespace')
    ..aOS(2, _omitFieldNames ? '' : 'permission')
    ..aOS(3, _omitFieldNames ? '' : 'profileId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GrantPermissionRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GrantPermissionRequest copyWith(
          void Function(GrantPermissionRequest) updates) =>
      super.copyWith((message) => updates(message as GrantPermissionRequest))
          as GrantPermissionRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GrantPermissionRequest() / GrantPermissionRequest.new instead')
  static GrantPermissionRequest create() => GrantPermissionRequest._();
  static $pb.GeneratedMessage $_createMessage() => GrantPermissionRequest._();
  @$core.override
  GrantPermissionRequest createEmptyInstance() => GrantPermissionRequest._();
  @$core.pragma('dart2js:noInline')
  static GrantPermissionRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GrantPermissionRequest>(
          GrantPermissionRequest.$_createMessage);
  static GrantPermissionRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get namespace => $_getSZ(0);
  @$pb.TagNumber(1)
  set namespace($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasNamespace() => $_has(0);
  @$pb.TagNumber(1)
  void clearNamespace() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get permission => $_getSZ(1);
  @$pb.TagNumber(2)
  set permission($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasPermission() => $_has(1);
  @$pb.TagNumber(2)
  void clearPermission() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get profileId => $_getSZ(2);
  @$pb.TagNumber(3)
  set profileId($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasProfileId() => $_has(2);
  @$pb.TagNumber(3)
  void clearProfileId() => $_clearField(3);
}

class GrantPermissionResponse extends $pb.GeneratedMessage {
  factory GrantPermissionResponse({
    $core.bool? succeeded,
  }) {
    final result = GrantPermissionResponse._();
    if (succeeded != null) result.succeeded = succeeded;
    return result;
  }

  GrantPermissionResponse._();

  factory GrantPermissionResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GrantPermissionResponse()..mergeFromBuffer(data, registry);
  factory GrantPermissionResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GrantPermissionResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GrantPermissionResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: GrantPermissionResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'succeeded')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GrantPermissionResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GrantPermissionResponse copyWith(
          void Function(GrantPermissionResponse) updates) =>
      super.copyWith((message) => updates(message as GrantPermissionResponse))
          as GrantPermissionResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GrantPermissionResponse() / GrantPermissionResponse.new instead')
  static GrantPermissionResponse create() => GrantPermissionResponse._();
  static $pb.GeneratedMessage $_createMessage() => GrantPermissionResponse._();
  @$core.override
  GrantPermissionResponse createEmptyInstance() => GrantPermissionResponse._();
  @$core.pragma('dart2js:noInline')
  static GrantPermissionResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GrantPermissionResponse>(
          GrantPermissionResponse.$_createMessage);
  static GrantPermissionResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get succeeded => $_getBF(0);
  @$pb.TagNumber(1)
  set succeeded($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSucceeded() => $_has(0);
  @$pb.TagNumber(1)
  void clearSucceeded() => $_clearField(1);
}

class RevokePermissionRequest extends $pb.GeneratedMessage {
  factory RevokePermissionRequest({
    $core.String? namespace,
    $core.String? permission,
    $core.String? profileId,
  }) {
    final result = RevokePermissionRequest._();
    if (namespace != null) result.namespace = namespace;
    if (permission != null) result.permission = permission;
    if (profileId != null) result.profileId = profileId;
    return result;
  }

  RevokePermissionRequest._();

  factory RevokePermissionRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RevokePermissionRequest()..mergeFromBuffer(data, registry);
  factory RevokePermissionRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RevokePermissionRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RevokePermissionRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RevokePermissionRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'namespace')
    ..aOS(2, _omitFieldNames ? '' : 'permission')
    ..aOS(3, _omitFieldNames ? '' : 'profileId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RevokePermissionRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RevokePermissionRequest copyWith(
          void Function(RevokePermissionRequest) updates) =>
      super.copyWith((message) => updates(message as RevokePermissionRequest))
          as RevokePermissionRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RevokePermissionRequest() / RevokePermissionRequest.new instead')
  static RevokePermissionRequest create() => RevokePermissionRequest._();
  static $pb.GeneratedMessage $_createMessage() => RevokePermissionRequest._();
  @$core.override
  RevokePermissionRequest createEmptyInstance() => RevokePermissionRequest._();
  @$core.pragma('dart2js:noInline')
  static RevokePermissionRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RevokePermissionRequest>(
          RevokePermissionRequest.$_createMessage);
  static RevokePermissionRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get namespace => $_getSZ(0);
  @$pb.TagNumber(1)
  set namespace($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasNamespace() => $_has(0);
  @$pb.TagNumber(1)
  void clearNamespace() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get permission => $_getSZ(1);
  @$pb.TagNumber(2)
  set permission($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasPermission() => $_has(1);
  @$pb.TagNumber(2)
  void clearPermission() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get profileId => $_getSZ(2);
  @$pb.TagNumber(3)
  set profileId($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasProfileId() => $_has(2);
  @$pb.TagNumber(3)
  void clearProfileId() => $_clearField(3);
}

class RevokePermissionResponse extends $pb.GeneratedMessage {
  factory RevokePermissionResponse({
    $core.bool? succeeded,
  }) {
    final result = RevokePermissionResponse._();
    if (succeeded != null) result.succeeded = succeeded;
    return result;
  }

  RevokePermissionResponse._();

  factory RevokePermissionResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RevokePermissionResponse()..mergeFromBuffer(data, registry);
  factory RevokePermissionResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RevokePermissionResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RevokePermissionResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'tenancy.v1'),
      createEmptyInstance: RevokePermissionResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'succeeded')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RevokePermissionResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RevokePermissionResponse copyWith(
          void Function(RevokePermissionResponse) updates) =>
      super.copyWith((message) => updates(message as RevokePermissionResponse))
          as RevokePermissionResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RevokePermissionResponse() / RevokePermissionResponse.new instead')
  static RevokePermissionResponse create() => RevokePermissionResponse._();
  static $pb.GeneratedMessage $_createMessage() => RevokePermissionResponse._();
  @$core.override
  RevokePermissionResponse createEmptyInstance() =>
      RevokePermissionResponse._();
  @$core.pragma('dart2js:noInline')
  static RevokePermissionResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RevokePermissionResponse>(
          RevokePermissionResponse.$_createMessage);
  static RevokePermissionResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get succeeded => $_getBF(0);
  @$pb.TagNumber(1)
  set succeeded($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSucceeded() => $_has(0);
  @$pb.TagNumber(1)
  void clearSucceeded() => $_clearField(1);
}

/// TenancyService provides multi-tenancy and data isolation.
/// All RPCs require authentication via Bearer token.
class TenancyServiceApi {
  final $pb.RpcClient _client;

  TenancyServiceApi(this._client);

  /// GetTenant retrieves a tenant by ID.
  $async.Future<GetTenantResponse> getTenant(
          $pb.ClientContext? ctx, GetTenantRequest request) =>
      _client.invoke<GetTenantResponse>(
          ctx, 'TenancyService', 'GetTenant', request, GetTenantResponse());

  /// ListTenant retrieves all tenants matching criteria.
  $async.Future<ListTenantResponse> listTenant(
          $pb.ClientContext? ctx, ListTenantRequest request) =>
      _client.invoke<ListTenantResponse>(
          ctx, 'TenancyService', 'ListTenant', request, ListTenantResponse());

  /// CreateTenant creates a new tenant.
  $async.Future<CreateTenantResponse> createTenant(
          $pb.ClientContext? ctx, CreateTenantRequest request) =>
      _client.invoke<CreateTenantResponse>(ctx, 'TenancyService',
          'CreateTenant', request, CreateTenantResponse());

  /// UpdateTenant updates an existing tenant.
  $async.Future<UpdateTenantResponse> updateTenant(
          $pb.ClientContext? ctx, UpdateTenantRequest request) =>
      _client.invoke<UpdateTenantResponse>(ctx, 'TenancyService',
          'UpdateTenant', request, UpdateTenantResponse());

  /// RemoveTenant soft-deletes a tenant and all its partitions.
  $async.Future<RemoveTenantResponse> removeTenant(
          $pb.ClientContext? ctx, RemoveTenantRequest request) =>
      _client.invoke<RemoveTenantResponse>(ctx, 'TenancyService',
          'RemoveTenant', request, RemoveTenantResponse());

  /// ListPartition retrieves all partitions matching criteria.
  $async.Future<ListPartitionResponse> listPartition(
          $pb.ClientContext? ctx, ListPartitionRequest request) =>
      _client.invoke<ListPartitionResponse>(ctx, 'TenancyService',
          'ListPartition', request, ListPartitionResponse());

  /// CreatePartition creates a new partition.
  $async.Future<CreatePartitionResponse> createPartition(
          $pb.ClientContext? ctx, CreatePartitionRequest request) =>
      _client.invoke<CreatePartitionResponse>(ctx, 'TenancyService',
          'CreatePartition', request, CreatePartitionResponse());

  /// GetPartition retrieves a partition by ID or domain.
  $async.Future<GetPartitionResponse> getPartition(
          $pb.ClientContext? ctx, GetPartitionRequest request) =>
      _client.invoke<GetPartitionResponse>(ctx, 'TenancyService',
          'GetPartition', request, GetPartitionResponse());

  /// GetPartitionParents retrieves the parent hierarchy.
  $async.Future<GetPartitionParentsResponse> getPartitionParents(
          $pb.ClientContext? ctx, GetPartitionParentsRequest request) =>
      _client.invoke<GetPartitionParentsResponse>(ctx, 'TenancyService',
          'GetPartitionParents', request, GetPartitionParentsResponse());

  /// RemovePartition soft-deletes a partition.
  $async.Future<RemovePartitionResponse> removePartition(
          $pb.ClientContext? ctx, RemovePartitionRequest request) =>
      _client.invoke<RemovePartitionResponse>(ctx, 'TenancyService',
          'RemovePartition', request, RemovePartitionResponse());

  /// UpdatePartition updates an existing partition.
  $async.Future<UpdatePartitionResponse> updatePartition(
          $pb.ClientContext? ctx, UpdatePartitionRequest request) =>
      _client.invoke<UpdatePartitionResponse>(ctx, 'TenancyService',
          'UpdatePartition', request, UpdatePartitionResponse());

  /// CreatePartitionRole creates a role within a partition.
  $async.Future<CreatePartitionRoleResponse> createPartitionRole(
          $pb.ClientContext? ctx, CreatePartitionRoleRequest request) =>
      _client.invoke<CreatePartitionRoleResponse>(ctx, 'TenancyService',
          'CreatePartitionRole', request, CreatePartitionRoleResponse());

  /// ListPartitionRole retrieves all roles for a partition.
  $async.Future<ListPartitionRoleResponse> listPartitionRole(
          $pb.ClientContext? ctx, ListPartitionRoleRequest request) =>
      _client.invoke<ListPartitionRoleResponse>(ctx, 'TenancyService',
          'ListPartitionRole', request, ListPartitionRoleResponse());

  /// UpdatePartitionRole updates an existing partition role.
  $async.Future<UpdatePartitionRoleResponse> updatePartitionRole(
          $pb.ClientContext? ctx, UpdatePartitionRoleRequest request) =>
      _client.invoke<UpdatePartitionRoleResponse>(ctx, 'TenancyService',
          'UpdatePartitionRole', request, UpdatePartitionRoleResponse());

  /// RemovePartitionRole deletes a partition role.
  $async.Future<RemovePartitionRoleResponse> removePartitionRole(
          $pb.ClientContext? ctx, RemovePartitionRoleRequest request) =>
      _client.invoke<RemovePartitionRoleResponse>(ctx, 'TenancyService',
          'RemovePartitionRole', request, RemovePartitionRoleResponse());

  /// CreatePage creates a custom UI page for a partition.
  $async.Future<CreatePageResponse> createPage(
          $pb.ClientContext? ctx, CreatePageRequest request) =>
      _client.invoke<CreatePageResponse>(
          ctx, 'TenancyService', 'CreatePage', request, CreatePageResponse());

  /// ListPage retrieves all custom pages for a partition.
  $async.Future<ListPageResponse> listPage(
          $pb.ClientContext? ctx, ListPageRequest request) =>
      _client.invoke<ListPageResponse>(
          ctx, 'TenancyService', 'ListPage', request, ListPageResponse());

  /// GetPage retrieves a custom page.
  $async.Future<GetPageResponse> getPage(
          $pb.ClientContext? ctx, GetPageRequest request) =>
      _client.invoke<GetPageResponse>(
          ctx, 'TenancyService', 'GetPage', request, GetPageResponse());

  /// UpdatePage updates an existing custom page.
  $async.Future<UpdatePageResponse> updatePage(
          $pb.ClientContext? ctx, UpdatePageRequest request) =>
      _client.invoke<UpdatePageResponse>(
          ctx, 'TenancyService', 'UpdatePage', request, UpdatePageResponse());

  /// RemovePage deletes a custom page.
  $async.Future<RemovePageResponse> removePage(
          $pb.ClientContext? ctx, RemovePageRequest request) =>
      _client.invoke<RemovePageResponse>(
          ctx, 'TenancyService', 'RemovePage', request, RemovePageResponse());

  /// CreateAccess grants a profile access to a partition.
  $async.Future<CreateAccessResponse> createAccess(
          $pb.ClientContext? ctx, CreateAccessRequest request) =>
      _client.invoke<CreateAccessResponse>(ctx, 'TenancyService',
          'CreateAccess', request, CreateAccessResponse());

  /// GetAccess retrieves an access grant.
  $async.Future<GetAccessResponse> getAccess(
          $pb.ClientContext? ctx, GetAccessRequest request) =>
      _client.invoke<GetAccessResponse>(
          ctx, 'TenancyService', 'GetAccess', request, GetAccessResponse());

  /// ListAccess retrieves all access grants for a partition or profile.
  $async.Future<ListAccessResponse> listAccess(
          $pb.ClientContext? ctx, ListAccessRequest request) =>
      _client.invoke<ListAccessResponse>(
          ctx, 'TenancyService', 'ListAccess', request, ListAccessResponse());

  /// RemoveAccess revokes a profile's access to a partition.
  $async.Future<RemoveAccessResponse> removeAccess(
          $pb.ClientContext? ctx, RemoveAccessRequest request) =>
      _client.invoke<RemoveAccessResponse>(ctx, 'TenancyService',
          'RemoveAccess', request, RemoveAccessResponse());

  /// CreateAccessRole assigns a role to an access grant.
  $async.Future<CreateAccessRoleResponse> createAccessRole(
          $pb.ClientContext? ctx, CreateAccessRoleRequest request) =>
      _client.invoke<CreateAccessRoleResponse>(ctx, 'TenancyService',
          'CreateAccessRole', request, CreateAccessRoleResponse());

  /// ListAccessRole retrieves all roles for an access grant.
  $async.Future<ListAccessRoleResponse> listAccessRole(
          $pb.ClientContext? ctx, ListAccessRoleRequest request) =>
      _client.invoke<ListAccessRoleResponse>(ctx, 'TenancyService',
          'ListAccessRole', request, ListAccessRoleResponse());

  /// RemoveAccessRole removes a role from an access grant.
  $async.Future<RemoveAccessRoleResponse> removeAccessRole(
          $pb.ClientContext? ctx, RemoveAccessRoleRequest request) =>
      _client.invoke<RemoveAccessRoleResponse>(ctx, 'TenancyService',
          'RemoveAccessRole', request, RemoveAccessRoleResponse());

  /// ListServiceNamespaces returns all registered service permission namespaces.
  $async.Future<ListServiceNamespacesResponse> listServiceNamespaces(
          $pb.ClientContext? ctx, ListServiceNamespacesRequest request) =>
      _client.invoke<ListServiceNamespacesResponse>(ctx, 'TenancyService',
          'ListServiceNamespaces', request, ListServiceNamespacesResponse());

  /// GrantPermission grants a specific permission to a profile in a service namespace.
  $async.Future<GrantPermissionResponse> grantPermission(
          $pb.ClientContext? ctx, GrantPermissionRequest request) =>
      _client.invoke<GrantPermissionResponse>(ctx, 'TenancyService',
          'GrantPermission', request, GrantPermissionResponse());

  /// RevokePermission revokes a specific permission from a profile in a service namespace.
  $async.Future<RevokePermissionResponse> revokePermission(
          $pb.ClientContext? ctx, RevokePermissionRequest request) =>
      _client.invoke<RevokePermissionResponse>(ctx, 'TenancyService',
          'RevokePermission', request, RevokePermissionResponse());
}

const $core.bool _omitFieldNames =
    $core.bool.fromEnvironment('protobuf.omit_field_names');
const $core.bool _omitMessageNames =
    $core.bool.fromEnvironment('protobuf.omit_message_names');
