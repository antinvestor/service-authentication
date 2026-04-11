//
//  Generated code. Do not modify.
//  source: audit/v1/audit.proto
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

import '../../google/protobuf/struct.pb.dart' as $6;
import '../../google/protobuf/timestamp.pb.dart' as $2;

/// AuditEntryObject represents a single audit trail entry.
/// Entries are append-only and tamper-proof via hash chaining and digital signatures.
class AuditEntryObject extends $pb.GeneratedMessage {
  factory AuditEntryObject({
    $core.String? id,
    $core.String? tenantId,
    $core.String? partitionId,
    $core.String? profileId,
    $core.String? action,
    $core.String? resourceType,
    $core.String? resourceId,
    $core.String? service,
    $6.Struct? details,
    $core.String? ipAddress,
    $core.String? userAgent,
    $core.String? deviceId,
    $core.String? targetProfileId,
    $core.String? traceId,
    $2.Timestamp? createdAt,
    $core.String? previousHash,
    $core.String? entryHash,
    $core.String? signature,
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
    if (action != null) {
      $result.action = action;
    }
    if (resourceType != null) {
      $result.resourceType = resourceType;
    }
    if (resourceId != null) {
      $result.resourceId = resourceId;
    }
    if (service != null) {
      $result.service = service;
    }
    if (details != null) {
      $result.details = details;
    }
    if (ipAddress != null) {
      $result.ipAddress = ipAddress;
    }
    if (userAgent != null) {
      $result.userAgent = userAgent;
    }
    if (deviceId != null) {
      $result.deviceId = deviceId;
    }
    if (targetProfileId != null) {
      $result.targetProfileId = targetProfileId;
    }
    if (traceId != null) {
      $result.traceId = traceId;
    }
    if (createdAt != null) {
      $result.createdAt = createdAt;
    }
    if (previousHash != null) {
      $result.previousHash = previousHash;
    }
    if (entryHash != null) {
      $result.entryHash = entryHash;
    }
    if (signature != null) {
      $result.signature = signature;
    }
    return $result;
  }
  AuditEntryObject._() : super();
  factory AuditEntryObject.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory AuditEntryObject.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'AuditEntryObject', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'tenantId')
    ..aOS(3, _omitFieldNames ? '' : 'partitionId')
    ..aOS(4, _omitFieldNames ? '' : 'profileId')
    ..aOS(5, _omitFieldNames ? '' : 'action')
    ..aOS(6, _omitFieldNames ? '' : 'resourceType')
    ..aOS(7, _omitFieldNames ? '' : 'resourceId')
    ..aOS(8, _omitFieldNames ? '' : 'service')
    ..aOM<$6.Struct>(9, _omitFieldNames ? '' : 'details', subBuilder: $6.Struct.create)
    ..aOS(10, _omitFieldNames ? '' : 'ipAddress')
    ..aOS(11, _omitFieldNames ? '' : 'userAgent')
    ..aOS(12, _omitFieldNames ? '' : 'deviceId')
    ..aOS(13, _omitFieldNames ? '' : 'targetProfileId')
    ..aOS(14, _omitFieldNames ? '' : 'traceId')
    ..aOM<$2.Timestamp>(15, _omitFieldNames ? '' : 'createdAt', subBuilder: $2.Timestamp.create)
    ..aOS(16, _omitFieldNames ? '' : 'previousHash')
    ..aOS(17, _omitFieldNames ? '' : 'entryHash')
    ..aOS(18, _omitFieldNames ? '' : 'signature')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  AuditEntryObject clone() => AuditEntryObject()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  AuditEntryObject copyWith(void Function(AuditEntryObject) updates) => super.copyWith((message) => updates(message as AuditEntryObject)) as AuditEntryObject;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static AuditEntryObject create() => AuditEntryObject._();
  AuditEntryObject createEmptyInstance() => create();
  static $pb.PbList<AuditEntryObject> createRepeated() => $pb.PbList<AuditEntryObject>();
  @$core.pragma('dart2js:noInline')
  static AuditEntryObject getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<AuditEntryObject>(create);
  static AuditEntryObject? _defaultInstance;

  /// Unique identifier for this audit entry.
  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);

  /// Tenant context for multi-tenancy isolation.
  @$pb.TagNumber(2)
  $core.String get tenantId => $_getSZ(1);
  @$pb.TagNumber(2)
  set tenantId($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasTenantId() => $_has(1);
  @$pb.TagNumber(2)
  void clearTenantId() => clearField(2);

  /// Partition context within the tenant.
  @$pb.TagNumber(3)
  $core.String get partitionId => $_getSZ(2);
  @$pb.TagNumber(3)
  set partitionId($core.String v) { $_setString(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasPartitionId() => $_has(2);
  @$pb.TagNumber(3)
  void clearPartitionId() => clearField(3);

  /// Profile ID of the actor who performed the action.
  @$pb.TagNumber(4)
  $core.String get profileId => $_getSZ(3);
  @$pb.TagNumber(4)
  set profileId($core.String v) { $_setString(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasProfileId() => $_has(3);
  @$pb.TagNumber(4)
  void clearProfileId() => clearField(4);

  /// The action performed (e.g., "create", "update", "delete", "login", "grant_permission").
  @$pb.TagNumber(5)
  $core.String get action => $_getSZ(4);
  @$pb.TagNumber(5)
  set action($core.String v) { $_setString(4, v); }
  @$pb.TagNumber(5)
  $core.bool hasAction() => $_has(4);
  @$pb.TagNumber(5)
  void clearAction() => clearField(5);

  /// Type of the resource affected (e.g., "partition", "service_account", "setting").
  @$pb.TagNumber(6)
  $core.String get resourceType => $_getSZ(5);
  @$pb.TagNumber(6)
  set resourceType($core.String v) { $_setString(5, v); }
  @$pb.TagNumber(6)
  $core.bool hasResourceType() => $_has(5);
  @$pb.TagNumber(6)
  void clearResourceType() => clearField(6);

  /// Identifier of the affected resource.
  @$pb.TagNumber(7)
  $core.String get resourceId => $_getSZ(6);
  @$pb.TagNumber(7)
  set resourceId($core.String v) { $_setString(6, v); }
  @$pb.TagNumber(7)
  $core.bool hasResourceId() => $_has(6);
  @$pb.TagNumber(7)
  void clearResourceId() => clearField(7);

  /// Originating service name (e.g., "service_tenancy", "service_profile").
  @$pb.TagNumber(8)
  $core.String get service => $_getSZ(7);
  @$pb.TagNumber(8)
  set service($core.String v) { $_setString(7, v); }
  @$pb.TagNumber(8)
  $core.bool hasService() => $_has(7);
  @$pb.TagNumber(8)
  void clearService() => clearField(8);

  /// Arbitrary details about the action as structured data.
  @$pb.TagNumber(9)
  $6.Struct get details => $_getN(8);
  @$pb.TagNumber(9)
  set details($6.Struct v) { setField(9, v); }
  @$pb.TagNumber(9)
  $core.bool hasDetails() => $_has(8);
  @$pb.TagNumber(9)
  void clearDetails() => clearField(9);
  @$pb.TagNumber(9)
  $6.Struct ensureDetails() => $_ensure(8);

  /// IP address of the actor.
  @$pb.TagNumber(10)
  $core.String get ipAddress => $_getSZ(9);
  @$pb.TagNumber(10)
  set ipAddress($core.String v) { $_setString(9, v); }
  @$pb.TagNumber(10)
  $core.bool hasIpAddress() => $_has(9);
  @$pb.TagNumber(10)
  void clearIpAddress() => clearField(10);

  /// User agent string of the actor's client.
  @$pb.TagNumber(11)
  $core.String get userAgent => $_getSZ(10);
  @$pb.TagNumber(11)
  set userAgent($core.String v) { $_setString(10, v); }
  @$pb.TagNumber(11)
  $core.bool hasUserAgent() => $_has(10);
  @$pb.TagNumber(11)
  void clearUserAgent() => clearField(11);

  /// Device ID from which the action was performed.
  @$pb.TagNumber(12)
  $core.String get deviceId => $_getSZ(11);
  @$pb.TagNumber(12)
  set deviceId($core.String v) { $_setString(11, v); }
  @$pb.TagNumber(12)
  $core.bool hasDeviceId() => $_has(11);
  @$pb.TagNumber(12)
  void clearDeviceId() => clearField(12);

  /// Profile ID of the target user (if the action affects another user).
  @$pb.TagNumber(13)
  $core.String get targetProfileId => $_getSZ(12);
  @$pb.TagNumber(13)
  set targetProfileId($core.String v) { $_setString(12, v); }
  @$pb.TagNumber(13)
  $core.bool hasTargetProfileId() => $_has(12);
  @$pb.TagNumber(13)
  void clearTargetProfileId() => clearField(13);

  /// OpenTelemetry trace ID for request correlation.
  @$pb.TagNumber(14)
  $core.String get traceId => $_getSZ(13);
  @$pb.TagNumber(14)
  set traceId($core.String v) { $_setString(13, v); }
  @$pb.TagNumber(14)
  $core.bool hasTraceId() => $_has(13);
  @$pb.TagNumber(14)
  void clearTraceId() => clearField(14);

  /// Timestamp when the action occurred.
  @$pb.TagNumber(15)
  $2.Timestamp get createdAt => $_getN(14);
  @$pb.TagNumber(15)
  set createdAt($2.Timestamp v) { setField(15, v); }
  @$pb.TagNumber(15)
  $core.bool hasCreatedAt() => $_has(14);
  @$pb.TagNumber(15)
  void clearCreatedAt() => clearField(15);
  @$pb.TagNumber(15)
  $2.Timestamp ensureCreatedAt() => $_ensure(14);

  /// SHA-256 hash of the previous entry in the chain (tamper-proof integrity).
  @$pb.TagNumber(16)
  $core.String get previousHash => $_getSZ(15);
  @$pb.TagNumber(16)
  set previousHash($core.String v) { $_setString(15, v); }
  @$pb.TagNumber(16)
  $core.bool hasPreviousHash() => $_has(15);
  @$pb.TagNumber(16)
  void clearPreviousHash() => clearField(16);

  /// SHA-256 hash of this entry's content including the previous hash.
  @$pb.TagNumber(17)
  $core.String get entryHash => $_getSZ(16);
  @$pb.TagNumber(17)
  set entryHash($core.String v) { $_setString(16, v); }
  @$pb.TagNumber(17)
  $core.bool hasEntryHash() => $_has(16);
  @$pb.TagNumber(17)
  void clearEntryHash() => clearField(17);

  /// Ed25519 digital signature of the entry hash.
  @$pb.TagNumber(18)
  $core.String get signature => $_getSZ(17);
  @$pb.TagNumber(18)
  set signature($core.String v) { $_setString(17, v); }
  @$pb.TagNumber(18)
  $core.bool hasSignature() => $_has(17);
  @$pb.TagNumber(18)
  void clearSignature() => clearField(18);
}

/// CreateAuditEntryRequest creates a new audit entry.
/// The hash chain and signature are computed server-side.
class CreateAuditEntryRequest extends $pb.GeneratedMessage {
  factory CreateAuditEntryRequest({
    $core.String? profileId,
    $core.String? action,
    $core.String? resourceType,
    $core.String? resourceId,
    $core.String? service,
    $6.Struct? details,
    $core.String? ipAddress,
    $core.String? userAgent,
    $core.String? deviceId,
    $core.String? targetProfileId,
    $core.String? traceId,
  }) {
    final $result = create();
    if (profileId != null) {
      $result.profileId = profileId;
    }
    if (action != null) {
      $result.action = action;
    }
    if (resourceType != null) {
      $result.resourceType = resourceType;
    }
    if (resourceId != null) {
      $result.resourceId = resourceId;
    }
    if (service != null) {
      $result.service = service;
    }
    if (details != null) {
      $result.details = details;
    }
    if (ipAddress != null) {
      $result.ipAddress = ipAddress;
    }
    if (userAgent != null) {
      $result.userAgent = userAgent;
    }
    if (deviceId != null) {
      $result.deviceId = deviceId;
    }
    if (targetProfileId != null) {
      $result.targetProfileId = targetProfileId;
    }
    if (traceId != null) {
      $result.traceId = traceId;
    }
    return $result;
  }
  CreateAuditEntryRequest._() : super();
  factory CreateAuditEntryRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory CreateAuditEntryRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'CreateAuditEntryRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'profileId')
    ..aOS(2, _omitFieldNames ? '' : 'action')
    ..aOS(3, _omitFieldNames ? '' : 'resourceType')
    ..aOS(4, _omitFieldNames ? '' : 'resourceId')
    ..aOS(5, _omitFieldNames ? '' : 'service')
    ..aOM<$6.Struct>(6, _omitFieldNames ? '' : 'details', subBuilder: $6.Struct.create)
    ..aOS(7, _omitFieldNames ? '' : 'ipAddress')
    ..aOS(8, _omitFieldNames ? '' : 'userAgent')
    ..aOS(9, _omitFieldNames ? '' : 'deviceId')
    ..aOS(10, _omitFieldNames ? '' : 'targetProfileId')
    ..aOS(11, _omitFieldNames ? '' : 'traceId')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  CreateAuditEntryRequest clone() => CreateAuditEntryRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  CreateAuditEntryRequest copyWith(void Function(CreateAuditEntryRequest) updates) => super.copyWith((message) => updates(message as CreateAuditEntryRequest)) as CreateAuditEntryRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static CreateAuditEntryRequest create() => CreateAuditEntryRequest._();
  CreateAuditEntryRequest createEmptyInstance() => create();
  static $pb.PbList<CreateAuditEntryRequest> createRepeated() => $pb.PbList<CreateAuditEntryRequest>();
  @$core.pragma('dart2js:noInline')
  static CreateAuditEntryRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<CreateAuditEntryRequest>(create);
  static CreateAuditEntryRequest? _defaultInstance;

  /// Profile ID of the actor. Required.
  @$pb.TagNumber(1)
  $core.String get profileId => $_getSZ(0);
  @$pb.TagNumber(1)
  set profileId($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasProfileId() => $_has(0);
  @$pb.TagNumber(1)
  void clearProfileId() => clearField(1);

  /// The action performed. Required.
  @$pb.TagNumber(2)
  $core.String get action => $_getSZ(1);
  @$pb.TagNumber(2)
  set action($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasAction() => $_has(1);
  @$pb.TagNumber(2)
  void clearAction() => clearField(2);

  /// Type of the resource affected. Required.
  @$pb.TagNumber(3)
  $core.String get resourceType => $_getSZ(2);
  @$pb.TagNumber(3)
  set resourceType($core.String v) { $_setString(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasResourceType() => $_has(2);
  @$pb.TagNumber(3)
  void clearResourceType() => clearField(3);

  /// Identifier of the affected resource.
  @$pb.TagNumber(4)
  $core.String get resourceId => $_getSZ(3);
  @$pb.TagNumber(4)
  set resourceId($core.String v) { $_setString(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasResourceId() => $_has(3);
  @$pb.TagNumber(4)
  void clearResourceId() => clearField(4);

  /// Originating service name. Required.
  @$pb.TagNumber(5)
  $core.String get service => $_getSZ(4);
  @$pb.TagNumber(5)
  set service($core.String v) { $_setString(4, v); }
  @$pb.TagNumber(5)
  $core.bool hasService() => $_has(4);
  @$pb.TagNumber(5)
  void clearService() => clearField(5);

  /// Arbitrary details about the action.
  @$pb.TagNumber(6)
  $6.Struct get details => $_getN(5);
  @$pb.TagNumber(6)
  set details($6.Struct v) { setField(6, v); }
  @$pb.TagNumber(6)
  $core.bool hasDetails() => $_has(5);
  @$pb.TagNumber(6)
  void clearDetails() => clearField(6);
  @$pb.TagNumber(6)
  $6.Struct ensureDetails() => $_ensure(5);

  /// IP address of the actor.
  @$pb.TagNumber(7)
  $core.String get ipAddress => $_getSZ(6);
  @$pb.TagNumber(7)
  set ipAddress($core.String v) { $_setString(6, v); }
  @$pb.TagNumber(7)
  $core.bool hasIpAddress() => $_has(6);
  @$pb.TagNumber(7)
  void clearIpAddress() => clearField(7);

  /// User agent string.
  @$pb.TagNumber(8)
  $core.String get userAgent => $_getSZ(7);
  @$pb.TagNumber(8)
  set userAgent($core.String v) { $_setString(7, v); }
  @$pb.TagNumber(8)
  $core.bool hasUserAgent() => $_has(7);
  @$pb.TagNumber(8)
  void clearUserAgent() => clearField(8);

  /// Device ID from which the action was performed.
  @$pb.TagNumber(9)
  $core.String get deviceId => $_getSZ(8);
  @$pb.TagNumber(9)
  set deviceId($core.String v) { $_setString(8, v); }
  @$pb.TagNumber(9)
  $core.bool hasDeviceId() => $_has(8);
  @$pb.TagNumber(9)
  void clearDeviceId() => clearField(9);

  /// Profile ID of the target user (optional).
  @$pb.TagNumber(10)
  $core.String get targetProfileId => $_getSZ(9);
  @$pb.TagNumber(10)
  set targetProfileId($core.String v) { $_setString(9, v); }
  @$pb.TagNumber(10)
  $core.bool hasTargetProfileId() => $_has(9);
  @$pb.TagNumber(10)
  void clearTargetProfileId() => clearField(10);

  /// OpenTelemetry trace ID for correlation (optional).
  @$pb.TagNumber(11)
  $core.String get traceId => $_getSZ(10);
  @$pb.TagNumber(11)
  set traceId($core.String v) { $_setString(10, v); }
  @$pb.TagNumber(11)
  $core.bool hasTraceId() => $_has(10);
  @$pb.TagNumber(11)
  void clearTraceId() => clearField(11);
}

class CreateAuditEntryResponse extends $pb.GeneratedMessage {
  factory CreateAuditEntryResponse({
    AuditEntryObject? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data = data;
    }
    return $result;
  }
  CreateAuditEntryResponse._() : super();
  factory CreateAuditEntryResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory CreateAuditEntryResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'CreateAuditEntryResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..aOM<AuditEntryObject>(1, _omitFieldNames ? '' : 'data', subBuilder: AuditEntryObject.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  CreateAuditEntryResponse clone() => CreateAuditEntryResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  CreateAuditEntryResponse copyWith(void Function(CreateAuditEntryResponse) updates) => super.copyWith((message) => updates(message as CreateAuditEntryResponse)) as CreateAuditEntryResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static CreateAuditEntryResponse create() => CreateAuditEntryResponse._();
  CreateAuditEntryResponse createEmptyInstance() => create();
  static $pb.PbList<CreateAuditEntryResponse> createRepeated() => $pb.PbList<CreateAuditEntryResponse>();
  @$core.pragma('dart2js:noInline')
  static CreateAuditEntryResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<CreateAuditEntryResponse>(create);
  static CreateAuditEntryResponse? _defaultInstance;

  @$pb.TagNumber(1)
  AuditEntryObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(AuditEntryObject v) { setField(1, v); }
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => clearField(1);
  @$pb.TagNumber(1)
  AuditEntryObject ensureData() => $_ensure(0);
}

/// BatchCreateAuditEntriesRequest creates multiple audit entries atomically.
class BatchCreateAuditEntriesRequest extends $pb.GeneratedMessage {
  factory BatchCreateAuditEntriesRequest({
    $core.Iterable<CreateAuditEntryRequest>? entries,
  }) {
    final $result = create();
    if (entries != null) {
      $result.entries.addAll(entries);
    }
    return $result;
  }
  BatchCreateAuditEntriesRequest._() : super();
  factory BatchCreateAuditEntriesRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory BatchCreateAuditEntriesRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'BatchCreateAuditEntriesRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..pc<CreateAuditEntryRequest>(1, _omitFieldNames ? '' : 'entries', $pb.PbFieldType.PM, subBuilder: CreateAuditEntryRequest.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  BatchCreateAuditEntriesRequest clone() => BatchCreateAuditEntriesRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  BatchCreateAuditEntriesRequest copyWith(void Function(BatchCreateAuditEntriesRequest) updates) => super.copyWith((message) => updates(message as BatchCreateAuditEntriesRequest)) as BatchCreateAuditEntriesRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static BatchCreateAuditEntriesRequest create() => BatchCreateAuditEntriesRequest._();
  BatchCreateAuditEntriesRequest createEmptyInstance() => create();
  static $pb.PbList<BatchCreateAuditEntriesRequest> createRepeated() => $pb.PbList<BatchCreateAuditEntriesRequest>();
  @$core.pragma('dart2js:noInline')
  static BatchCreateAuditEntriesRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<BatchCreateAuditEntriesRequest>(create);
  static BatchCreateAuditEntriesRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<CreateAuditEntryRequest> get entries => $_getList(0);
}

class BatchCreateAuditEntriesResponse extends $pb.GeneratedMessage {
  factory BatchCreateAuditEntriesResponse({
    $core.Iterable<AuditEntryObject>? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data.addAll(data);
    }
    return $result;
  }
  BatchCreateAuditEntriesResponse._() : super();
  factory BatchCreateAuditEntriesResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory BatchCreateAuditEntriesResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'BatchCreateAuditEntriesResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..pc<AuditEntryObject>(1, _omitFieldNames ? '' : 'data', $pb.PbFieldType.PM, subBuilder: AuditEntryObject.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  BatchCreateAuditEntriesResponse clone() => BatchCreateAuditEntriesResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  BatchCreateAuditEntriesResponse copyWith(void Function(BatchCreateAuditEntriesResponse) updates) => super.copyWith((message) => updates(message as BatchCreateAuditEntriesResponse)) as BatchCreateAuditEntriesResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static BatchCreateAuditEntriesResponse create() => BatchCreateAuditEntriesResponse._();
  BatchCreateAuditEntriesResponse createEmptyInstance() => create();
  static $pb.PbList<BatchCreateAuditEntriesResponse> createRepeated() => $pb.PbList<BatchCreateAuditEntriesResponse>();
  @$core.pragma('dart2js:noInline')
  static BatchCreateAuditEntriesResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<BatchCreateAuditEntriesResponse>(create);
  static BatchCreateAuditEntriesResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<AuditEntryObject> get data => $_getList(0);
}

/// GetAuditEntryRequest retrieves a single audit entry by ID.
class GetAuditEntryRequest extends $pb.GeneratedMessage {
  factory GetAuditEntryRequest({
    $core.String? id,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    return $result;
  }
  GetAuditEntryRequest._() : super();
  factory GetAuditEntryRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory GetAuditEntryRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'GetAuditEntryRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  GetAuditEntryRequest clone() => GetAuditEntryRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  GetAuditEntryRequest copyWith(void Function(GetAuditEntryRequest) updates) => super.copyWith((message) => updates(message as GetAuditEntryRequest)) as GetAuditEntryRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetAuditEntryRequest create() => GetAuditEntryRequest._();
  GetAuditEntryRequest createEmptyInstance() => create();
  static $pb.PbList<GetAuditEntryRequest> createRepeated() => $pb.PbList<GetAuditEntryRequest>();
  @$core.pragma('dart2js:noInline')
  static GetAuditEntryRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetAuditEntryRequest>(create);
  static GetAuditEntryRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);
}

class GetAuditEntryResponse extends $pb.GeneratedMessage {
  factory GetAuditEntryResponse({
    AuditEntryObject? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data = data;
    }
    return $result;
  }
  GetAuditEntryResponse._() : super();
  factory GetAuditEntryResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory GetAuditEntryResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'GetAuditEntryResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..aOM<AuditEntryObject>(1, _omitFieldNames ? '' : 'data', subBuilder: AuditEntryObject.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  GetAuditEntryResponse clone() => GetAuditEntryResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  GetAuditEntryResponse copyWith(void Function(GetAuditEntryResponse) updates) => super.copyWith((message) => updates(message as GetAuditEntryResponse)) as GetAuditEntryResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetAuditEntryResponse create() => GetAuditEntryResponse._();
  GetAuditEntryResponse createEmptyInstance() => create();
  static $pb.PbList<GetAuditEntryResponse> createRepeated() => $pb.PbList<GetAuditEntryResponse>();
  @$core.pragma('dart2js:noInline')
  static GetAuditEntryResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetAuditEntryResponse>(create);
  static GetAuditEntryResponse? _defaultInstance;

  @$pb.TagNumber(1)
  AuditEntryObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(AuditEntryObject v) { setField(1, v); }
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => clearField(1);
  @$pb.TagNumber(1)
  AuditEntryObject ensureData() => $_ensure(0);
}

/// ListAuditEntriesRequest lists audit entries with filtering and pagination.
class ListAuditEntriesRequest extends $pb.GeneratedMessage {
  factory ListAuditEntriesRequest({
    $core.String? profileId,
    $core.String? action,
    $core.String? resourceType,
    $core.String? resourceId,
    $core.String? service,
    $core.String? targetProfileId,
    $core.String? deviceId,
    $2.Timestamp? startDate,
    $2.Timestamp? endDate,
    $core.int? count,
    $core.String? page,
  }) {
    final $result = create();
    if (profileId != null) {
      $result.profileId = profileId;
    }
    if (action != null) {
      $result.action = action;
    }
    if (resourceType != null) {
      $result.resourceType = resourceType;
    }
    if (resourceId != null) {
      $result.resourceId = resourceId;
    }
    if (service != null) {
      $result.service = service;
    }
    if (targetProfileId != null) {
      $result.targetProfileId = targetProfileId;
    }
    if (deviceId != null) {
      $result.deviceId = deviceId;
    }
    if (startDate != null) {
      $result.startDate = startDate;
    }
    if (endDate != null) {
      $result.endDate = endDate;
    }
    if (count != null) {
      $result.count = count;
    }
    if (page != null) {
      $result.page = page;
    }
    return $result;
  }
  ListAuditEntriesRequest._() : super();
  factory ListAuditEntriesRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory ListAuditEntriesRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'ListAuditEntriesRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'profileId')
    ..aOS(2, _omitFieldNames ? '' : 'action')
    ..aOS(3, _omitFieldNames ? '' : 'resourceType')
    ..aOS(4, _omitFieldNames ? '' : 'resourceId')
    ..aOS(5, _omitFieldNames ? '' : 'service')
    ..aOS(6, _omitFieldNames ? '' : 'targetProfileId')
    ..aOS(7, _omitFieldNames ? '' : 'deviceId')
    ..aOM<$2.Timestamp>(8, _omitFieldNames ? '' : 'startDate', subBuilder: $2.Timestamp.create)
    ..aOM<$2.Timestamp>(9, _omitFieldNames ? '' : 'endDate', subBuilder: $2.Timestamp.create)
    ..a<$core.int>(10, _omitFieldNames ? '' : 'count', $pb.PbFieldType.O3)
    ..aOS(11, _omitFieldNames ? '' : 'page')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  ListAuditEntriesRequest clone() => ListAuditEntriesRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  ListAuditEntriesRequest copyWith(void Function(ListAuditEntriesRequest) updates) => super.copyWith((message) => updates(message as ListAuditEntriesRequest)) as ListAuditEntriesRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListAuditEntriesRequest create() => ListAuditEntriesRequest._();
  ListAuditEntriesRequest createEmptyInstance() => create();
  static $pb.PbList<ListAuditEntriesRequest> createRepeated() => $pb.PbList<ListAuditEntriesRequest>();
  @$core.pragma('dart2js:noInline')
  static ListAuditEntriesRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ListAuditEntriesRequest>(create);
  static ListAuditEntriesRequest? _defaultInstance;

  /// Filter by profile ID of the actor.
  @$pb.TagNumber(1)
  $core.String get profileId => $_getSZ(0);
  @$pb.TagNumber(1)
  set profileId($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasProfileId() => $_has(0);
  @$pb.TagNumber(1)
  void clearProfileId() => clearField(1);

  /// Filter by action type.
  @$pb.TagNumber(2)
  $core.String get action => $_getSZ(1);
  @$pb.TagNumber(2)
  set action($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasAction() => $_has(1);
  @$pb.TagNumber(2)
  void clearAction() => clearField(2);

  /// Filter by resource type.
  @$pb.TagNumber(3)
  $core.String get resourceType => $_getSZ(2);
  @$pb.TagNumber(3)
  set resourceType($core.String v) { $_setString(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasResourceType() => $_has(2);
  @$pb.TagNumber(3)
  void clearResourceType() => clearField(3);

  /// Filter by resource ID.
  @$pb.TagNumber(4)
  $core.String get resourceId => $_getSZ(3);
  @$pb.TagNumber(4)
  set resourceId($core.String v) { $_setString(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasResourceId() => $_has(3);
  @$pb.TagNumber(4)
  void clearResourceId() => clearField(4);

  /// Filter by originating service.
  @$pb.TagNumber(5)
  $core.String get service => $_getSZ(4);
  @$pb.TagNumber(5)
  set service($core.String v) { $_setString(4, v); }
  @$pb.TagNumber(5)
  $core.bool hasService() => $_has(4);
  @$pb.TagNumber(5)
  void clearService() => clearField(5);

  /// Filter by target profile ID.
  @$pb.TagNumber(6)
  $core.String get targetProfileId => $_getSZ(5);
  @$pb.TagNumber(6)
  set targetProfileId($core.String v) { $_setString(5, v); }
  @$pb.TagNumber(6)
  $core.bool hasTargetProfileId() => $_has(5);
  @$pb.TagNumber(6)
  void clearTargetProfileId() => clearField(6);

  /// Filter by device ID.
  @$pb.TagNumber(7)
  $core.String get deviceId => $_getSZ(6);
  @$pb.TagNumber(7)
  set deviceId($core.String v) { $_setString(6, v); }
  @$pb.TagNumber(7)
  $core.bool hasDeviceId() => $_has(6);
  @$pb.TagNumber(7)
  void clearDeviceId() => clearField(7);

  /// Filter entries created after this timestamp.
  @$pb.TagNumber(8)
  $2.Timestamp get startDate => $_getN(7);
  @$pb.TagNumber(8)
  set startDate($2.Timestamp v) { setField(8, v); }
  @$pb.TagNumber(8)
  $core.bool hasStartDate() => $_has(7);
  @$pb.TagNumber(8)
  void clearStartDate() => clearField(8);
  @$pb.TagNumber(8)
  $2.Timestamp ensureStartDate() => $_ensure(7);

  /// Filter entries created before this timestamp.
  @$pb.TagNumber(9)
  $2.Timestamp get endDate => $_getN(8);
  @$pb.TagNumber(9)
  set endDate($2.Timestamp v) { setField(9, v); }
  @$pb.TagNumber(9)
  $core.bool hasEndDate() => $_has(8);
  @$pb.TagNumber(9)
  void clearEndDate() => clearField(9);
  @$pb.TagNumber(9)
  $2.Timestamp ensureEndDate() => $_ensure(8);

  /// Maximum number of entries to return per page. Default 50, max 500.
  @$pb.TagNumber(10)
  $core.int get count => $_getIZ(9);
  @$pb.TagNumber(10)
  set count($core.int v) { $_setSignedInt32(9, v); }
  @$pb.TagNumber(10)
  $core.bool hasCount() => $_has(9);
  @$pb.TagNumber(10)
  void clearCount() => clearField(10);

  /// Pagination cursor (ID of the last entry from previous page).
  @$pb.TagNumber(11)
  $core.String get page => $_getSZ(10);
  @$pb.TagNumber(11)
  set page($core.String v) { $_setString(10, v); }
  @$pb.TagNumber(11)
  $core.bool hasPage() => $_has(10);
  @$pb.TagNumber(11)
  void clearPage() => clearField(11);
}

class ListAuditEntriesResponse extends $pb.GeneratedMessage {
  factory ListAuditEntriesResponse({
    $core.Iterable<AuditEntryObject>? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data.addAll(data);
    }
    return $result;
  }
  ListAuditEntriesResponse._() : super();
  factory ListAuditEntriesResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory ListAuditEntriesResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'ListAuditEntriesResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..pc<AuditEntryObject>(1, _omitFieldNames ? '' : 'data', $pb.PbFieldType.PM, subBuilder: AuditEntryObject.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  ListAuditEntriesResponse clone() => ListAuditEntriesResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  ListAuditEntriesResponse copyWith(void Function(ListAuditEntriesResponse) updates) => super.copyWith((message) => updates(message as ListAuditEntriesResponse)) as ListAuditEntriesResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListAuditEntriesResponse create() => ListAuditEntriesResponse._();
  ListAuditEntriesResponse createEmptyInstance() => create();
  static $pb.PbList<ListAuditEntriesResponse> createRepeated() => $pb.PbList<ListAuditEntriesResponse>();
  @$core.pragma('dart2js:noInline')
  static ListAuditEntriesResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ListAuditEntriesResponse>(create);
  static ListAuditEntriesResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<AuditEntryObject> get data => $_getList(0);
}

/// SearchAuditEntriesRequest provides free-text search across audit entries.
class SearchAuditEntriesRequest extends $pb.GeneratedMessage {
  factory SearchAuditEntriesRequest({
    $core.String? query,
    $2.Timestamp? startDate,
    $2.Timestamp? endDate,
    $core.int? count,
    $core.String? page,
  }) {
    final $result = create();
    if (query != null) {
      $result.query = query;
    }
    if (startDate != null) {
      $result.startDate = startDate;
    }
    if (endDate != null) {
      $result.endDate = endDate;
    }
    if (count != null) {
      $result.count = count;
    }
    if (page != null) {
      $result.page = page;
    }
    return $result;
  }
  SearchAuditEntriesRequest._() : super();
  factory SearchAuditEntriesRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory SearchAuditEntriesRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'SearchAuditEntriesRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'query')
    ..aOM<$2.Timestamp>(2, _omitFieldNames ? '' : 'startDate', subBuilder: $2.Timestamp.create)
    ..aOM<$2.Timestamp>(3, _omitFieldNames ? '' : 'endDate', subBuilder: $2.Timestamp.create)
    ..a<$core.int>(4, _omitFieldNames ? '' : 'count', $pb.PbFieldType.O3)
    ..aOS(5, _omitFieldNames ? '' : 'page')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  SearchAuditEntriesRequest clone() => SearchAuditEntriesRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  SearchAuditEntriesRequest copyWith(void Function(SearchAuditEntriesRequest) updates) => super.copyWith((message) => updates(message as SearchAuditEntriesRequest)) as SearchAuditEntriesRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SearchAuditEntriesRequest create() => SearchAuditEntriesRequest._();
  SearchAuditEntriesRequest createEmptyInstance() => create();
  static $pb.PbList<SearchAuditEntriesRequest> createRepeated() => $pb.PbList<SearchAuditEntriesRequest>();
  @$core.pragma('dart2js:noInline')
  static SearchAuditEntriesRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<SearchAuditEntriesRequest>(create);
  static SearchAuditEntriesRequest? _defaultInstance;

  /// Free-text search query matching action, resource_type, resource_id, or details.
  @$pb.TagNumber(1)
  $core.String get query => $_getSZ(0);
  @$pb.TagNumber(1)
  set query($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasQuery() => $_has(0);
  @$pb.TagNumber(1)
  void clearQuery() => clearField(1);

  /// Filter entries created after this timestamp.
  @$pb.TagNumber(2)
  $2.Timestamp get startDate => $_getN(1);
  @$pb.TagNumber(2)
  set startDate($2.Timestamp v) { setField(2, v); }
  @$pb.TagNumber(2)
  $core.bool hasStartDate() => $_has(1);
  @$pb.TagNumber(2)
  void clearStartDate() => clearField(2);
  @$pb.TagNumber(2)
  $2.Timestamp ensureStartDate() => $_ensure(1);

  /// Filter entries created before this timestamp.
  @$pb.TagNumber(3)
  $2.Timestamp get endDate => $_getN(2);
  @$pb.TagNumber(3)
  set endDate($2.Timestamp v) { setField(3, v); }
  @$pb.TagNumber(3)
  $core.bool hasEndDate() => $_has(2);
  @$pb.TagNumber(3)
  void clearEndDate() => clearField(3);
  @$pb.TagNumber(3)
  $2.Timestamp ensureEndDate() => $_ensure(2);

  /// Maximum number of entries to return per page. Default 50, max 500.
  @$pb.TagNumber(4)
  $core.int get count => $_getIZ(3);
  @$pb.TagNumber(4)
  set count($core.int v) { $_setSignedInt32(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasCount() => $_has(3);
  @$pb.TagNumber(4)
  void clearCount() => clearField(4);

  /// Pagination cursor.
  @$pb.TagNumber(5)
  $core.String get page => $_getSZ(4);
  @$pb.TagNumber(5)
  set page($core.String v) { $_setString(4, v); }
  @$pb.TagNumber(5)
  $core.bool hasPage() => $_has(4);
  @$pb.TagNumber(5)
  void clearPage() => clearField(5);
}

class SearchAuditEntriesResponse extends $pb.GeneratedMessage {
  factory SearchAuditEntriesResponse({
    $core.Iterable<AuditEntryObject>? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data.addAll(data);
    }
    return $result;
  }
  SearchAuditEntriesResponse._() : super();
  factory SearchAuditEntriesResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory SearchAuditEntriesResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'SearchAuditEntriesResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..pc<AuditEntryObject>(1, _omitFieldNames ? '' : 'data', $pb.PbFieldType.PM, subBuilder: AuditEntryObject.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  SearchAuditEntriesResponse clone() => SearchAuditEntriesResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  SearchAuditEntriesResponse copyWith(void Function(SearchAuditEntriesResponse) updates) => super.copyWith((message) => updates(message as SearchAuditEntriesResponse)) as SearchAuditEntriesResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SearchAuditEntriesResponse create() => SearchAuditEntriesResponse._();
  SearchAuditEntriesResponse createEmptyInstance() => create();
  static $pb.PbList<SearchAuditEntriesResponse> createRepeated() => $pb.PbList<SearchAuditEntriesResponse>();
  @$core.pragma('dart2js:noInline')
  static SearchAuditEntriesResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<SearchAuditEntriesResponse>(create);
  static SearchAuditEntriesResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<AuditEntryObject> get data => $_getList(0);
}

/// VerifyIntegrityRequest verifies the hash chain integrity over a time range.
class VerifyIntegrityRequest extends $pb.GeneratedMessage {
  factory VerifyIntegrityRequest({
    $2.Timestamp? startDate,
    $2.Timestamp? endDate,
  }) {
    final $result = create();
    if (startDate != null) {
      $result.startDate = startDate;
    }
    if (endDate != null) {
      $result.endDate = endDate;
    }
    return $result;
  }
  VerifyIntegrityRequest._() : super();
  factory VerifyIntegrityRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory VerifyIntegrityRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'VerifyIntegrityRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..aOM<$2.Timestamp>(1, _omitFieldNames ? '' : 'startDate', subBuilder: $2.Timestamp.create)
    ..aOM<$2.Timestamp>(2, _omitFieldNames ? '' : 'endDate', subBuilder: $2.Timestamp.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  VerifyIntegrityRequest clone() => VerifyIntegrityRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  VerifyIntegrityRequest copyWith(void Function(VerifyIntegrityRequest) updates) => super.copyWith((message) => updates(message as VerifyIntegrityRequest)) as VerifyIntegrityRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static VerifyIntegrityRequest create() => VerifyIntegrityRequest._();
  VerifyIntegrityRequest createEmptyInstance() => create();
  static $pb.PbList<VerifyIntegrityRequest> createRepeated() => $pb.PbList<VerifyIntegrityRequest>();
  @$core.pragma('dart2js:noInline')
  static VerifyIntegrityRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<VerifyIntegrityRequest>(create);
  static VerifyIntegrityRequest? _defaultInstance;

  /// Start of the time range to verify.
  @$pb.TagNumber(1)
  $2.Timestamp get startDate => $_getN(0);
  @$pb.TagNumber(1)
  set startDate($2.Timestamp v) { setField(1, v); }
  @$pb.TagNumber(1)
  $core.bool hasStartDate() => $_has(0);
  @$pb.TagNumber(1)
  void clearStartDate() => clearField(1);
  @$pb.TagNumber(1)
  $2.Timestamp ensureStartDate() => $_ensure(0);

  /// End of the time range to verify.
  @$pb.TagNumber(2)
  $2.Timestamp get endDate => $_getN(1);
  @$pb.TagNumber(2)
  set endDate($2.Timestamp v) { setField(2, v); }
  @$pb.TagNumber(2)
  $core.bool hasEndDate() => $_has(1);
  @$pb.TagNumber(2)
  void clearEndDate() => clearField(2);
  @$pb.TagNumber(2)
  $2.Timestamp ensureEndDate() => $_ensure(1);
}

/// VerifyIntegrityResponse reports the result of integrity verification.
class VerifyIntegrityResponse extends $pb.GeneratedMessage {
  factory VerifyIntegrityResponse({
    $core.bool? valid,
    $fixnum.Int64? entriesVerified,
    $core.String? firstInvalidEntryId,
    $core.String? message,
  }) {
    final $result = create();
    if (valid != null) {
      $result.valid = valid;
    }
    if (entriesVerified != null) {
      $result.entriesVerified = entriesVerified;
    }
    if (firstInvalidEntryId != null) {
      $result.firstInvalidEntryId = firstInvalidEntryId;
    }
    if (message != null) {
      $result.message = message;
    }
    return $result;
  }
  VerifyIntegrityResponse._() : super();
  factory VerifyIntegrityResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory VerifyIntegrityResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'VerifyIntegrityResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'), createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'valid')
    ..aInt64(2, _omitFieldNames ? '' : 'entriesVerified')
    ..aOS(3, _omitFieldNames ? '' : 'firstInvalidEntryId')
    ..aOS(4, _omitFieldNames ? '' : 'message')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  VerifyIntegrityResponse clone() => VerifyIntegrityResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  VerifyIntegrityResponse copyWith(void Function(VerifyIntegrityResponse) updates) => super.copyWith((message) => updates(message as VerifyIntegrityResponse)) as VerifyIntegrityResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static VerifyIntegrityResponse create() => VerifyIntegrityResponse._();
  VerifyIntegrityResponse createEmptyInstance() => create();
  static $pb.PbList<VerifyIntegrityResponse> createRepeated() => $pb.PbList<VerifyIntegrityResponse>();
  @$core.pragma('dart2js:noInline')
  static VerifyIntegrityResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<VerifyIntegrityResponse>(create);
  static VerifyIntegrityResponse? _defaultInstance;

  /// Whether the hash chain is intact.
  @$pb.TagNumber(1)
  $core.bool get valid => $_getBF(0);
  @$pb.TagNumber(1)
  set valid($core.bool v) { $_setBool(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasValid() => $_has(0);
  @$pb.TagNumber(1)
  void clearValid() => clearField(1);

  /// Total number of entries verified.
  @$pb.TagNumber(2)
  $fixnum.Int64 get entriesVerified => $_getI64(1);
  @$pb.TagNumber(2)
  set entriesVerified($fixnum.Int64 v) { $_setInt64(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasEntriesVerified() => $_has(1);
  @$pb.TagNumber(2)
  void clearEntriesVerified() => clearField(2);

  /// ID of the first entry that failed verification (empty if valid).
  @$pb.TagNumber(3)
  $core.String get firstInvalidEntryId => $_getSZ(2);
  @$pb.TagNumber(3)
  set firstInvalidEntryId($core.String v) { $_setString(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasFirstInvalidEntryId() => $_has(2);
  @$pb.TagNumber(3)
  void clearFirstInvalidEntryId() => clearField(3);

  /// Human-readable description of the verification result.
  @$pb.TagNumber(4)
  $core.String get message => $_getSZ(3);
  @$pb.TagNumber(4)
  set message($core.String v) { $_setString(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasMessage() => $_has(3);
  @$pb.TagNumber(4)
  void clearMessage() => clearField(4);
}

class AuditServiceApi {
  $pb.RpcClient _client;
  AuditServiceApi(this._client);

  $async.Future<CreateAuditEntryResponse> createAuditEntry($pb.ClientContext? ctx, CreateAuditEntryRequest request) =>
    _client.invoke<CreateAuditEntryResponse>(ctx, 'AuditService', 'CreateAuditEntry', request, CreateAuditEntryResponse())
  ;
  $async.Future<BatchCreateAuditEntriesResponse> batchCreateAuditEntries($pb.ClientContext? ctx, BatchCreateAuditEntriesRequest request) =>
    _client.invoke<BatchCreateAuditEntriesResponse>(ctx, 'AuditService', 'BatchCreateAuditEntries', request, BatchCreateAuditEntriesResponse())
  ;
  $async.Future<GetAuditEntryResponse> getAuditEntry($pb.ClientContext? ctx, GetAuditEntryRequest request) =>
    _client.invoke<GetAuditEntryResponse>(ctx, 'AuditService', 'GetAuditEntry', request, GetAuditEntryResponse())
  ;
  $async.Future<ListAuditEntriesResponse> listAuditEntries($pb.ClientContext? ctx, ListAuditEntriesRequest request) =>
    _client.invoke<ListAuditEntriesResponse>(ctx, 'AuditService', 'ListAuditEntries', request, ListAuditEntriesResponse())
  ;
  $async.Future<SearchAuditEntriesResponse> searchAuditEntries($pb.ClientContext? ctx, SearchAuditEntriesRequest request) =>
    _client.invoke<SearchAuditEntriesResponse>(ctx, 'AuditService', 'SearchAuditEntries', request, SearchAuditEntriesResponse())
  ;
  $async.Future<VerifyIntegrityResponse> verifyIntegrity($pb.ClientContext? ctx, VerifyIntegrityRequest request) =>
    _client.invoke<VerifyIntegrityResponse>(ctx, 'AuditService', 'VerifyIntegrity', request, VerifyIntegrityResponse())
  ;
}


const _omitFieldNames = $core.bool.fromEnvironment('protobuf.omit_field_names');
const _omitMessageNames = $core.bool.fromEnvironment('protobuf.omit_message_names');
