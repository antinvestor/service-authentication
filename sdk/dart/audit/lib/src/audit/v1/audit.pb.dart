// This is a generated file - do not edit.
//
// Generated from audit/v1/audit.proto.

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
import 'package:protobuf/well_known_types/google/protobuf/struct.pb.dart' as $0;
import 'package:protobuf/well_known_types/google/protobuf/timestamp.pb.dart'
    as $1;

import 'audit.pbenum.dart';

export 'package:protobuf/protobuf.dart' show GeneratedMessageGenericExtensions;

export 'audit.pbenum.dart';

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
    $0.Struct? details,
    $core.String? ipAddress,
    $core.String? userAgent,
    $core.String? deviceId,
    $core.String? targetProfileId,
    $core.String? traceId,
    $1.Timestamp? createdAt,
    $core.String? previousHash,
    $core.String? entryHash,
    $core.String? signature,
    $fixnum.Int64? seq,
    $core.String? keyId,
    $core.int? canonVersion,
    $core.String? entryId,
    $core.String? actorServiceAccountId,
    $core.String? onBehalfOf,
    $1.Timestamp? occurredAt,
    $1.Timestamp? receivedAt,
    $core.String? correlationId,
    $core.String? eventId,
    $core.String? intentId,
    $core.String? instanceId,
    $core.String? payloadHash,
    $core.String? authorizationHash,
    $core.String? policyHash,
    $core.String? deviceKeyId,
    $core.String? stateFrom,
    $core.String? stateTo,
    $fixnum.Int64? resourceVersion,
    $core.Iterable<AuditRelation>? relations,
    $core.int? manifestVersion,
    $core.bool? unmanifested,
    IntakeState? state,
    AuditPhase? phase,
    $core.String? outcomeOfEntryId,
    $core.String? auditClass,
    $core.bool? writtenDuringDegradation,
  }) {
    final result = AuditEntryObject._();
    if (id != null) result.id = id;
    if (tenantId != null) result.tenantId = tenantId;
    if (partitionId != null) result.partitionId = partitionId;
    if (profileId != null) result.profileId = profileId;
    if (action != null) result.action = action;
    if (resourceType != null) result.resourceType = resourceType;
    if (resourceId != null) result.resourceId = resourceId;
    if (service != null) result.service = service;
    if (details != null) result.details = details;
    if (ipAddress != null) result.ipAddress = ipAddress;
    if (userAgent != null) result.userAgent = userAgent;
    if (deviceId != null) result.deviceId = deviceId;
    if (targetProfileId != null) result.targetProfileId = targetProfileId;
    if (traceId != null) result.traceId = traceId;
    if (createdAt != null) result.createdAt = createdAt;
    if (previousHash != null) result.previousHash = previousHash;
    if (entryHash != null) result.entryHash = entryHash;
    if (signature != null) result.signature = signature;
    if (seq != null) result.seq = seq;
    if (keyId != null) result.keyId = keyId;
    if (canonVersion != null) result.canonVersion = canonVersion;
    if (entryId != null) result.entryId = entryId;
    if (actorServiceAccountId != null)
      result.actorServiceAccountId = actorServiceAccountId;
    if (onBehalfOf != null) result.onBehalfOf = onBehalfOf;
    if (occurredAt != null) result.occurredAt = occurredAt;
    if (receivedAt != null) result.receivedAt = receivedAt;
    if (correlationId != null) result.correlationId = correlationId;
    if (eventId != null) result.eventId = eventId;
    if (intentId != null) result.intentId = intentId;
    if (instanceId != null) result.instanceId = instanceId;
    if (payloadHash != null) result.payloadHash = payloadHash;
    if (authorizationHash != null) result.authorizationHash = authorizationHash;
    if (policyHash != null) result.policyHash = policyHash;
    if (deviceKeyId != null) result.deviceKeyId = deviceKeyId;
    if (stateFrom != null) result.stateFrom = stateFrom;
    if (stateTo != null) result.stateTo = stateTo;
    if (resourceVersion != null) result.resourceVersion = resourceVersion;
    if (relations != null) result.relations.addAll(relations);
    if (manifestVersion != null) result.manifestVersion = manifestVersion;
    if (unmanifested != null) result.unmanifested = unmanifested;
    if (state != null) result.state = state;
    if (phase != null) result.phase = phase;
    if (outcomeOfEntryId != null) result.outcomeOfEntryId = outcomeOfEntryId;
    if (auditClass != null) result.auditClass = auditClass;
    if (writtenDuringDegradation != null)
      result.writtenDuringDegradation = writtenDuringDegradation;
    return result;
  }

  AuditEntryObject._();

  factory AuditEntryObject.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AuditEntryObject()..mergeFromBuffer(data, registry);
  factory AuditEntryObject.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AuditEntryObject()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'AuditEntryObject',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: AuditEntryObject.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'tenantId')
    ..aOS(3, _omitFieldNames ? '' : 'partitionId')
    ..aOS(4, _omitFieldNames ? '' : 'profileId')
    ..aOS(5, _omitFieldNames ? '' : 'action')
    ..aOS(6, _omitFieldNames ? '' : 'resourceType')
    ..aOS(7, _omitFieldNames ? '' : 'resourceId')
    ..aOS(8, _omitFieldNames ? '' : 'service')
    ..aOM<$0.Struct>(9, _omitFieldNames ? '' : 'details',
        subBuilder: $0.Struct.$_createMessage)
    ..aOS(10, _omitFieldNames ? '' : 'ipAddress')
    ..aOS(11, _omitFieldNames ? '' : 'userAgent')
    ..aOS(12, _omitFieldNames ? '' : 'deviceId')
    ..aOS(13, _omitFieldNames ? '' : 'targetProfileId')
    ..aOS(14, _omitFieldNames ? '' : 'traceId')
    ..aOM<$1.Timestamp>(15, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOS(16, _omitFieldNames ? '' : 'previousHash')
    ..aOS(17, _omitFieldNames ? '' : 'entryHash')
    ..aOS(18, _omitFieldNames ? '' : 'signature')
    ..aInt64(19, _omitFieldNames ? '' : 'seq')
    ..aOS(20, _omitFieldNames ? '' : 'keyId')
    ..aI(21, _omitFieldNames ? '' : 'canonVersion')
    ..aOS(22, _omitFieldNames ? '' : 'entryId')
    ..aOS(23, _omitFieldNames ? '' : 'actorServiceAccountId')
    ..aOS(24, _omitFieldNames ? '' : 'onBehalfOf')
    ..aOM<$1.Timestamp>(25, _omitFieldNames ? '' : 'occurredAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOM<$1.Timestamp>(26, _omitFieldNames ? '' : 'receivedAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOS(27, _omitFieldNames ? '' : 'correlationId')
    ..aOS(28, _omitFieldNames ? '' : 'eventId')
    ..aOS(29, _omitFieldNames ? '' : 'intentId')
    ..aOS(30, _omitFieldNames ? '' : 'instanceId')
    ..aOS(31, _omitFieldNames ? '' : 'payloadHash')
    ..aOS(32, _omitFieldNames ? '' : 'authorizationHash')
    ..aOS(33, _omitFieldNames ? '' : 'policyHash')
    ..aOS(34, _omitFieldNames ? '' : 'deviceKeyId')
    ..aOS(35, _omitFieldNames ? '' : 'stateFrom')
    ..aOS(36, _omitFieldNames ? '' : 'stateTo')
    ..aInt64(37, _omitFieldNames ? '' : 'resourceVersion')
    ..pPM<AuditRelation>(38, _omitFieldNames ? '' : 'relations',
        subBuilder: AuditRelation.$_createMessage)
    ..aI(39, _omitFieldNames ? '' : 'manifestVersion')
    ..aOB(40, _omitFieldNames ? '' : 'unmanifested')
    ..aE<IntakeState>(41, _omitFieldNames ? '' : 'state',
        enumValues: IntakeState.values)
    ..aE<AuditPhase>(42, _omitFieldNames ? '' : 'phase',
        enumValues: AuditPhase.values)
    ..aOS(43, _omitFieldNames ? '' : 'outcomeOfEntryId')
    ..aOS(44, _omitFieldNames ? '' : 'auditClass')
    ..aOB(45, _omitFieldNames ? '' : 'writtenDuringDegradation')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AuditEntryObject clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AuditEntryObject copyWith(void Function(AuditEntryObject) updates) =>
      super.copyWith((message) => updates(message as AuditEntryObject))
          as AuditEntryObject;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use AuditEntryObject() / AuditEntryObject.new instead')
  static AuditEntryObject create() => AuditEntryObject._();
  static $pb.GeneratedMessage $_createMessage() => AuditEntryObject._();
  @$core.override
  AuditEntryObject createEmptyInstance() => AuditEntryObject._();
  @$core.pragma('dart2js:noInline')
  static AuditEntryObject getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<AuditEntryObject>(
          AuditEntryObject.$_createMessage);
  static AuditEntryObject? _defaultInstance;

  /// Unique identifier for this audit entry.
  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  /// Tenant context for multi-tenancy isolation.
  @$pb.TagNumber(2)
  $core.String get tenantId => $_getSZ(1);
  @$pb.TagNumber(2)
  set tenantId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasTenantId() => $_has(1);
  @$pb.TagNumber(2)
  void clearTenantId() => $_clearField(2);

  /// Partition context within the tenant.
  @$pb.TagNumber(3)
  $core.String get partitionId => $_getSZ(2);
  @$pb.TagNumber(3)
  set partitionId($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasPartitionId() => $_has(2);
  @$pb.TagNumber(3)
  void clearPartitionId() => $_clearField(3);

  /// Profile ID of the actor who performed the action.
  @$pb.TagNumber(4)
  $core.String get profileId => $_getSZ(3);
  @$pb.TagNumber(4)
  set profileId($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasProfileId() => $_has(3);
  @$pb.TagNumber(4)
  void clearProfileId() => $_clearField(4);

  /// The action performed (e.g., "create", "update", "delete", "login", "grant_permission").
  @$pb.TagNumber(5)
  $core.String get action => $_getSZ(4);
  @$pb.TagNumber(5)
  set action($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasAction() => $_has(4);
  @$pb.TagNumber(5)
  void clearAction() => $_clearField(5);

  /// Type of the resource affected (e.g., "partition", "service_account", "setting").
  @$pb.TagNumber(6)
  $core.String get resourceType => $_getSZ(5);
  @$pb.TagNumber(6)
  set resourceType($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasResourceType() => $_has(5);
  @$pb.TagNumber(6)
  void clearResourceType() => $_clearField(6);

  /// Identifier of the affected resource.
  @$pb.TagNumber(7)
  $core.String get resourceId => $_getSZ(6);
  @$pb.TagNumber(7)
  set resourceId($core.String value) => $_setString(6, value);
  @$pb.TagNumber(7)
  $core.bool hasResourceId() => $_has(6);
  @$pb.TagNumber(7)
  void clearResourceId() => $_clearField(7);

  /// Originating service name (e.g., "service_tenancy", "service_profile").
  @$pb.TagNumber(8)
  $core.String get service => $_getSZ(7);
  @$pb.TagNumber(8)
  set service($core.String value) => $_setString(7, value);
  @$pb.TagNumber(8)
  $core.bool hasService() => $_has(7);
  @$pb.TagNumber(8)
  void clearService() => $_clearField(8);

  /// Arbitrary details about the action as structured data.
  @$pb.TagNumber(9)
  $0.Struct get details => $_getN(8);
  @$pb.TagNumber(9)
  set details($0.Struct value) => $_setField(9, value);
  @$pb.TagNumber(9)
  $core.bool hasDetails() => $_has(8);
  @$pb.TagNumber(9)
  void clearDetails() => $_clearField(9);
  @$pb.TagNumber(9)
  $0.Struct ensureDetails() => $_ensure(8);

  /// IP address of the actor.
  @$pb.TagNumber(10)
  $core.String get ipAddress => $_getSZ(9);
  @$pb.TagNumber(10)
  set ipAddress($core.String value) => $_setString(9, value);
  @$pb.TagNumber(10)
  $core.bool hasIpAddress() => $_has(9);
  @$pb.TagNumber(10)
  void clearIpAddress() => $_clearField(10);

  /// User agent string of the actor's client.
  @$pb.TagNumber(11)
  $core.String get userAgent => $_getSZ(10);
  @$pb.TagNumber(11)
  set userAgent($core.String value) => $_setString(10, value);
  @$pb.TagNumber(11)
  $core.bool hasUserAgent() => $_has(10);
  @$pb.TagNumber(11)
  void clearUserAgent() => $_clearField(11);

  /// Device ID from which the action was performed.
  @$pb.TagNumber(12)
  $core.String get deviceId => $_getSZ(11);
  @$pb.TagNumber(12)
  set deviceId($core.String value) => $_setString(11, value);
  @$pb.TagNumber(12)
  $core.bool hasDeviceId() => $_has(11);
  @$pb.TagNumber(12)
  void clearDeviceId() => $_clearField(12);

  /// Profile ID of the target user (if the action affects another user).
  @$pb.TagNumber(13)
  $core.String get targetProfileId => $_getSZ(12);
  @$pb.TagNumber(13)
  set targetProfileId($core.String value) => $_setString(12, value);
  @$pb.TagNumber(13)
  $core.bool hasTargetProfileId() => $_has(12);
  @$pb.TagNumber(13)
  void clearTargetProfileId() => $_clearField(13);

  /// OpenTelemetry trace ID for request correlation.
  @$pb.TagNumber(14)
  $core.String get traceId => $_getSZ(13);
  @$pb.TagNumber(14)
  set traceId($core.String value) => $_setString(13, value);
  @$pb.TagNumber(14)
  $core.bool hasTraceId() => $_has(13);
  @$pb.TagNumber(14)
  void clearTraceId() => $_clearField(14);

  /// Timestamp when the action occurred.
  @$pb.TagNumber(15)
  $1.Timestamp get createdAt => $_getN(14);
  @$pb.TagNumber(15)
  set createdAt($1.Timestamp value) => $_setField(15, value);
  @$pb.TagNumber(15)
  $core.bool hasCreatedAt() => $_has(14);
  @$pb.TagNumber(15)
  void clearCreatedAt() => $_clearField(15);
  @$pb.TagNumber(15)
  $1.Timestamp ensureCreatedAt() => $_ensure(14);

  /// SHA-256 hash of the previous entry in the chain (tamper-proof integrity).
  @$pb.TagNumber(16)
  $core.String get previousHash => $_getSZ(15);
  @$pb.TagNumber(16)
  set previousHash($core.String value) => $_setString(15, value);
  @$pb.TagNumber(16)
  $core.bool hasPreviousHash() => $_has(15);
  @$pb.TagNumber(16)
  void clearPreviousHash() => $_clearField(16);

  /// SHA-256 hash of this entry's content including the previous hash.
  @$pb.TagNumber(17)
  $core.String get entryHash => $_getSZ(16);
  @$pb.TagNumber(17)
  set entryHash($core.String value) => $_setString(16, value);
  @$pb.TagNumber(17)
  $core.bool hasEntryHash() => $_has(16);
  @$pb.TagNumber(17)
  void clearEntryHash() => $_clearField(17);

  /// Ed25519 digital signature of the entry hash.
  @$pb.TagNumber(18)
  $core.String get signature => $_getSZ(17);
  @$pb.TagNumber(18)
  set signature($core.String value) => $_setString(17, value);
  @$pb.TagNumber(18)
  $core.bool hasSignature() => $_has(17);
  @$pb.TagNumber(18)
  void clearSignature() => $_clearField(18);

  /// Position of this entry in the tenant's chain (1-based, gap-free).
  @$pb.TagNumber(19)
  $fixnum.Int64 get seq => $_getI64(18);
  @$pb.TagNumber(19)
  set seq($fixnum.Int64 value) => $_setInt64(18, value);
  @$pb.TagNumber(19)
  $core.bool hasSeq() => $_has(18);
  @$pb.TagNumber(19)
  void clearSeq() => $_clearField(19);

  /// Identifier of the signing key used for this entry.
  @$pb.TagNumber(20)
  $core.String get keyId => $_getSZ(19);
  @$pb.TagNumber(20)
  set keyId($core.String value) => $_setString(19, value);
  @$pb.TagNumber(20)
  $core.bool hasKeyId() => $_has(19);
  @$pb.TagNumber(20)
  void clearKeyId() => $_clearField(20);

  /// Canonical encoding version used to compute entry_hash (1 = legacy, 2 = length-prefixed).
  @$pb.TagNumber(21)
  $core.int get canonVersion => $_getIZ(20);
  @$pb.TagNumber(21)
  set canonVersion($core.int value) => $_setSignedInt32(20, value);
  @$pb.TagNumber(21)
  $core.bool hasCanonVersion() => $_has(20);
  @$pb.TagNumber(21)
  void clearCanonVersion() => $_clearField(21);

  /// Producer-supplied idempotency key, unique per (tenant, service).
  @$pb.TagNumber(22)
  $core.String get entryId => $_getSZ(21);
  @$pb.TagNumber(22)
  set entryId($core.String value) => $_setString(21, value);
  @$pb.TagNumber(22)
  $core.bool hasEntryId() => $_has(21);
  @$pb.TagNumber(22)
  void clearEntryId() => $_clearField(22);

  /// Service account that submitted the entry (from caller claims).
  @$pb.TagNumber(23)
  $core.String get actorServiceAccountId => $_getSZ(22);
  @$pb.TagNumber(23)
  set actorServiceAccountId($core.String value) => $_setString(22, value);
  @$pb.TagNumber(23)
  $core.bool hasActorServiceAccountId() => $_has(22);
  @$pb.TagNumber(23)
  void clearActorServiceAccountId() => $_clearField(23);

  /// Person on whose behalf an operator or administrator acted.
  @$pb.TagNumber(24)
  $core.String get onBehalfOf => $_getSZ(23);
  @$pb.TagNumber(24)
  set onBehalfOf($core.String value) => $_setString(23, value);
  @$pb.TagNumber(24)
  $core.bool hasOnBehalfOf() => $_has(23);
  @$pb.TagNumber(24)
  void clearOnBehalfOf() => $_clearField(24);

  /// When the action happened at the producer.
  @$pb.TagNumber(25)
  $1.Timestamp get occurredAt => $_getN(24);
  @$pb.TagNumber(25)
  set occurredAt($1.Timestamp value) => $_setField(25, value);
  @$pb.TagNumber(25)
  $core.bool hasOccurredAt() => $_has(24);
  @$pb.TagNumber(25)
  void clearOccurredAt() => $_clearField(25);
  @$pb.TagNumber(25)
  $1.Timestamp ensureOccurredAt() => $_ensure(24);

  /// When the audit service accepted the entry.
  @$pb.TagNumber(26)
  $1.Timestamp get receivedAt => $_getN(25);
  @$pb.TagNumber(26)
  set receivedAt($1.Timestamp value) => $_setField(26, value);
  @$pb.TagNumber(26)
  $core.bool hasReceivedAt() => $_has(25);
  @$pb.TagNumber(26)
  void clearReceivedAt() => $_clearField(26);
  @$pb.TagNumber(26)
  $1.Timestamp ensureReceivedAt() => $_ensure(25);

  /// Correlation identifier across services.
  @$pb.TagNumber(27)
  $core.String get correlationId => $_getSZ(26);
  @$pb.TagNumber(27)
  set correlationId($core.String value) => $_setString(26, value);
  @$pb.TagNumber(27)
  $core.bool hasCorrelationId() => $_has(26);
  @$pb.TagNumber(27)
  void clearCorrelationId() => $_clearField(27);

  /// Domain event identifier this action produced or relates to.
  @$pb.TagNumber(28)
  $core.String get eventId => $_getSZ(27);
  @$pb.TagNumber(28)
  set eventId($core.String value) => $_setString(27, value);
  @$pb.TagNumber(28)
  $core.bool hasEventId() => $_has(27);
  @$pb.TagNumber(28)
  void clearEventId() => $_clearField(28);

  /// Financial intent identifier this action relates to.
  @$pb.TagNumber(29)
  $core.String get intentId => $_getSZ(28);
  @$pb.TagNumber(29)
  set intentId($core.String value) => $_setString(28, value);
  @$pb.TagNumber(29)
  $core.bool hasIntentId() => $_has(28);
  @$pb.TagNumber(29)
  void clearIntentId() => $_clearField(29);

  /// Workflow instance identifier this action relates to.
  @$pb.TagNumber(30)
  $core.String get instanceId => $_getSZ(29);
  @$pb.TagNumber(30)
  set instanceId($core.String value) => $_setString(29, value);
  @$pb.TagNumber(30)
  $core.bool hasInstanceId() => $_has(29);
  @$pb.TagNumber(30)
  void clearInstanceId() => $_clearField(30);

  /// SHA-256 hex of the request payload the person signed.
  @$pb.TagNumber(31)
  $core.String get payloadHash => $_getSZ(30);
  @$pb.TagNumber(31)
  set payloadHash($core.String value) => $_setString(30, value);
  @$pb.TagNumber(31)
  $core.bool hasPayloadHash() => $_has(30);
  @$pb.TagNumber(31)
  void clearPayloadHash() => $_clearField(31);

  /// SHA-256 hex of the authorization evidence record.
  @$pb.TagNumber(32)
  $core.String get authorizationHash => $_getSZ(31);
  @$pb.TagNumber(32)
  set authorizationHash($core.String value) => $_setString(31, value);
  @$pb.TagNumber(32)
  $core.bool hasAuthorizationHash() => $_has(31);
  @$pb.TagNumber(32)
  void clearAuthorizationHash() => $_clearField(32);

  /// SHA-256 hex of the policy in force.
  @$pb.TagNumber(33)
  $core.String get policyHash => $_getSZ(32);
  @$pb.TagNumber(33)
  set policyHash($core.String value) => $_setString(32, value);
  @$pb.TagNumber(33)
  $core.bool hasPolicyHash() => $_has(32);
  @$pb.TagNumber(33)
  void clearPolicyHash() => $_clearField(33);

  /// Device key that signed the request, if any.
  @$pb.TagNumber(34)
  $core.String get deviceKeyId => $_getSZ(33);
  @$pb.TagNumber(34)
  set deviceKeyId($core.String value) => $_setString(33, value);
  @$pb.TagNumber(34)
  $core.bool hasDeviceKeyId() => $_has(33);
  @$pb.TagNumber(34)
  void clearDeviceKeyId() => $_clearField(34);

  /// State transition on the resource.
  @$pb.TagNumber(35)
  $core.String get stateFrom => $_getSZ(34);
  @$pb.TagNumber(35)
  set stateFrom($core.String value) => $_setString(34, value);
  @$pb.TagNumber(35)
  $core.bool hasStateFrom() => $_has(34);
  @$pb.TagNumber(35)
  void clearStateFrom() => $_clearField(35);

  @$pb.TagNumber(36)
  $core.String get stateTo => $_getSZ(35);
  @$pb.TagNumber(36)
  set stateTo($core.String value) => $_setString(35, value);
  @$pb.TagNumber(36)
  $core.bool hasStateTo() => $_has(35);
  @$pb.TagNumber(36)
  void clearStateTo() => $_clearField(36);

  /// Version of the resource after the action.
  @$pb.TagNumber(37)
  $fixnum.Int64 get resourceVersion => $_getI64(36);
  @$pb.TagNumber(37)
  set resourceVersion($fixnum.Int64 value) => $_setInt64(36, value);
  @$pb.TagNumber(37)
  $core.bool hasResourceVersion() => $_has(36);
  @$pb.TagNumber(37)
  void clearResourceVersion() => $_clearField(37);

  /// Relationships created, modified or removed by this action.
  @$pb.TagNumber(38)
  $pb.PbList<AuditRelation> get relations => $_getList(37);

  /// Version of the producer's audit manifest the entry was validated against (0 = none).
  @$pb.TagNumber(39)
  $core.int get manifestVersion => $_getIZ(38);
  @$pb.TagNumber(39)
  set manifestVersion($core.int value) => $_setSignedInt32(38, value);
  @$pb.TagNumber(39)
  $core.bool hasManifestVersion() => $_has(38);
  @$pb.TagNumber(39)
  void clearManifestVersion() => $_clearField(39);

  /// True when the producing service had no registered manifest at acceptance.
  @$pb.TagNumber(40)
  $core.bool get unmanifested => $_getBF(39);
  @$pb.TagNumber(40)
  set unmanifested($core.bool value) => $_setBool(39, value);
  @$pb.TagNumber(40)
  $core.bool hasUnmanifested() => $_has(39);
  @$pb.TagNumber(40)
  void clearUnmanifested() => $_clearField(40);

  /// Intake state of the entry.
  @$pb.TagNumber(41)
  IntakeState get state => $_getN(40);
  @$pb.TagNumber(41)
  set state(IntakeState value) => $_setField(41, value);
  @$pb.TagNumber(41)
  $core.bool hasState() => $_has(40);
  @$pb.TagNumber(41)
  void clearState() => $_clearField(41);

  /// Phase of the command this entry records (GFOS §10.4, K11).
  @$pb.TagNumber(42)
  AuditPhase get phase => $_getN(41);
  @$pb.TagNumber(42)
  set phase(AuditPhase value) => $_setField(42, value);
  @$pb.TagNumber(42)
  $core.bool hasPhase() => $_has(41);
  @$pb.TagNumber(42)
  void clearPhase() => $_clearField(42);

  /// entry_id of the REQUESTED entry this entry is the outcome of.
  @$pb.TagNumber(43)
  $core.String get outcomeOfEntryId => $_getSZ(42);
  @$pb.TagNumber(43)
  set outcomeOfEntryId($core.String value) => $_setString(42, value);
  @$pb.TagNumber(43)
  $core.bool hasOutcomeOfEntryId() => $_has(42);
  @$pb.TagNumber(43)
  void clearOutcomeOfEntryId() => $_clearField(43);

  /// Producer audit class in force for the RPC ("AUDIT_REQUIRED", ...).
  @$pb.TagNumber(44)
  $core.String get auditClass => $_getSZ(43);
  @$pb.TagNumber(44)
  set auditClass($core.String value) => $_setString(43, value);
  @$pb.TagNumber(44)
  $core.bool hasAuditClass() => $_has(43);
  @$pb.TagNumber(44)
  void clearAuditClass() => $_clearField(44);

  /// True when the producer wrote this entry while AUDIT_DEGRADED was
  /// declared and drained it from its local outbox afterwards.
  @$pb.TagNumber(45)
  $core.bool get writtenDuringDegradation => $_getBF(44);
  @$pb.TagNumber(45)
  set writtenDuringDegradation($core.bool value) => $_setBool(44, value);
  @$pb.TagNumber(45)
  $core.bool hasWrittenDuringDegradation() => $_has(44);
  @$pb.TagNumber(45)
  void clearWrittenDuringDegradation() => $_clearField(45);
}

/// AuditRelation is a link between two entities affected by an action.
class AuditRelation extends $pb.GeneratedMessage {
  factory AuditRelation({
    $core.String? parentType,
    $core.String? parentId,
    $core.String? childType,
    $core.String? childId,
    $core.String? action,
  }) {
    final result = AuditRelation._();
    if (parentType != null) result.parentType = parentType;
    if (parentId != null) result.parentId = parentId;
    if (childType != null) result.childType = childType;
    if (childId != null) result.childId = childId;
    if (action != null) result.action = action;
    return result;
  }

  AuditRelation._();

  factory AuditRelation.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AuditRelation()..mergeFromBuffer(data, registry);
  factory AuditRelation.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AuditRelation()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'AuditRelation',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: AuditRelation.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'parentType')
    ..aOS(2, _omitFieldNames ? '' : 'parentId')
    ..aOS(3, _omitFieldNames ? '' : 'childType')
    ..aOS(4, _omitFieldNames ? '' : 'childId')
    ..aOS(5, _omitFieldNames ? '' : 'action')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AuditRelation clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AuditRelation copyWith(void Function(AuditRelation) updates) =>
      super.copyWith((message) => updates(message as AuditRelation))
          as AuditRelation;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use AuditRelation() / AuditRelation.new instead')
  static AuditRelation create() => AuditRelation._();
  static $pb.GeneratedMessage $_createMessage() => AuditRelation._();
  @$core.override
  AuditRelation createEmptyInstance() => AuditRelation._();
  @$core.pragma('dart2js:noInline')
  static AuditRelation getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<AuditRelation>(
          AuditRelation.$_createMessage);
  static AuditRelation? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get parentType => $_getSZ(0);
  @$pb.TagNumber(1)
  set parentType($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasParentType() => $_has(0);
  @$pb.TagNumber(1)
  void clearParentType() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get parentId => $_getSZ(1);
  @$pb.TagNumber(2)
  set parentId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasParentId() => $_has(1);
  @$pb.TagNumber(2)
  void clearParentId() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get childType => $_getSZ(2);
  @$pb.TagNumber(3)
  set childType($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasChildType() => $_has(2);
  @$pb.TagNumber(3)
  void clearChildType() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get childId => $_getSZ(3);
  @$pb.TagNumber(4)
  set childId($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasChildId() => $_has(3);
  @$pb.TagNumber(4)
  void clearChildId() => $_clearField(4);

  /// "added", "removed" or "modified".
  @$pb.TagNumber(5)
  $core.String get action => $_getSZ(4);
  @$pb.TagNumber(5)
  set action($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasAction() => $_has(4);
  @$pb.TagNumber(5)
  void clearAction() => $_clearField(5);
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
    $0.Struct? details,
    $core.String? ipAddress,
    $core.String? userAgent,
    $core.String? deviceId,
    $core.String? targetProfileId,
    $core.String? traceId,
    $core.String? entryId,
    $core.String? onBehalfOf,
    $1.Timestamp? occurredAt,
    $core.String? correlationId,
    $core.String? eventId,
    $core.String? intentId,
    $core.String? instanceId,
    $core.String? payloadHash,
    $core.String? authorizationHash,
    $core.String? policyHash,
    $core.String? deviceKeyId,
    $core.String? stateFrom,
    $core.String? stateTo,
    $fixnum.Int64? resourceVersion,
    $core.Iterable<AuditRelation>? relations,
    AuditPhase? phase,
    $core.String? outcomeOfEntryId,
    $core.String? auditClass,
    $core.bool? writtenDuringDegradation,
  }) {
    final result = CreateAuditEntryRequest._();
    if (profileId != null) result.profileId = profileId;
    if (action != null) result.action = action;
    if (resourceType != null) result.resourceType = resourceType;
    if (resourceId != null) result.resourceId = resourceId;
    if (service != null) result.service = service;
    if (details != null) result.details = details;
    if (ipAddress != null) result.ipAddress = ipAddress;
    if (userAgent != null) result.userAgent = userAgent;
    if (deviceId != null) result.deviceId = deviceId;
    if (targetProfileId != null) result.targetProfileId = targetProfileId;
    if (traceId != null) result.traceId = traceId;
    if (entryId != null) result.entryId = entryId;
    if (onBehalfOf != null) result.onBehalfOf = onBehalfOf;
    if (occurredAt != null) result.occurredAt = occurredAt;
    if (correlationId != null) result.correlationId = correlationId;
    if (eventId != null) result.eventId = eventId;
    if (intentId != null) result.intentId = intentId;
    if (instanceId != null) result.instanceId = instanceId;
    if (payloadHash != null) result.payloadHash = payloadHash;
    if (authorizationHash != null) result.authorizationHash = authorizationHash;
    if (policyHash != null) result.policyHash = policyHash;
    if (deviceKeyId != null) result.deviceKeyId = deviceKeyId;
    if (stateFrom != null) result.stateFrom = stateFrom;
    if (stateTo != null) result.stateTo = stateTo;
    if (resourceVersion != null) result.resourceVersion = resourceVersion;
    if (relations != null) result.relations.addAll(relations);
    if (phase != null) result.phase = phase;
    if (outcomeOfEntryId != null) result.outcomeOfEntryId = outcomeOfEntryId;
    if (auditClass != null) result.auditClass = auditClass;
    if (writtenDuringDegradation != null)
      result.writtenDuringDegradation = writtenDuringDegradation;
    return result;
  }

  CreateAuditEntryRequest._();

  factory CreateAuditEntryRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateAuditEntryRequest()..mergeFromBuffer(data, registry);
  factory CreateAuditEntryRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateAuditEntryRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateAuditEntryRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: CreateAuditEntryRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'profileId')
    ..aOS(2, _omitFieldNames ? '' : 'action')
    ..aOS(3, _omitFieldNames ? '' : 'resourceType')
    ..aOS(4, _omitFieldNames ? '' : 'resourceId')
    ..aOS(5, _omitFieldNames ? '' : 'service')
    ..aOM<$0.Struct>(6, _omitFieldNames ? '' : 'details',
        subBuilder: $0.Struct.$_createMessage)
    ..aOS(7, _omitFieldNames ? '' : 'ipAddress')
    ..aOS(8, _omitFieldNames ? '' : 'userAgent')
    ..aOS(9, _omitFieldNames ? '' : 'deviceId')
    ..aOS(10, _omitFieldNames ? '' : 'targetProfileId')
    ..aOS(11, _omitFieldNames ? '' : 'traceId')
    ..aOS(12, _omitFieldNames ? '' : 'entryId')
    ..aOS(13, _omitFieldNames ? '' : 'onBehalfOf')
    ..aOM<$1.Timestamp>(14, _omitFieldNames ? '' : 'occurredAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOS(15, _omitFieldNames ? '' : 'correlationId')
    ..aOS(16, _omitFieldNames ? '' : 'eventId')
    ..aOS(17, _omitFieldNames ? '' : 'intentId')
    ..aOS(18, _omitFieldNames ? '' : 'instanceId')
    ..aOS(19, _omitFieldNames ? '' : 'payloadHash')
    ..aOS(20, _omitFieldNames ? '' : 'authorizationHash')
    ..aOS(21, _omitFieldNames ? '' : 'policyHash')
    ..aOS(22, _omitFieldNames ? '' : 'deviceKeyId')
    ..aOS(23, _omitFieldNames ? '' : 'stateFrom')
    ..aOS(24, _omitFieldNames ? '' : 'stateTo')
    ..aInt64(25, _omitFieldNames ? '' : 'resourceVersion')
    ..pPM<AuditRelation>(26, _omitFieldNames ? '' : 'relations',
        subBuilder: AuditRelation.$_createMessage)
    ..aE<AuditPhase>(27, _omitFieldNames ? '' : 'phase',
        enumValues: AuditPhase.values)
    ..aOS(28, _omitFieldNames ? '' : 'outcomeOfEntryId')
    ..aOS(29, _omitFieldNames ? '' : 'auditClass')
    ..aOB(30, _omitFieldNames ? '' : 'writtenDuringDegradation')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateAuditEntryRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateAuditEntryRequest copyWith(
          void Function(CreateAuditEntryRequest) updates) =>
      super.copyWith((message) => updates(message as CreateAuditEntryRequest))
          as CreateAuditEntryRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreateAuditEntryRequest() / CreateAuditEntryRequest.new instead')
  static CreateAuditEntryRequest create() => CreateAuditEntryRequest._();
  static $pb.GeneratedMessage $_createMessage() => CreateAuditEntryRequest._();
  @$core.override
  CreateAuditEntryRequest createEmptyInstance() => CreateAuditEntryRequest._();
  @$core.pragma('dart2js:noInline')
  static CreateAuditEntryRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateAuditEntryRequest>(
          CreateAuditEntryRequest.$_createMessage);
  static CreateAuditEntryRequest? _defaultInstance;

  /// Profile ID of the actor. Required.
  @$pb.TagNumber(1)
  $core.String get profileId => $_getSZ(0);
  @$pb.TagNumber(1)
  set profileId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasProfileId() => $_has(0);
  @$pb.TagNumber(1)
  void clearProfileId() => $_clearField(1);

  /// The action performed. Required.
  @$pb.TagNumber(2)
  $core.String get action => $_getSZ(1);
  @$pb.TagNumber(2)
  set action($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasAction() => $_has(1);
  @$pb.TagNumber(2)
  void clearAction() => $_clearField(2);

  /// Type of the resource affected. Required.
  @$pb.TagNumber(3)
  $core.String get resourceType => $_getSZ(2);
  @$pb.TagNumber(3)
  set resourceType($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasResourceType() => $_has(2);
  @$pb.TagNumber(3)
  void clearResourceType() => $_clearField(3);

  /// Identifier of the affected resource.
  @$pb.TagNumber(4)
  $core.String get resourceId => $_getSZ(3);
  @$pb.TagNumber(4)
  set resourceId($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasResourceId() => $_has(3);
  @$pb.TagNumber(4)
  void clearResourceId() => $_clearField(4);

  /// Originating service name. Required.
  @$pb.TagNumber(5)
  $core.String get service => $_getSZ(4);
  @$pb.TagNumber(5)
  set service($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasService() => $_has(4);
  @$pb.TagNumber(5)
  void clearService() => $_clearField(5);

  /// Arbitrary details about the action.
  @$pb.TagNumber(6)
  $0.Struct get details => $_getN(5);
  @$pb.TagNumber(6)
  set details($0.Struct value) => $_setField(6, value);
  @$pb.TagNumber(6)
  $core.bool hasDetails() => $_has(5);
  @$pb.TagNumber(6)
  void clearDetails() => $_clearField(6);
  @$pb.TagNumber(6)
  $0.Struct ensureDetails() => $_ensure(5);

  /// IP address of the actor.
  @$pb.TagNumber(7)
  $core.String get ipAddress => $_getSZ(6);
  @$pb.TagNumber(7)
  set ipAddress($core.String value) => $_setString(6, value);
  @$pb.TagNumber(7)
  $core.bool hasIpAddress() => $_has(6);
  @$pb.TagNumber(7)
  void clearIpAddress() => $_clearField(7);

  /// User agent string.
  @$pb.TagNumber(8)
  $core.String get userAgent => $_getSZ(7);
  @$pb.TagNumber(8)
  set userAgent($core.String value) => $_setString(7, value);
  @$pb.TagNumber(8)
  $core.bool hasUserAgent() => $_has(7);
  @$pb.TagNumber(8)
  void clearUserAgent() => $_clearField(8);

  /// Device ID from which the action was performed.
  @$pb.TagNumber(9)
  $core.String get deviceId => $_getSZ(8);
  @$pb.TagNumber(9)
  set deviceId($core.String value) => $_setString(8, value);
  @$pb.TagNumber(9)
  $core.bool hasDeviceId() => $_has(8);
  @$pb.TagNumber(9)
  void clearDeviceId() => $_clearField(9);

  /// Profile ID of the target user (optional).
  @$pb.TagNumber(10)
  $core.String get targetProfileId => $_getSZ(9);
  @$pb.TagNumber(10)
  set targetProfileId($core.String value) => $_setString(9, value);
  @$pb.TagNumber(10)
  $core.bool hasTargetProfileId() => $_has(9);
  @$pb.TagNumber(10)
  void clearTargetProfileId() => $_clearField(10);

  /// OpenTelemetry trace ID for correlation (optional).
  @$pb.TagNumber(11)
  $core.String get traceId => $_getSZ(10);
  @$pb.TagNumber(11)
  set traceId($core.String value) => $_setString(10, value);
  @$pb.TagNumber(11)
  $core.bool hasTraceId() => $_has(10);
  @$pb.TagNumber(11)
  void clearTraceId() => $_clearField(11);

  /// Idempotency key unique per (tenant, service). Generated server-side when empty.
  @$pb.TagNumber(12)
  $core.String get entryId => $_getSZ(11);
  @$pb.TagNumber(12)
  set entryId($core.String value) => $_setString(11, value);
  @$pb.TagNumber(12)
  $core.bool hasEntryId() => $_has(11);
  @$pb.TagNumber(12)
  void clearEntryId() => $_clearField(12);

  /// Person on whose behalf an operator or administrator acts (optional).
  @$pb.TagNumber(13)
  $core.String get onBehalfOf => $_getSZ(12);
  @$pb.TagNumber(13)
  set onBehalfOf($core.String value) => $_setString(12, value);
  @$pb.TagNumber(13)
  $core.bool hasOnBehalfOf() => $_has(12);
  @$pb.TagNumber(13)
  void clearOnBehalfOf() => $_clearField(13);

  /// When the action happened at the producer. Defaults to receipt time.
  @$pb.TagNumber(14)
  $1.Timestamp get occurredAt => $_getN(13);
  @$pb.TagNumber(14)
  set occurredAt($1.Timestamp value) => $_setField(14, value);
  @$pb.TagNumber(14)
  $core.bool hasOccurredAt() => $_has(13);
  @$pb.TagNumber(14)
  void clearOccurredAt() => $_clearField(14);
  @$pb.TagNumber(14)
  $1.Timestamp ensureOccurredAt() => $_ensure(13);

  @$pb.TagNumber(15)
  $core.String get correlationId => $_getSZ(14);
  @$pb.TagNumber(15)
  set correlationId($core.String value) => $_setString(14, value);
  @$pb.TagNumber(15)
  $core.bool hasCorrelationId() => $_has(14);
  @$pb.TagNumber(15)
  void clearCorrelationId() => $_clearField(15);

  @$pb.TagNumber(16)
  $core.String get eventId => $_getSZ(15);
  @$pb.TagNumber(16)
  set eventId($core.String value) => $_setString(15, value);
  @$pb.TagNumber(16)
  $core.bool hasEventId() => $_has(15);
  @$pb.TagNumber(16)
  void clearEventId() => $_clearField(16);

  @$pb.TagNumber(17)
  $core.String get intentId => $_getSZ(16);
  @$pb.TagNumber(17)
  set intentId($core.String value) => $_setString(16, value);
  @$pb.TagNumber(17)
  $core.bool hasIntentId() => $_has(16);
  @$pb.TagNumber(17)
  void clearIntentId() => $_clearField(17);

  @$pb.TagNumber(18)
  $core.String get instanceId => $_getSZ(17);
  @$pb.TagNumber(18)
  set instanceId($core.String value) => $_setString(17, value);
  @$pb.TagNumber(18)
  $core.bool hasInstanceId() => $_has(17);
  @$pb.TagNumber(18)
  void clearInstanceId() => $_clearField(18);

  /// 32-byte lowercase hex digests (optional).
  @$pb.TagNumber(19)
  $core.String get payloadHash => $_getSZ(18);
  @$pb.TagNumber(19)
  set payloadHash($core.String value) => $_setString(18, value);
  @$pb.TagNumber(19)
  $core.bool hasPayloadHash() => $_has(18);
  @$pb.TagNumber(19)
  void clearPayloadHash() => $_clearField(19);

  @$pb.TagNumber(20)
  $core.String get authorizationHash => $_getSZ(19);
  @$pb.TagNumber(20)
  set authorizationHash($core.String value) => $_setString(19, value);
  @$pb.TagNumber(20)
  $core.bool hasAuthorizationHash() => $_has(19);
  @$pb.TagNumber(20)
  void clearAuthorizationHash() => $_clearField(20);

  @$pb.TagNumber(21)
  $core.String get policyHash => $_getSZ(20);
  @$pb.TagNumber(21)
  set policyHash($core.String value) => $_setString(20, value);
  @$pb.TagNumber(21)
  $core.bool hasPolicyHash() => $_has(20);
  @$pb.TagNumber(21)
  void clearPolicyHash() => $_clearField(21);

  @$pb.TagNumber(22)
  $core.String get deviceKeyId => $_getSZ(21);
  @$pb.TagNumber(22)
  set deviceKeyId($core.String value) => $_setString(21, value);
  @$pb.TagNumber(22)
  $core.bool hasDeviceKeyId() => $_has(21);
  @$pb.TagNumber(22)
  void clearDeviceKeyId() => $_clearField(22);

  @$pb.TagNumber(23)
  $core.String get stateFrom => $_getSZ(22);
  @$pb.TagNumber(23)
  set stateFrom($core.String value) => $_setString(22, value);
  @$pb.TagNumber(23)
  $core.bool hasStateFrom() => $_has(22);
  @$pb.TagNumber(23)
  void clearStateFrom() => $_clearField(23);

  @$pb.TagNumber(24)
  $core.String get stateTo => $_getSZ(23);
  @$pb.TagNumber(24)
  set stateTo($core.String value) => $_setString(23, value);
  @$pb.TagNumber(24)
  $core.bool hasStateTo() => $_has(23);
  @$pb.TagNumber(24)
  void clearStateTo() => $_clearField(24);

  @$pb.TagNumber(25)
  $fixnum.Int64 get resourceVersion => $_getI64(24);
  @$pb.TagNumber(25)
  set resourceVersion($fixnum.Int64 value) => $_setInt64(24, value);
  @$pb.TagNumber(25)
  $core.bool hasResourceVersion() => $_has(24);
  @$pb.TagNumber(25)
  void clearResourceVersion() => $_clearField(25);

  @$pb.TagNumber(26)
  $pb.PbList<AuditRelation> get relations => $_getList(25);

  /// Phase of the command (GFOS §10.4, K11). When unset the service falls
  /// back to details["phase"] so a producer on the pre-K11 client still
  /// records the phase it already sends.
  @$pb.TagNumber(27)
  AuditPhase get phase => $_getN(26);
  @$pb.TagNumber(27)
  set phase(AuditPhase value) => $_setField(27, value);
  @$pb.TagNumber(27)
  $core.bool hasPhase() => $_has(26);
  @$pb.TagNumber(27)
  void clearPhase() => $_clearField(27);

  /// entry_id of the REQUESTED entry this entry is the outcome of. Required
  /// for a COMPLETED or FAILED outcome of an AUDIT_REQUIRED command; must be
  /// empty on a REQUESTED entry. Falls back to details["linked_entry_id"].
  @$pb.TagNumber(28)
  $core.String get outcomeOfEntryId => $_getSZ(27);
  @$pb.TagNumber(28)
  set outcomeOfEntryId($core.String value) => $_setString(27, value);
  @$pb.TagNumber(28)
  $core.bool hasOutcomeOfEntryId() => $_has(27);
  @$pb.TagNumber(28)
  void clearOutcomeOfEntryId() => $_clearField(28);

  /// Producer audit class of the RPC. Falls back to details["class"].
  @$pb.TagNumber(29)
  $core.String get auditClass => $_getSZ(28);
  @$pb.TagNumber(29)
  set auditClass($core.String value) => $_setString(28, value);
  @$pb.TagNumber(29)
  $core.bool hasAuditClass() => $_has(28);
  @$pb.TagNumber(29)
  void clearAuditClass() => $_clearField(29);

  /// True when the producer is draining an entry it parked locally while
  /// AUDIT_DEGRADED was declared. The entry keeps its original occurred_at
  /// and is recorded as written during degradation.
  @$pb.TagNumber(30)
  $core.bool get writtenDuringDegradation => $_getBF(29);
  @$pb.TagNumber(30)
  set writtenDuringDegradation($core.bool value) => $_setBool(29, value);
  @$pb.TagNumber(30)
  $core.bool hasWrittenDuringDegradation() => $_has(29);
  @$pb.TagNumber(30)
  void clearWrittenDuringDegradation() => $_clearField(30);
}

class CreateAuditEntryResponse extends $pb.GeneratedMessage {
  factory CreateAuditEntryResponse({
    @$core.Deprecated('This field is deprecated.') AuditEntryObject? data,
    $core.String? intakeId,
    $core.String? entryId,
    IntakeState? state,
  }) {
    final result = CreateAuditEntryResponse._();
    if (data != null) result.data = data;
    if (intakeId != null) result.intakeId = intakeId;
    if (entryId != null) result.entryId = entryId;
    if (state != null) result.state = state;
    return result;
  }

  CreateAuditEntryResponse._();

  factory CreateAuditEntryResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateAuditEntryResponse()..mergeFromBuffer(data, registry);
  factory CreateAuditEntryResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      CreateAuditEntryResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CreateAuditEntryResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: CreateAuditEntryResponse.$_createMessage)
    ..aOM<AuditEntryObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: AuditEntryObject.$_createMessage)
    ..aOS(2, _omitFieldNames ? '' : 'intakeId')
    ..aOS(3, _omitFieldNames ? '' : 'entryId')
    ..aE<IntakeState>(4, _omitFieldNames ? '' : 'state',
        enumValues: IntakeState.values)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateAuditEntryResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CreateAuditEntryResponse copyWith(
          void Function(CreateAuditEntryResponse) updates) =>
      super.copyWith((message) => updates(message as CreateAuditEntryResponse))
          as CreateAuditEntryResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use CreateAuditEntryResponse() / CreateAuditEntryResponse.new instead')
  static CreateAuditEntryResponse create() => CreateAuditEntryResponse._();
  static $pb.GeneratedMessage $_createMessage() => CreateAuditEntryResponse._();
  @$core.override
  CreateAuditEntryResponse createEmptyInstance() =>
      CreateAuditEntryResponse._();
  @$core.pragma('dart2js:noInline')
  static CreateAuditEntryResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CreateAuditEntryResponse>(
          CreateAuditEntryResponse.$_createMessage);
  static CreateAuditEntryResponse? _defaultInstance;

  /// Deprecated: v2 returns the intake receipt; the chained entry is available via GetAuditEntry.
  @$core.Deprecated('This field is deprecated.')
  @$pb.TagNumber(1)
  AuditEntryObject get data => $_getN(0);
  @$core.Deprecated('This field is deprecated.')
  @$pb.TagNumber(1)
  set data(AuditEntryObject value) => $_setField(1, value);
  @$core.Deprecated('This field is deprecated.')
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$core.Deprecated('This field is deprecated.')
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$core.Deprecated('This field is deprecated.')
  @$pb.TagNumber(1)
  AuditEntryObject ensureData() => $_ensure(0);

  /// Identifier of the intake row holding the accepted entry.
  @$pb.TagNumber(2)
  $core.String get intakeId => $_getSZ(1);
  @$pb.TagNumber(2)
  set intakeId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasIntakeId() => $_has(1);
  @$pb.TagNumber(2)
  void clearIntakeId() => $_clearField(2);

  /// Idempotency key (echoed or generated).
  @$pb.TagNumber(3)
  $core.String get entryId => $_getSZ(2);
  @$pb.TagNumber(3)
  set entryId($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasEntryId() => $_has(2);
  @$pb.TagNumber(3)
  void clearEntryId() => $_clearField(3);

  /// Always INTAKE_STATE_ACCEPTED on success, or the existing state for a duplicate.
  @$pb.TagNumber(4)
  IntakeState get state => $_getN(3);
  @$pb.TagNumber(4)
  set state(IntakeState value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasState() => $_has(3);
  @$pb.TagNumber(4)
  void clearState() => $_clearField(4);
}

/// BatchCreateAuditEntriesRequest creates multiple audit entries atomically.
class BatchCreateAuditEntriesRequest extends $pb.GeneratedMessage {
  factory BatchCreateAuditEntriesRequest({
    $core.Iterable<CreateAuditEntryRequest>? entries,
  }) {
    final result = BatchCreateAuditEntriesRequest._();
    if (entries != null) result.entries.addAll(entries);
    return result;
  }

  BatchCreateAuditEntriesRequest._();

  factory BatchCreateAuditEntriesRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      BatchCreateAuditEntriesRequest()..mergeFromBuffer(data, registry);
  factory BatchCreateAuditEntriesRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      BatchCreateAuditEntriesRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'BatchCreateAuditEntriesRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: BatchCreateAuditEntriesRequest.$_createMessage)
    ..pPM<CreateAuditEntryRequest>(1, _omitFieldNames ? '' : 'entries',
        subBuilder: CreateAuditEntryRequest.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  BatchCreateAuditEntriesRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  BatchCreateAuditEntriesRequest copyWith(
          void Function(BatchCreateAuditEntriesRequest) updates) =>
      super.copyWith(
              (message) => updates(message as BatchCreateAuditEntriesRequest))
          as BatchCreateAuditEntriesRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use BatchCreateAuditEntriesRequest() / BatchCreateAuditEntriesRequest.new instead')
  static BatchCreateAuditEntriesRequest create() =>
      BatchCreateAuditEntriesRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      BatchCreateAuditEntriesRequest._();
  @$core.override
  BatchCreateAuditEntriesRequest createEmptyInstance() =>
      BatchCreateAuditEntriesRequest._();
  @$core.pragma('dart2js:noInline')
  static BatchCreateAuditEntriesRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<BatchCreateAuditEntriesRequest>(
          BatchCreateAuditEntriesRequest.$_createMessage);
  static BatchCreateAuditEntriesRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<CreateAuditEntryRequest> get entries => $_getList(0);
}

class BatchCreateAuditEntriesResponse extends $pb.GeneratedMessage {
  factory BatchCreateAuditEntriesResponse({
    @$core.Deprecated('This field is deprecated.')
    $core.Iterable<AuditEntryObject>? data,
    $core.Iterable<CreateAuditEntryResponse>? receipts,
  }) {
    final result = BatchCreateAuditEntriesResponse._();
    if (data != null) result.data.addAll(data);
    if (receipts != null) result.receipts.addAll(receipts);
    return result;
  }

  BatchCreateAuditEntriesResponse._();

  factory BatchCreateAuditEntriesResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      BatchCreateAuditEntriesResponse()..mergeFromBuffer(data, registry);
  factory BatchCreateAuditEntriesResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      BatchCreateAuditEntriesResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'BatchCreateAuditEntriesResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: BatchCreateAuditEntriesResponse.$_createMessage)
    ..pPM<AuditEntryObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: AuditEntryObject.$_createMessage)
    ..pPM<CreateAuditEntryResponse>(2, _omitFieldNames ? '' : 'receipts',
        subBuilder: CreateAuditEntryResponse.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  BatchCreateAuditEntriesResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  BatchCreateAuditEntriesResponse copyWith(
          void Function(BatchCreateAuditEntriesResponse) updates) =>
      super.copyWith(
              (message) => updates(message as BatchCreateAuditEntriesResponse))
          as BatchCreateAuditEntriesResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use BatchCreateAuditEntriesResponse() / BatchCreateAuditEntriesResponse.new instead')
  static BatchCreateAuditEntriesResponse create() =>
      BatchCreateAuditEntriesResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      BatchCreateAuditEntriesResponse._();
  @$core.override
  BatchCreateAuditEntriesResponse createEmptyInstance() =>
      BatchCreateAuditEntriesResponse._();
  @$core.pragma('dart2js:noInline')
  static BatchCreateAuditEntriesResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<BatchCreateAuditEntriesResponse>(
          BatchCreateAuditEntriesResponse.$_createMessage);
  static BatchCreateAuditEntriesResponse? _defaultInstance;

  /// Deprecated: see CreateAuditEntryResponse.data.
  @$core.Deprecated('This field is deprecated.')
  @$pb.TagNumber(1)
  $pb.PbList<AuditEntryObject> get data => $_getList(0);

  /// One receipt per request entry, in request order.
  @$pb.TagNumber(2)
  $pb.PbList<CreateAuditEntryResponse> get receipts => $_getList(1);
}

/// GetAuditEntryRequest retrieves a single audit entry by ID.
class GetAuditEntryRequest extends $pb.GeneratedMessage {
  factory GetAuditEntryRequest({
    $core.String? id,
  }) {
    final result = GetAuditEntryRequest._();
    if (id != null) result.id = id;
    return result;
  }

  GetAuditEntryRequest._();

  factory GetAuditEntryRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetAuditEntryRequest()..mergeFromBuffer(data, registry);
  factory GetAuditEntryRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetAuditEntryRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetAuditEntryRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: GetAuditEntryRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetAuditEntryRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetAuditEntryRequest copyWith(void Function(GetAuditEntryRequest) updates) =>
      super.copyWith((message) => updates(message as GetAuditEntryRequest))
          as GetAuditEntryRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetAuditEntryRequest() / GetAuditEntryRequest.new instead')
  static GetAuditEntryRequest create() => GetAuditEntryRequest._();
  static $pb.GeneratedMessage $_createMessage() => GetAuditEntryRequest._();
  @$core.override
  GetAuditEntryRequest createEmptyInstance() => GetAuditEntryRequest._();
  @$core.pragma('dart2js:noInline')
  static GetAuditEntryRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetAuditEntryRequest>(
          GetAuditEntryRequest.$_createMessage);
  static GetAuditEntryRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class GetAuditEntryResponse extends $pb.GeneratedMessage {
  factory GetAuditEntryResponse({
    AuditEntryObject? data,
  }) {
    final result = GetAuditEntryResponse._();
    if (data != null) result.data = data;
    return result;
  }

  GetAuditEntryResponse._();

  factory GetAuditEntryResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetAuditEntryResponse()..mergeFromBuffer(data, registry);
  factory GetAuditEntryResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetAuditEntryResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetAuditEntryResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: GetAuditEntryResponse.$_createMessage)
    ..aOM<AuditEntryObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: AuditEntryObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetAuditEntryResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetAuditEntryResponse copyWith(
          void Function(GetAuditEntryResponse) updates) =>
      super.copyWith((message) => updates(message as GetAuditEntryResponse))
          as GetAuditEntryResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetAuditEntryResponse() / GetAuditEntryResponse.new instead')
  static GetAuditEntryResponse create() => GetAuditEntryResponse._();
  static $pb.GeneratedMessage $_createMessage() => GetAuditEntryResponse._();
  @$core.override
  GetAuditEntryResponse createEmptyInstance() => GetAuditEntryResponse._();
  @$core.pragma('dart2js:noInline')
  static GetAuditEntryResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetAuditEntryResponse>(
          GetAuditEntryResponse.$_createMessage);
  static GetAuditEntryResponse? _defaultInstance;

  @$pb.TagNumber(1)
  AuditEntryObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(AuditEntryObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
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
    $1.Timestamp? startDate,
    $1.Timestamp? endDate,
    $core.int? count,
    $core.String? page,
    $core.String? intentId,
    $core.String? eventId,
    $core.String? correlationId,
    $core.String? onBehalfOf,
    $fixnum.Int64? seqFrom,
    $fixnum.Int64? seqTo,
    AuditPhase? phase,
    $core.bool? withoutOutcome,
    $core.bool? writtenDuringDegradationOnly,
  }) {
    final result = ListAuditEntriesRequest._();
    if (profileId != null) result.profileId = profileId;
    if (action != null) result.action = action;
    if (resourceType != null) result.resourceType = resourceType;
    if (resourceId != null) result.resourceId = resourceId;
    if (service != null) result.service = service;
    if (targetProfileId != null) result.targetProfileId = targetProfileId;
    if (deviceId != null) result.deviceId = deviceId;
    if (startDate != null) result.startDate = startDate;
    if (endDate != null) result.endDate = endDate;
    if (count != null) result.count = count;
    if (page != null) result.page = page;
    if (intentId != null) result.intentId = intentId;
    if (eventId != null) result.eventId = eventId;
    if (correlationId != null) result.correlationId = correlationId;
    if (onBehalfOf != null) result.onBehalfOf = onBehalfOf;
    if (seqFrom != null) result.seqFrom = seqFrom;
    if (seqTo != null) result.seqTo = seqTo;
    if (phase != null) result.phase = phase;
    if (withoutOutcome != null) result.withoutOutcome = withoutOutcome;
    if (writtenDuringDegradationOnly != null)
      result.writtenDuringDegradationOnly = writtenDuringDegradationOnly;
    return result;
  }

  ListAuditEntriesRequest._();

  factory ListAuditEntriesRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListAuditEntriesRequest()..mergeFromBuffer(data, registry);
  factory ListAuditEntriesRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListAuditEntriesRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListAuditEntriesRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: ListAuditEntriesRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'profileId')
    ..aOS(2, _omitFieldNames ? '' : 'action')
    ..aOS(3, _omitFieldNames ? '' : 'resourceType')
    ..aOS(4, _omitFieldNames ? '' : 'resourceId')
    ..aOS(5, _omitFieldNames ? '' : 'service')
    ..aOS(6, _omitFieldNames ? '' : 'targetProfileId')
    ..aOS(7, _omitFieldNames ? '' : 'deviceId')
    ..aOM<$1.Timestamp>(8, _omitFieldNames ? '' : 'startDate',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOM<$1.Timestamp>(9, _omitFieldNames ? '' : 'endDate',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aI(10, _omitFieldNames ? '' : 'count')
    ..aOS(11, _omitFieldNames ? '' : 'page')
    ..aOS(12, _omitFieldNames ? '' : 'intentId')
    ..aOS(13, _omitFieldNames ? '' : 'eventId')
    ..aOS(14, _omitFieldNames ? '' : 'correlationId')
    ..aOS(15, _omitFieldNames ? '' : 'onBehalfOf')
    ..aInt64(16, _omitFieldNames ? '' : 'seqFrom')
    ..aInt64(17, _omitFieldNames ? '' : 'seqTo')
    ..aE<AuditPhase>(18, _omitFieldNames ? '' : 'phase',
        enumValues: AuditPhase.values)
    ..aOB(19, _omitFieldNames ? '' : 'withoutOutcome')
    ..aOB(20, _omitFieldNames ? '' : 'writtenDuringDegradationOnly')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListAuditEntriesRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListAuditEntriesRequest copyWith(
          void Function(ListAuditEntriesRequest) updates) =>
      super.copyWith((message) => updates(message as ListAuditEntriesRequest))
          as ListAuditEntriesRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListAuditEntriesRequest() / ListAuditEntriesRequest.new instead')
  static ListAuditEntriesRequest create() => ListAuditEntriesRequest._();
  static $pb.GeneratedMessage $_createMessage() => ListAuditEntriesRequest._();
  @$core.override
  ListAuditEntriesRequest createEmptyInstance() => ListAuditEntriesRequest._();
  @$core.pragma('dart2js:noInline')
  static ListAuditEntriesRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListAuditEntriesRequest>(
          ListAuditEntriesRequest.$_createMessage);
  static ListAuditEntriesRequest? _defaultInstance;

  /// Filter by profile ID of the actor.
  @$pb.TagNumber(1)
  $core.String get profileId => $_getSZ(0);
  @$pb.TagNumber(1)
  set profileId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasProfileId() => $_has(0);
  @$pb.TagNumber(1)
  void clearProfileId() => $_clearField(1);

  /// Filter by action type.
  @$pb.TagNumber(2)
  $core.String get action => $_getSZ(1);
  @$pb.TagNumber(2)
  set action($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasAction() => $_has(1);
  @$pb.TagNumber(2)
  void clearAction() => $_clearField(2);

  /// Filter by resource type.
  @$pb.TagNumber(3)
  $core.String get resourceType => $_getSZ(2);
  @$pb.TagNumber(3)
  set resourceType($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasResourceType() => $_has(2);
  @$pb.TagNumber(3)
  void clearResourceType() => $_clearField(3);

  /// Filter by resource ID.
  @$pb.TagNumber(4)
  $core.String get resourceId => $_getSZ(3);
  @$pb.TagNumber(4)
  set resourceId($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasResourceId() => $_has(3);
  @$pb.TagNumber(4)
  void clearResourceId() => $_clearField(4);

  /// Filter by originating service.
  @$pb.TagNumber(5)
  $core.String get service => $_getSZ(4);
  @$pb.TagNumber(5)
  set service($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasService() => $_has(4);
  @$pb.TagNumber(5)
  void clearService() => $_clearField(5);

  /// Filter by target profile ID.
  @$pb.TagNumber(6)
  $core.String get targetProfileId => $_getSZ(5);
  @$pb.TagNumber(6)
  set targetProfileId($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasTargetProfileId() => $_has(5);
  @$pb.TagNumber(6)
  void clearTargetProfileId() => $_clearField(6);

  /// Filter by device ID.
  @$pb.TagNumber(7)
  $core.String get deviceId => $_getSZ(6);
  @$pb.TagNumber(7)
  set deviceId($core.String value) => $_setString(6, value);
  @$pb.TagNumber(7)
  $core.bool hasDeviceId() => $_has(6);
  @$pb.TagNumber(7)
  void clearDeviceId() => $_clearField(7);

  /// Filter entries created after this timestamp.
  @$pb.TagNumber(8)
  $1.Timestamp get startDate => $_getN(7);
  @$pb.TagNumber(8)
  set startDate($1.Timestamp value) => $_setField(8, value);
  @$pb.TagNumber(8)
  $core.bool hasStartDate() => $_has(7);
  @$pb.TagNumber(8)
  void clearStartDate() => $_clearField(8);
  @$pb.TagNumber(8)
  $1.Timestamp ensureStartDate() => $_ensure(7);

  /// Filter entries created before this timestamp.
  @$pb.TagNumber(9)
  $1.Timestamp get endDate => $_getN(8);
  @$pb.TagNumber(9)
  set endDate($1.Timestamp value) => $_setField(9, value);
  @$pb.TagNumber(9)
  $core.bool hasEndDate() => $_has(8);
  @$pb.TagNumber(9)
  void clearEndDate() => $_clearField(9);
  @$pb.TagNumber(9)
  $1.Timestamp ensureEndDate() => $_ensure(8);

  /// Maximum number of entries to return per page. Default 50, max 500.
  @$pb.TagNumber(10)
  $core.int get count => $_getIZ(9);
  @$pb.TagNumber(10)
  set count($core.int value) => $_setSignedInt32(9, value);
  @$pb.TagNumber(10)
  $core.bool hasCount() => $_has(9);
  @$pb.TagNumber(10)
  void clearCount() => $_clearField(10);

  /// Pagination cursor (ID of the last entry from previous page).
  @$pb.TagNumber(11)
  $core.String get page => $_getSZ(10);
  @$pb.TagNumber(11)
  set page($core.String value) => $_setString(10, value);
  @$pb.TagNumber(11)
  $core.bool hasPage() => $_has(10);
  @$pb.TagNumber(11)
  void clearPage() => $_clearField(11);

  @$pb.TagNumber(12)
  $core.String get intentId => $_getSZ(11);
  @$pb.TagNumber(12)
  set intentId($core.String value) => $_setString(11, value);
  @$pb.TagNumber(12)
  $core.bool hasIntentId() => $_has(11);
  @$pb.TagNumber(12)
  void clearIntentId() => $_clearField(12);

  @$pb.TagNumber(13)
  $core.String get eventId => $_getSZ(12);
  @$pb.TagNumber(13)
  set eventId($core.String value) => $_setString(12, value);
  @$pb.TagNumber(13)
  $core.bool hasEventId() => $_has(12);
  @$pb.TagNumber(13)
  void clearEventId() => $_clearField(13);

  @$pb.TagNumber(14)
  $core.String get correlationId => $_getSZ(13);
  @$pb.TagNumber(14)
  set correlationId($core.String value) => $_setString(13, value);
  @$pb.TagNumber(14)
  $core.bool hasCorrelationId() => $_has(13);
  @$pb.TagNumber(14)
  void clearCorrelationId() => $_clearField(14);

  @$pb.TagNumber(15)
  $core.String get onBehalfOf => $_getSZ(14);
  @$pb.TagNumber(15)
  set onBehalfOf($core.String value) => $_setString(14, value);
  @$pb.TagNumber(15)
  $core.bool hasOnBehalfOf() => $_has(14);
  @$pb.TagNumber(15)
  void clearOnBehalfOf() => $_clearField(15);

  /// Sequence range filters. When either is set, results are ordered by seq ascending.
  @$pb.TagNumber(16)
  $fixnum.Int64 get seqFrom => $_getI64(15);
  @$pb.TagNumber(16)
  set seqFrom($fixnum.Int64 value) => $_setInt64(15, value);
  @$pb.TagNumber(16)
  $core.bool hasSeqFrom() => $_has(15);
  @$pb.TagNumber(16)
  void clearSeqFrom() => $_clearField(16);

  @$pb.TagNumber(17)
  $fixnum.Int64 get seqTo => $_getI64(16);
  @$pb.TagNumber(17)
  set seqTo($fixnum.Int64 value) => $_setInt64(16, value);
  @$pb.TagNumber(17)
  $core.bool hasSeqTo() => $_has(16);
  @$pb.TagNumber(17)
  void clearSeqTo() => $_clearField(17);

  /// Filter by phase (GFOS §10.4, K11).
  @$pb.TagNumber(18)
  AuditPhase get phase => $_getN(17);
  @$pb.TagNumber(18)
  set phase(AuditPhase value) => $_setField(18, value);
  @$pb.TagNumber(18)
  $core.bool hasPhase() => $_has(17);
  @$pb.TagNumber(18)
  void clearPhase() => $_clearField(18);

  /// Return only REQUESTED entries that carry no linked outcome, i.e. the
  /// commands that read as "asked, not done".
  @$pb.TagNumber(19)
  $core.bool get withoutOutcome => $_getBF(18);
  @$pb.TagNumber(19)
  set withoutOutcome($core.bool value) => $_setBool(18, value);
  @$pb.TagNumber(19)
  $core.bool hasWithoutOutcome() => $_has(18);
  @$pb.TagNumber(19)
  void clearWithoutOutcome() => $_clearField(19);

  /// Filter by entries written while AUDIT_DEGRADED was declared.
  @$pb.TagNumber(20)
  $core.bool get writtenDuringDegradationOnly => $_getBF(19);
  @$pb.TagNumber(20)
  set writtenDuringDegradationOnly($core.bool value) => $_setBool(19, value);
  @$pb.TagNumber(20)
  $core.bool hasWrittenDuringDegradationOnly() => $_has(19);
  @$pb.TagNumber(20)
  void clearWrittenDuringDegradationOnly() => $_clearField(20);
}

class ListAuditEntriesResponse extends $pb.GeneratedMessage {
  factory ListAuditEntriesResponse({
    $core.Iterable<AuditEntryObject>? data,
  }) {
    final result = ListAuditEntriesResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  ListAuditEntriesResponse._();

  factory ListAuditEntriesResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListAuditEntriesResponse()..mergeFromBuffer(data, registry);
  factory ListAuditEntriesResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListAuditEntriesResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListAuditEntriesResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: ListAuditEntriesResponse.$_createMessage)
    ..pPM<AuditEntryObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: AuditEntryObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListAuditEntriesResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListAuditEntriesResponse copyWith(
          void Function(ListAuditEntriesResponse) updates) =>
      super.copyWith((message) => updates(message as ListAuditEntriesResponse))
          as ListAuditEntriesResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListAuditEntriesResponse() / ListAuditEntriesResponse.new instead')
  static ListAuditEntriesResponse create() => ListAuditEntriesResponse._();
  static $pb.GeneratedMessage $_createMessage() => ListAuditEntriesResponse._();
  @$core.override
  ListAuditEntriesResponse createEmptyInstance() =>
      ListAuditEntriesResponse._();
  @$core.pragma('dart2js:noInline')
  static ListAuditEntriesResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListAuditEntriesResponse>(
          ListAuditEntriesResponse.$_createMessage);
  static ListAuditEntriesResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<AuditEntryObject> get data => $_getList(0);
}

/// SearchAuditEntriesRequest provides free-text search across audit entries.
class SearchAuditEntriesRequest extends $pb.GeneratedMessage {
  factory SearchAuditEntriesRequest({
    $core.String? query,
    $1.Timestamp? startDate,
    $1.Timestamp? endDate,
    $core.int? count,
    $core.String? page,
  }) {
    final result = SearchAuditEntriesRequest._();
    if (query != null) result.query = query;
    if (startDate != null) result.startDate = startDate;
    if (endDate != null) result.endDate = endDate;
    if (count != null) result.count = count;
    if (page != null) result.page = page;
    return result;
  }

  SearchAuditEntriesRequest._();

  factory SearchAuditEntriesRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      SearchAuditEntriesRequest()..mergeFromBuffer(data, registry);
  factory SearchAuditEntriesRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      SearchAuditEntriesRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SearchAuditEntriesRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: SearchAuditEntriesRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'query')
    ..aOM<$1.Timestamp>(2, _omitFieldNames ? '' : 'startDate',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOM<$1.Timestamp>(3, _omitFieldNames ? '' : 'endDate',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aI(4, _omitFieldNames ? '' : 'count')
    ..aOS(5, _omitFieldNames ? '' : 'page')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SearchAuditEntriesRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SearchAuditEntriesRequest copyWith(
          void Function(SearchAuditEntriesRequest) updates) =>
      super.copyWith((message) => updates(message as SearchAuditEntriesRequest))
          as SearchAuditEntriesRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use SearchAuditEntriesRequest() / SearchAuditEntriesRequest.new instead')
  static SearchAuditEntriesRequest create() => SearchAuditEntriesRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      SearchAuditEntriesRequest._();
  @$core.override
  SearchAuditEntriesRequest createEmptyInstance() =>
      SearchAuditEntriesRequest._();
  @$core.pragma('dart2js:noInline')
  static SearchAuditEntriesRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SearchAuditEntriesRequest>(
          SearchAuditEntriesRequest.$_createMessage);
  static SearchAuditEntriesRequest? _defaultInstance;

  /// Free-text search query matching action, resource_type, resource_id, or details.
  @$pb.TagNumber(1)
  $core.String get query => $_getSZ(0);
  @$pb.TagNumber(1)
  set query($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasQuery() => $_has(0);
  @$pb.TagNumber(1)
  void clearQuery() => $_clearField(1);

  /// Filter entries created after this timestamp.
  @$pb.TagNumber(2)
  $1.Timestamp get startDate => $_getN(1);
  @$pb.TagNumber(2)
  set startDate($1.Timestamp value) => $_setField(2, value);
  @$pb.TagNumber(2)
  $core.bool hasStartDate() => $_has(1);
  @$pb.TagNumber(2)
  void clearStartDate() => $_clearField(2);
  @$pb.TagNumber(2)
  $1.Timestamp ensureStartDate() => $_ensure(1);

  /// Filter entries created before this timestamp.
  @$pb.TagNumber(3)
  $1.Timestamp get endDate => $_getN(2);
  @$pb.TagNumber(3)
  set endDate($1.Timestamp value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasEndDate() => $_has(2);
  @$pb.TagNumber(3)
  void clearEndDate() => $_clearField(3);
  @$pb.TagNumber(3)
  $1.Timestamp ensureEndDate() => $_ensure(2);

  /// Maximum number of entries to return per page. Default 50, max 500.
  @$pb.TagNumber(4)
  $core.int get count => $_getIZ(3);
  @$pb.TagNumber(4)
  set count($core.int value) => $_setSignedInt32(3, value);
  @$pb.TagNumber(4)
  $core.bool hasCount() => $_has(3);
  @$pb.TagNumber(4)
  void clearCount() => $_clearField(4);

  /// Pagination cursor.
  @$pb.TagNumber(5)
  $core.String get page => $_getSZ(4);
  @$pb.TagNumber(5)
  set page($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasPage() => $_has(4);
  @$pb.TagNumber(5)
  void clearPage() => $_clearField(5);
}

class SearchAuditEntriesResponse extends $pb.GeneratedMessage {
  factory SearchAuditEntriesResponse({
    $core.Iterable<AuditEntryObject>? data,
  }) {
    final result = SearchAuditEntriesResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  SearchAuditEntriesResponse._();

  factory SearchAuditEntriesResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      SearchAuditEntriesResponse()..mergeFromBuffer(data, registry);
  factory SearchAuditEntriesResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      SearchAuditEntriesResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SearchAuditEntriesResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: SearchAuditEntriesResponse.$_createMessage)
    ..pPM<AuditEntryObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: AuditEntryObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SearchAuditEntriesResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SearchAuditEntriesResponse copyWith(
          void Function(SearchAuditEntriesResponse) updates) =>
      super.copyWith(
              (message) => updates(message as SearchAuditEntriesResponse))
          as SearchAuditEntriesResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use SearchAuditEntriesResponse() / SearchAuditEntriesResponse.new instead')
  static SearchAuditEntriesResponse create() => SearchAuditEntriesResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      SearchAuditEntriesResponse._();
  @$core.override
  SearchAuditEntriesResponse createEmptyInstance() =>
      SearchAuditEntriesResponse._();
  @$core.pragma('dart2js:noInline')
  static SearchAuditEntriesResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SearchAuditEntriesResponse>(
          SearchAuditEntriesResponse.$_createMessage);
  static SearchAuditEntriesResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<AuditEntryObject> get data => $_getList(0);
}

/// VerifyIntegrityRequest verifies the hash chain integrity over a sequence range.
/// A date range is accepted as a convenience and resolved to sequence numbers.
class VerifyIntegrityRequest extends $pb.GeneratedMessage {
  factory VerifyIntegrityRequest({
    $1.Timestamp? startDate,
    $1.Timestamp? endDate,
    $fixnum.Int64? startSeq,
    $fixnum.Int64? endSeq,
  }) {
    final result = VerifyIntegrityRequest._();
    if (startDate != null) result.startDate = startDate;
    if (endDate != null) result.endDate = endDate;
    if (startSeq != null) result.startSeq = startSeq;
    if (endSeq != null) result.endSeq = endSeq;
    return result;
  }

  VerifyIntegrityRequest._();

  factory VerifyIntegrityRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      VerifyIntegrityRequest()..mergeFromBuffer(data, registry);
  factory VerifyIntegrityRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      VerifyIntegrityRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'VerifyIntegrityRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: VerifyIntegrityRequest.$_createMessage)
    ..aOM<$1.Timestamp>(1, _omitFieldNames ? '' : 'startDate',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOM<$1.Timestamp>(2, _omitFieldNames ? '' : 'endDate',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aInt64(3, _omitFieldNames ? '' : 'startSeq')
    ..aInt64(4, _omitFieldNames ? '' : 'endSeq')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  VerifyIntegrityRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  VerifyIntegrityRequest copyWith(
          void Function(VerifyIntegrityRequest) updates) =>
      super.copyWith((message) => updates(message as VerifyIntegrityRequest))
          as VerifyIntegrityRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use VerifyIntegrityRequest() / VerifyIntegrityRequest.new instead')
  static VerifyIntegrityRequest create() => VerifyIntegrityRequest._();
  static $pb.GeneratedMessage $_createMessage() => VerifyIntegrityRequest._();
  @$core.override
  VerifyIntegrityRequest createEmptyInstance() => VerifyIntegrityRequest._();
  @$core.pragma('dart2js:noInline')
  static VerifyIntegrityRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<VerifyIntegrityRequest>(
          VerifyIntegrityRequest.$_createMessage);
  static VerifyIntegrityRequest? _defaultInstance;

  /// Start of the time range to verify (resolved to start_seq when start_seq is 0).
  @$pb.TagNumber(1)
  $1.Timestamp get startDate => $_getN(0);
  @$pb.TagNumber(1)
  set startDate($1.Timestamp value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasStartDate() => $_has(0);
  @$pb.TagNumber(1)
  void clearStartDate() => $_clearField(1);
  @$pb.TagNumber(1)
  $1.Timestamp ensureStartDate() => $_ensure(0);

  /// End of the time range to verify (resolved to end_seq when end_seq is 0).
  @$pb.TagNumber(2)
  $1.Timestamp get endDate => $_getN(1);
  @$pb.TagNumber(2)
  set endDate($1.Timestamp value) => $_setField(2, value);
  @$pb.TagNumber(2)
  $core.bool hasEndDate() => $_has(1);
  @$pb.TagNumber(2)
  void clearEndDate() => $_clearField(2);
  @$pb.TagNumber(2)
  $1.Timestamp ensureEndDate() => $_ensure(1);

  /// First sequence number to verify (1 = genesis).
  @$pb.TagNumber(3)
  $fixnum.Int64 get startSeq => $_getI64(2);
  @$pb.TagNumber(3)
  set startSeq($fixnum.Int64 value) => $_setInt64(2, value);
  @$pb.TagNumber(3)
  $core.bool hasStartSeq() => $_has(2);
  @$pb.TagNumber(3)
  void clearStartSeq() => $_clearField(3);

  /// Last sequence number to verify (0 = chain head).
  @$pb.TagNumber(4)
  $fixnum.Int64 get endSeq => $_getI64(3);
  @$pb.TagNumber(4)
  set endSeq($fixnum.Int64 value) => $_setInt64(3, value);
  @$pb.TagNumber(4)
  $core.bool hasEndSeq() => $_has(3);
  @$pb.TagNumber(4)
  void clearEndSeq() => $_clearField(4);
}

/// VerifyIntegrityResponse reports the result of integrity verification.
class VerifyIntegrityResponse extends $pb.GeneratedMessage {
  factory VerifyIntegrityResponse({
    $core.bool? valid,
    $fixnum.Int64? entriesVerified,
    $core.String? firstInvalidEntryId,
    $core.String? message,
    $fixnum.Int64? startCheckpointSeq,
    $fixnum.Int64? endSeq,
    $core.String? endHash,
    $core.Iterable<$core.String>? keyIdsUsed,
    $core.bool? partial,
    $fixnum.Int64? firstInvalidSeq,
  }) {
    final result = VerifyIntegrityResponse._();
    if (valid != null) result.valid = valid;
    if (entriesVerified != null) result.entriesVerified = entriesVerified;
    if (firstInvalidEntryId != null)
      result.firstInvalidEntryId = firstInvalidEntryId;
    if (message != null) result.message = message;
    if (startCheckpointSeq != null)
      result.startCheckpointSeq = startCheckpointSeq;
    if (endSeq != null) result.endSeq = endSeq;
    if (endHash != null) result.endHash = endHash;
    if (keyIdsUsed != null) result.keyIdsUsed.addAll(keyIdsUsed);
    if (partial != null) result.partial = partial;
    if (firstInvalidSeq != null) result.firstInvalidSeq = firstInvalidSeq;
    return result;
  }

  VerifyIntegrityResponse._();

  factory VerifyIntegrityResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      VerifyIntegrityResponse()..mergeFromBuffer(data, registry);
  factory VerifyIntegrityResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      VerifyIntegrityResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'VerifyIntegrityResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: VerifyIntegrityResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'valid')
    ..aInt64(2, _omitFieldNames ? '' : 'entriesVerified')
    ..aOS(3, _omitFieldNames ? '' : 'firstInvalidEntryId')
    ..aOS(4, _omitFieldNames ? '' : 'message')
    ..aInt64(5, _omitFieldNames ? '' : 'startCheckpointSeq')
    ..aInt64(6, _omitFieldNames ? '' : 'endSeq')
    ..aOS(7, _omitFieldNames ? '' : 'endHash')
    ..pPS(8, _omitFieldNames ? '' : 'keyIdsUsed')
    ..aOB(9, _omitFieldNames ? '' : 'partial')
    ..aInt64(10, _omitFieldNames ? '' : 'firstInvalidSeq')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  VerifyIntegrityResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  VerifyIntegrityResponse copyWith(
          void Function(VerifyIntegrityResponse) updates) =>
      super.copyWith((message) => updates(message as VerifyIntegrityResponse))
          as VerifyIntegrityResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use VerifyIntegrityResponse() / VerifyIntegrityResponse.new instead')
  static VerifyIntegrityResponse create() => VerifyIntegrityResponse._();
  static $pb.GeneratedMessage $_createMessage() => VerifyIntegrityResponse._();
  @$core.override
  VerifyIntegrityResponse createEmptyInstance() => VerifyIntegrityResponse._();
  @$core.pragma('dart2js:noInline')
  static VerifyIntegrityResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<VerifyIntegrityResponse>(
          VerifyIntegrityResponse.$_createMessage);
  static VerifyIntegrityResponse? _defaultInstance;

  /// Whether the hash chain is intact.
  @$pb.TagNumber(1)
  $core.bool get valid => $_getBF(0);
  @$pb.TagNumber(1)
  set valid($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasValid() => $_has(0);
  @$pb.TagNumber(1)
  void clearValid() => $_clearField(1);

  /// Total number of entries verified.
  @$pb.TagNumber(2)
  $fixnum.Int64 get entriesVerified => $_getI64(1);
  @$pb.TagNumber(2)
  set entriesVerified($fixnum.Int64 value) => $_setInt64(1, value);
  @$pb.TagNumber(2)
  $core.bool hasEntriesVerified() => $_has(1);
  @$pb.TagNumber(2)
  void clearEntriesVerified() => $_clearField(2);

  /// ID of the first entry that failed verification (empty if valid).
  @$pb.TagNumber(3)
  $core.String get firstInvalidEntryId => $_getSZ(2);
  @$pb.TagNumber(3)
  set firstInvalidEntryId($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasFirstInvalidEntryId() => $_has(2);
  @$pb.TagNumber(3)
  void clearFirstInvalidEntryId() => $_clearField(3);

  /// Human-readable description of the verification result.
  @$pb.TagNumber(4)
  $core.String get message => $_getSZ(3);
  @$pb.TagNumber(4)
  set message($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasMessage() => $_has(3);
  @$pb.TagNumber(4)
  void clearMessage() => $_clearField(4);

  /// Sequence of the checkpoint verification started from (0 = genesis).
  @$pb.TagNumber(5)
  $fixnum.Int64 get startCheckpointSeq => $_getI64(4);
  @$pb.TagNumber(5)
  set startCheckpointSeq($fixnum.Int64 value) => $_setInt64(4, value);
  @$pb.TagNumber(5)
  $core.bool hasStartCheckpointSeq() => $_has(4);
  @$pb.TagNumber(5)
  void clearStartCheckpointSeq() => $_clearField(5);

  /// Last sequence number verified.
  @$pb.TagNumber(6)
  $fixnum.Int64 get endSeq => $_getI64(5);
  @$pb.TagNumber(6)
  set endSeq($fixnum.Int64 value) => $_setInt64(5, value);
  @$pb.TagNumber(6)
  $core.bool hasEndSeq() => $_has(5);
  @$pb.TagNumber(6)
  void clearEndSeq() => $_clearField(6);

  /// Entry hash at end_seq.
  @$pb.TagNumber(7)
  $core.String get endHash => $_getSZ(6);
  @$pb.TagNumber(7)
  set endHash($core.String value) => $_setString(6, value);
  @$pb.TagNumber(7)
  $core.bool hasEndHash() => $_has(6);
  @$pb.TagNumber(7)
  void clearEndHash() => $_clearField(7);

  /// Signing keys encountered in the range.
  @$pb.TagNumber(8)
  $pb.PbList<$core.String> get keyIdsUsed => $_getList(7);

  /// True when the range exceeded the per-call cap; continue from end_seq + 1.
  @$pb.TagNumber(9)
  $core.bool get partial => $_getBF(8);
  @$pb.TagNumber(9)
  set partial($core.bool value) => $_setBool(8, value);
  @$pb.TagNumber(9)
  $core.bool hasPartial() => $_has(8);
  @$pb.TagNumber(9)
  void clearPartial() => $_clearField(9);

  /// Sequence of the first entry that failed verification (0 if valid).
  @$pb.TagNumber(10)
  $fixnum.Int64 get firstInvalidSeq => $_getI64(9);
  @$pb.TagNumber(10)
  set firstInvalidSeq($fixnum.Int64 value) => $_setInt64(9, value);
  @$pb.TagNumber(10)
  $core.bool hasFirstInvalidSeq() => $_has(9);
  @$pb.TagNumber(10)
  void clearFirstInvalidSeq() => $_clearField(10);
}

class AuditCheckpoint extends $pb.GeneratedMessage {
  factory AuditCheckpoint({
    $core.String? tenantId,
    $fixnum.Int64? seq,
    $core.String? entryHash,
    $core.String? keyId,
    $core.String? signature,
    $1.Timestamp? createdAt,
  }) {
    final result = AuditCheckpoint._();
    if (tenantId != null) result.tenantId = tenantId;
    if (seq != null) result.seq = seq;
    if (entryHash != null) result.entryHash = entryHash;
    if (keyId != null) result.keyId = keyId;
    if (signature != null) result.signature = signature;
    if (createdAt != null) result.createdAt = createdAt;
    return result;
  }

  AuditCheckpoint._();

  factory AuditCheckpoint.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AuditCheckpoint()..mergeFromBuffer(data, registry);
  factory AuditCheckpoint.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AuditCheckpoint()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'AuditCheckpoint',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: AuditCheckpoint.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'tenantId')
    ..aInt64(2, _omitFieldNames ? '' : 'seq')
    ..aOS(3, _omitFieldNames ? '' : 'entryHash')
    ..aOS(4, _omitFieldNames ? '' : 'keyId')
    ..aOS(5, _omitFieldNames ? '' : 'signature')
    ..aOM<$1.Timestamp>(6, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AuditCheckpoint clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AuditCheckpoint copyWith(void Function(AuditCheckpoint) updates) =>
      super.copyWith((message) => updates(message as AuditCheckpoint))
          as AuditCheckpoint;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use AuditCheckpoint() / AuditCheckpoint.new instead')
  static AuditCheckpoint create() => AuditCheckpoint._();
  static $pb.GeneratedMessage $_createMessage() => AuditCheckpoint._();
  @$core.override
  AuditCheckpoint createEmptyInstance() => AuditCheckpoint._();
  @$core.pragma('dart2js:noInline')
  static AuditCheckpoint getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<AuditCheckpoint>(
          AuditCheckpoint.$_createMessage);
  static AuditCheckpoint? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get tenantId => $_getSZ(0);
  @$pb.TagNumber(1)
  set tenantId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasTenantId() => $_has(0);
  @$pb.TagNumber(1)
  void clearTenantId() => $_clearField(1);

  @$pb.TagNumber(2)
  $fixnum.Int64 get seq => $_getI64(1);
  @$pb.TagNumber(2)
  set seq($fixnum.Int64 value) => $_setInt64(1, value);
  @$pb.TagNumber(2)
  $core.bool hasSeq() => $_has(1);
  @$pb.TagNumber(2)
  void clearSeq() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get entryHash => $_getSZ(2);
  @$pb.TagNumber(3)
  set entryHash($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasEntryHash() => $_has(2);
  @$pb.TagNumber(3)
  void clearEntryHash() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get keyId => $_getSZ(3);
  @$pb.TagNumber(4)
  set keyId($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasKeyId() => $_has(3);
  @$pb.TagNumber(4)
  void clearKeyId() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.String get signature => $_getSZ(4);
  @$pb.TagNumber(5)
  set signature($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasSignature() => $_has(4);
  @$pb.TagNumber(5)
  void clearSignature() => $_clearField(5);

  @$pb.TagNumber(6)
  $1.Timestamp get createdAt => $_getN(5);
  @$pb.TagNumber(6)
  set createdAt($1.Timestamp value) => $_setField(6, value);
  @$pb.TagNumber(6)
  $core.bool hasCreatedAt() => $_has(5);
  @$pb.TagNumber(6)
  void clearCreatedAt() => $_clearField(6);
  @$pb.TagNumber(6)
  $1.Timestamp ensureCreatedAt() => $_ensure(5);
}

class SigningKey extends $pb.GeneratedMessage {
  factory SigningKey({
    $core.String? keyId,
    $core.String? algorithm,
    $core.String? publicKey,
    $1.Timestamp? validFrom,
    $1.Timestamp? retiredAt,
  }) {
    final result = SigningKey._();
    if (keyId != null) result.keyId = keyId;
    if (algorithm != null) result.algorithm = algorithm;
    if (publicKey != null) result.publicKey = publicKey;
    if (validFrom != null) result.validFrom = validFrom;
    if (retiredAt != null) result.retiredAt = retiredAt;
    return result;
  }

  SigningKey._();

  factory SigningKey.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      SigningKey()..mergeFromBuffer(data, registry);
  factory SigningKey.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      SigningKey()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SigningKey',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: SigningKey.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'keyId')
    ..aOS(2, _omitFieldNames ? '' : 'algorithm')
    ..aOS(3, _omitFieldNames ? '' : 'publicKey')
    ..aOM<$1.Timestamp>(4, _omitFieldNames ? '' : 'validFrom',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOM<$1.Timestamp>(5, _omitFieldNames ? '' : 'retiredAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SigningKey clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SigningKey copyWith(void Function(SigningKey) updates) =>
      super.copyWith((message) => updates(message as SigningKey)) as SigningKey;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use SigningKey() / SigningKey.new instead')
  static SigningKey create() => SigningKey._();
  static $pb.GeneratedMessage $_createMessage() => SigningKey._();
  @$core.override
  SigningKey createEmptyInstance() => SigningKey._();
  @$core.pragma('dart2js:noInline')
  static SigningKey getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SigningKey>(SigningKey.$_createMessage);
  static SigningKey? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get keyId => $_getSZ(0);
  @$pb.TagNumber(1)
  set keyId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasKeyId() => $_has(0);
  @$pb.TagNumber(1)
  void clearKeyId() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get algorithm => $_getSZ(1);
  @$pb.TagNumber(2)
  set algorithm($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasAlgorithm() => $_has(1);
  @$pb.TagNumber(2)
  void clearAlgorithm() => $_clearField(2);

  /// Hex-encoded public key.
  @$pb.TagNumber(3)
  $core.String get publicKey => $_getSZ(2);
  @$pb.TagNumber(3)
  set publicKey($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasPublicKey() => $_has(2);
  @$pb.TagNumber(3)
  void clearPublicKey() => $_clearField(3);

  @$pb.TagNumber(4)
  $1.Timestamp get validFrom => $_getN(3);
  @$pb.TagNumber(4)
  set validFrom($1.Timestamp value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasValidFrom() => $_has(3);
  @$pb.TagNumber(4)
  void clearValidFrom() => $_clearField(4);
  @$pb.TagNumber(4)
  $1.Timestamp ensureValidFrom() => $_ensure(3);

  @$pb.TagNumber(5)
  $1.Timestamp get retiredAt => $_getN(4);
  @$pb.TagNumber(5)
  set retiredAt($1.Timestamp value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasRetiredAt() => $_has(4);
  @$pb.TagNumber(5)
  void clearRetiredAt() => $_clearField(5);
  @$pb.TagNumber(5)
  $1.Timestamp ensureRetiredAt() => $_ensure(4);
}

class ListCheckpointsRequest extends $pb.GeneratedMessage {
  factory ListCheckpointsRequest({
    $fixnum.Int64? seqFrom,
    $fixnum.Int64? seqTo,
    $core.int? count,
  }) {
    final result = ListCheckpointsRequest._();
    if (seqFrom != null) result.seqFrom = seqFrom;
    if (seqTo != null) result.seqTo = seqTo;
    if (count != null) result.count = count;
    return result;
  }

  ListCheckpointsRequest._();

  factory ListCheckpointsRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListCheckpointsRequest()..mergeFromBuffer(data, registry);
  factory ListCheckpointsRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListCheckpointsRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListCheckpointsRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: ListCheckpointsRequest.$_createMessage)
    ..aInt64(1, _omitFieldNames ? '' : 'seqFrom')
    ..aInt64(2, _omitFieldNames ? '' : 'seqTo')
    ..aI(3, _omitFieldNames ? '' : 'count')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListCheckpointsRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListCheckpointsRequest copyWith(
          void Function(ListCheckpointsRequest) updates) =>
      super.copyWith((message) => updates(message as ListCheckpointsRequest))
          as ListCheckpointsRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListCheckpointsRequest() / ListCheckpointsRequest.new instead')
  static ListCheckpointsRequest create() => ListCheckpointsRequest._();
  static $pb.GeneratedMessage $_createMessage() => ListCheckpointsRequest._();
  @$core.override
  ListCheckpointsRequest createEmptyInstance() => ListCheckpointsRequest._();
  @$core.pragma('dart2js:noInline')
  static ListCheckpointsRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListCheckpointsRequest>(
          ListCheckpointsRequest.$_createMessage);
  static ListCheckpointsRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $fixnum.Int64 get seqFrom => $_getI64(0);
  @$pb.TagNumber(1)
  set seqFrom($fixnum.Int64 value) => $_setInt64(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSeqFrom() => $_has(0);
  @$pb.TagNumber(1)
  void clearSeqFrom() => $_clearField(1);

  @$pb.TagNumber(2)
  $fixnum.Int64 get seqTo => $_getI64(1);
  @$pb.TagNumber(2)
  set seqTo($fixnum.Int64 value) => $_setInt64(1, value);
  @$pb.TagNumber(2)
  $core.bool hasSeqTo() => $_has(1);
  @$pb.TagNumber(2)
  void clearSeqTo() => $_clearField(2);

  /// Default 50, max 500.
  @$pb.TagNumber(3)
  $core.int get count => $_getIZ(2);
  @$pb.TagNumber(3)
  set count($core.int value) => $_setSignedInt32(2, value);
  @$pb.TagNumber(3)
  $core.bool hasCount() => $_has(2);
  @$pb.TagNumber(3)
  void clearCount() => $_clearField(3);
}

class ListCheckpointsResponse extends $pb.GeneratedMessage {
  factory ListCheckpointsResponse({
    $core.Iterable<AuditCheckpoint>? data,
  }) {
    final result = ListCheckpointsResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  ListCheckpointsResponse._();

  factory ListCheckpointsResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListCheckpointsResponse()..mergeFromBuffer(data, registry);
  factory ListCheckpointsResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListCheckpointsResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListCheckpointsResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: ListCheckpointsResponse.$_createMessage)
    ..pPM<AuditCheckpoint>(1, _omitFieldNames ? '' : 'data',
        subBuilder: AuditCheckpoint.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListCheckpointsResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListCheckpointsResponse copyWith(
          void Function(ListCheckpointsResponse) updates) =>
      super.copyWith((message) => updates(message as ListCheckpointsResponse))
          as ListCheckpointsResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListCheckpointsResponse() / ListCheckpointsResponse.new instead')
  static ListCheckpointsResponse create() => ListCheckpointsResponse._();
  static $pb.GeneratedMessage $_createMessage() => ListCheckpointsResponse._();
  @$core.override
  ListCheckpointsResponse createEmptyInstance() => ListCheckpointsResponse._();
  @$core.pragma('dart2js:noInline')
  static ListCheckpointsResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListCheckpointsResponse>(
          ListCheckpointsResponse.$_createMessage);
  static ListCheckpointsResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<AuditCheckpoint> get data => $_getList(0);
}

class GetSigningKeysRequest extends $pb.GeneratedMessage {
  factory GetSigningKeysRequest() => GetSigningKeysRequest._();

  GetSigningKeysRequest._();

  factory GetSigningKeysRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetSigningKeysRequest()..mergeFromBuffer(data, registry);
  factory GetSigningKeysRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetSigningKeysRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetSigningKeysRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: GetSigningKeysRequest.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetSigningKeysRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetSigningKeysRequest copyWith(
          void Function(GetSigningKeysRequest) updates) =>
      super.copyWith((message) => updates(message as GetSigningKeysRequest))
          as GetSigningKeysRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetSigningKeysRequest() / GetSigningKeysRequest.new instead')
  static GetSigningKeysRequest create() => GetSigningKeysRequest._();
  static $pb.GeneratedMessage $_createMessage() => GetSigningKeysRequest._();
  @$core.override
  GetSigningKeysRequest createEmptyInstance() => GetSigningKeysRequest._();
  @$core.pragma('dart2js:noInline')
  static GetSigningKeysRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetSigningKeysRequest>(
          GetSigningKeysRequest.$_createMessage);
  static GetSigningKeysRequest? _defaultInstance;
}

class GetSigningKeysResponse extends $pb.GeneratedMessage {
  factory GetSigningKeysResponse({
    $core.Iterable<SigningKey>? data,
  }) {
    final result = GetSigningKeysResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  GetSigningKeysResponse._();

  factory GetSigningKeysResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetSigningKeysResponse()..mergeFromBuffer(data, registry);
  factory GetSigningKeysResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetSigningKeysResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetSigningKeysResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: GetSigningKeysResponse.$_createMessage)
    ..pPM<SigningKey>(1, _omitFieldNames ? '' : 'data',
        subBuilder: SigningKey.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetSigningKeysResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetSigningKeysResponse copyWith(
          void Function(GetSigningKeysResponse) updates) =>
      super.copyWith((message) => updates(message as GetSigningKeysResponse))
          as GetSigningKeysResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetSigningKeysResponse() / GetSigningKeysResponse.new instead')
  static GetSigningKeysResponse create() => GetSigningKeysResponse._();
  static $pb.GeneratedMessage $_createMessage() => GetSigningKeysResponse._();
  @$core.override
  GetSigningKeysResponse createEmptyInstance() => GetSigningKeysResponse._();
  @$core.pragma('dart2js:noInline')
  static GetSigningKeysResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetSigningKeysResponse>(
          GetSigningKeysResponse.$_createMessage);
  static GetSigningKeysResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<SigningKey> get data => $_getList(0);
}

/// ExportAuditEntriesRequest streams a verifiable bundle for a sequence range.
class ExportAuditEntriesRequest extends $pb.GeneratedMessage {
  factory ExportAuditEntriesRequest({
    $fixnum.Int64? startSeq,
    $fixnum.Int64? endSeq,
  }) {
    final result = ExportAuditEntriesRequest._();
    if (startSeq != null) result.startSeq = startSeq;
    if (endSeq != null) result.endSeq = endSeq;
    return result;
  }

  ExportAuditEntriesRequest._();

  factory ExportAuditEntriesRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ExportAuditEntriesRequest()..mergeFromBuffer(data, registry);
  factory ExportAuditEntriesRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ExportAuditEntriesRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ExportAuditEntriesRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: ExportAuditEntriesRequest.$_createMessage)
    ..aInt64(1, _omitFieldNames ? '' : 'startSeq')
    ..aInt64(2, _omitFieldNames ? '' : 'endSeq')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ExportAuditEntriesRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ExportAuditEntriesRequest copyWith(
          void Function(ExportAuditEntriesRequest) updates) =>
      super.copyWith((message) => updates(message as ExportAuditEntriesRequest))
          as ExportAuditEntriesRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ExportAuditEntriesRequest() / ExportAuditEntriesRequest.new instead')
  static ExportAuditEntriesRequest create() => ExportAuditEntriesRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      ExportAuditEntriesRequest._();
  @$core.override
  ExportAuditEntriesRequest createEmptyInstance() =>
      ExportAuditEntriesRequest._();
  @$core.pragma('dart2js:noInline')
  static ExportAuditEntriesRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ExportAuditEntriesRequest>(
          ExportAuditEntriesRequest.$_createMessage);
  static ExportAuditEntriesRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $fixnum.Int64 get startSeq => $_getI64(0);
  @$pb.TagNumber(1)
  set startSeq($fixnum.Int64 value) => $_setInt64(0, value);
  @$pb.TagNumber(1)
  $core.bool hasStartSeq() => $_has(0);
  @$pb.TagNumber(1)
  void clearStartSeq() => $_clearField(1);

  @$pb.TagNumber(2)
  $fixnum.Int64 get endSeq => $_getI64(1);
  @$pb.TagNumber(2)
  set endSeq($fixnum.Int64 value) => $_setInt64(1, value);
  @$pb.TagNumber(2)
  $core.bool hasEndSeq() => $_has(1);
  @$pb.TagNumber(2)
  void clearEndSeq() => $_clearField(2);
}

class ExportAuditEntriesResponse_Header extends $pb.GeneratedMessage {
  factory ExportAuditEntriesResponse_Header({
    $core.String? tenantId,
    $fixnum.Int64? startSeq,
    $fixnum.Int64? endSeq,
    AuditCheckpoint? startCheckpoint,
    AuditCheckpoint? endCheckpoint,
    $core.Iterable<SigningKey>? keys,
  }) {
    final result = ExportAuditEntriesResponse_Header._();
    if (tenantId != null) result.tenantId = tenantId;
    if (startSeq != null) result.startSeq = startSeq;
    if (endSeq != null) result.endSeq = endSeq;
    if (startCheckpoint != null) result.startCheckpoint = startCheckpoint;
    if (endCheckpoint != null) result.endCheckpoint = endCheckpoint;
    if (keys != null) result.keys.addAll(keys);
    return result;
  }

  ExportAuditEntriesResponse_Header._();

  factory ExportAuditEntriesResponse_Header.fromBuffer(
          $core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ExportAuditEntriesResponse_Header()..mergeFromBuffer(data, registry);
  factory ExportAuditEntriesResponse_Header.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ExportAuditEntriesResponse_Header()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ExportAuditEntriesResponse.Header',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: ExportAuditEntriesResponse_Header.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'tenantId')
    ..aInt64(2, _omitFieldNames ? '' : 'startSeq')
    ..aInt64(3, _omitFieldNames ? '' : 'endSeq')
    ..aOM<AuditCheckpoint>(4, _omitFieldNames ? '' : 'startCheckpoint',
        subBuilder: AuditCheckpoint.$_createMessage)
    ..aOM<AuditCheckpoint>(5, _omitFieldNames ? '' : 'endCheckpoint',
        subBuilder: AuditCheckpoint.$_createMessage)
    ..pPM<SigningKey>(6, _omitFieldNames ? '' : 'keys',
        subBuilder: SigningKey.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ExportAuditEntriesResponse_Header clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ExportAuditEntriesResponse_Header copyWith(
          void Function(ExportAuditEntriesResponse_Header) updates) =>
      super.copyWith((message) =>
              updates(message as ExportAuditEntriesResponse_Header))
          as ExportAuditEntriesResponse_Header;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ExportAuditEntriesResponse_Header() / ExportAuditEntriesResponse_Header.new instead')
  static ExportAuditEntriesResponse_Header create() =>
      ExportAuditEntriesResponse_Header._();
  static $pb.GeneratedMessage $_createMessage() =>
      ExportAuditEntriesResponse_Header._();
  @$core.override
  ExportAuditEntriesResponse_Header createEmptyInstance() =>
      ExportAuditEntriesResponse_Header._();
  @$core.pragma('dart2js:noInline')
  static ExportAuditEntriesResponse_Header getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ExportAuditEntriesResponse_Header>(
          ExportAuditEntriesResponse_Header.$_createMessage);
  static ExportAuditEntriesResponse_Header? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get tenantId => $_getSZ(0);
  @$pb.TagNumber(1)
  set tenantId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasTenantId() => $_has(0);
  @$pb.TagNumber(1)
  void clearTenantId() => $_clearField(1);

  @$pb.TagNumber(2)
  $fixnum.Int64 get startSeq => $_getI64(1);
  @$pb.TagNumber(2)
  set startSeq($fixnum.Int64 value) => $_setInt64(1, value);
  @$pb.TagNumber(2)
  $core.bool hasStartSeq() => $_has(1);
  @$pb.TagNumber(2)
  void clearStartSeq() => $_clearField(2);

  @$pb.TagNumber(3)
  $fixnum.Int64 get endSeq => $_getI64(2);
  @$pb.TagNumber(3)
  set endSeq($fixnum.Int64 value) => $_setInt64(2, value);
  @$pb.TagNumber(3)
  $core.bool hasEndSeq() => $_has(2);
  @$pb.TagNumber(3)
  void clearEndSeq() => $_clearField(3);

  /// Checkpoint at or before start_seq (absent when starting from genesis).
  @$pb.TagNumber(4)
  AuditCheckpoint get startCheckpoint => $_getN(3);
  @$pb.TagNumber(4)
  set startCheckpoint(AuditCheckpoint value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasStartCheckpoint() => $_has(3);
  @$pb.TagNumber(4)
  void clearStartCheckpoint() => $_clearField(4);
  @$pb.TagNumber(4)
  AuditCheckpoint ensureStartCheckpoint() => $_ensure(3);

  /// Checkpoint at or after end_seq, if any.
  @$pb.TagNumber(5)
  AuditCheckpoint get endCheckpoint => $_getN(4);
  @$pb.TagNumber(5)
  set endCheckpoint(AuditCheckpoint value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasEndCheckpoint() => $_has(4);
  @$pb.TagNumber(5)
  void clearEndCheckpoint() => $_clearField(5);
  @$pb.TagNumber(5)
  AuditCheckpoint ensureEndCheckpoint() => $_ensure(4);

  @$pb.TagNumber(6)
  $pb.PbList<SigningKey> get keys => $_getList(5);
}

enum ExportAuditEntriesResponse_Payload { header, entry, notSet }

/// ExportAuditEntriesResponse: the first message carries the bounding
/// checkpoints and keys; subsequent messages carry entries in seq order.
class ExportAuditEntriesResponse extends $pb.GeneratedMessage {
  factory ExportAuditEntriesResponse({
    ExportAuditEntriesResponse_Header? header,
    AuditEntryObject? entry,
  }) {
    final result = ExportAuditEntriesResponse._();
    if (header != null) result.header = header;
    if (entry != null) result.entry = entry;
    return result;
  }

  ExportAuditEntriesResponse._();

  factory ExportAuditEntriesResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ExportAuditEntriesResponse()..mergeFromBuffer(data, registry);
  factory ExportAuditEntriesResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ExportAuditEntriesResponse()..mergeFromJson(json, registry);

  static const $core.Map<$core.int, ExportAuditEntriesResponse_Payload>
      _ExportAuditEntriesResponse_PayloadByTag = {
    1: ExportAuditEntriesResponse_Payload.header,
    2: ExportAuditEntriesResponse_Payload.entry,
    0: ExportAuditEntriesResponse_Payload.notSet
  };
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ExportAuditEntriesResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: ExportAuditEntriesResponse.$_createMessage)
    ..oo(0, [1, 2])
    ..aOM<ExportAuditEntriesResponse_Header>(1, _omitFieldNames ? '' : 'header',
        subBuilder: ExportAuditEntriesResponse_Header.$_createMessage)
    ..aOM<AuditEntryObject>(2, _omitFieldNames ? '' : 'entry',
        subBuilder: AuditEntryObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ExportAuditEntriesResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ExportAuditEntriesResponse copyWith(
          void Function(ExportAuditEntriesResponse) updates) =>
      super.copyWith(
              (message) => updates(message as ExportAuditEntriesResponse))
          as ExportAuditEntriesResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ExportAuditEntriesResponse() / ExportAuditEntriesResponse.new instead')
  static ExportAuditEntriesResponse create() => ExportAuditEntriesResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      ExportAuditEntriesResponse._();
  @$core.override
  ExportAuditEntriesResponse createEmptyInstance() =>
      ExportAuditEntriesResponse._();
  @$core.pragma('dart2js:noInline')
  static ExportAuditEntriesResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ExportAuditEntriesResponse>(
          ExportAuditEntriesResponse.$_createMessage);
  static ExportAuditEntriesResponse? _defaultInstance;

  @$pb.TagNumber(1)
  @$pb.TagNumber(2)
  ExportAuditEntriesResponse_Payload whichPayload() =>
      _ExportAuditEntriesResponse_PayloadByTag[$_whichOneof(0)]!;
  @$pb.TagNumber(1)
  @$pb.TagNumber(2)
  void clearPayload() => $_clearField($_whichOneof(0));

  @$pb.TagNumber(1)
  ExportAuditEntriesResponse_Header get header => $_getN(0);
  @$pb.TagNumber(1)
  set header(ExportAuditEntriesResponse_Header value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasHeader() => $_has(0);
  @$pb.TagNumber(1)
  void clearHeader() => $_clearField(1);
  @$pb.TagNumber(1)
  ExportAuditEntriesResponse_Header ensureHeader() => $_ensure(0);

  @$pb.TagNumber(2)
  AuditEntryObject get entry => $_getN(1);
  @$pb.TagNumber(2)
  set entry(AuditEntryObject value) => $_setField(2, value);
  @$pb.TagNumber(2)
  $core.bool hasEntry() => $_has(1);
  @$pb.TagNumber(2)
  void clearEntry() => $_clearField(2);
  @$pb.TagNumber(2)
  AuditEntryObject ensureEntry() => $_ensure(1);
}

/// AuditManifest declares a producing service's audit vocabulary.
class AuditManifest extends $pb.GeneratedMessage {
  factory AuditManifest({
    $core.String? service,
    $core.Iterable<$core.String>? actions,
    $core.Iterable<$core.String>? resourceTypes,
    $core.bool? openVocabulary,
    $core.bool? allowBackdating,
    $core.Iterable<$core.String>? extraForbiddenKeys,
  }) {
    final result = AuditManifest._();
    if (service != null) result.service = service;
    if (actions != null) result.actions.addAll(actions);
    if (resourceTypes != null) result.resourceTypes.addAll(resourceTypes);
    if (openVocabulary != null) result.openVocabulary = openVocabulary;
    if (allowBackdating != null) result.allowBackdating = allowBackdating;
    if (extraForbiddenKeys != null)
      result.extraForbiddenKeys.addAll(extraForbiddenKeys);
    return result;
  }

  AuditManifest._();

  factory AuditManifest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AuditManifest()..mergeFromBuffer(data, registry);
  factory AuditManifest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AuditManifest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'AuditManifest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: AuditManifest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'service')
    ..pPS(2, _omitFieldNames ? '' : 'actions')
    ..pPS(3, _omitFieldNames ? '' : 'resourceTypes')
    ..aOB(4, _omitFieldNames ? '' : 'openVocabulary')
    ..aOB(5, _omitFieldNames ? '' : 'allowBackdating')
    ..pPS(6, _omitFieldNames ? '' : 'extraForbiddenKeys')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AuditManifest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AuditManifest copyWith(void Function(AuditManifest) updates) =>
      super.copyWith((message) => updates(message as AuditManifest))
          as AuditManifest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use AuditManifest() / AuditManifest.new instead')
  static AuditManifest create() => AuditManifest._();
  static $pb.GeneratedMessage $_createMessage() => AuditManifest._();
  @$core.override
  AuditManifest createEmptyInstance() => AuditManifest._();
  @$core.pragma('dart2js:noInline')
  static AuditManifest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<AuditManifest>(
          AuditManifest.$_createMessage);
  static AuditManifest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get service => $_getSZ(0);
  @$pb.TagNumber(1)
  set service($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasService() => $_has(0);
  @$pb.TagNumber(1)
  void clearService() => $_clearField(1);

  @$pb.TagNumber(2)
  $pb.PbList<$core.String> get actions => $_getList(1);

  @$pb.TagNumber(3)
  $pb.PbList<$core.String> get resourceTypes => $_getList(2);

  /// Accept any (action, resource_type) pair.
  @$pb.TagNumber(4)
  $core.bool get openVocabulary => $_getBF(3);
  @$pb.TagNumber(4)
  set openVocabulary($core.bool value) => $_setBool(3, value);
  @$pb.TagNumber(4)
  $core.bool hasOpenVocabulary() => $_has(3);
  @$pb.TagNumber(4)
  void clearOpenVocabulary() => $_clearField(4);

  /// Allow occurred_at older than the standard window (outbox replays).
  @$pb.TagNumber(5)
  $core.bool get allowBackdating => $_getBF(4);
  @$pb.TagNumber(5)
  set allowBackdating($core.bool value) => $_setBool(4, value);
  @$pb.TagNumber(5)
  $core.bool hasAllowBackdating() => $_has(4);
  @$pb.TagNumber(5)
  void clearAllowBackdating() => $_clearField(5);

  /// Additional forbidden detail keys (case-insensitive substrings).
  @$pb.TagNumber(6)
  $pb.PbList<$core.String> get extraForbiddenKeys => $_getList(5);
}

class RegisterAuditManifestRequest extends $pb.GeneratedMessage {
  factory RegisterAuditManifestRequest({
    AuditManifest? manifest,
  }) {
    final result = RegisterAuditManifestRequest._();
    if (manifest != null) result.manifest = manifest;
    return result;
  }

  RegisterAuditManifestRequest._();

  factory RegisterAuditManifestRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RegisterAuditManifestRequest()..mergeFromBuffer(data, registry);
  factory RegisterAuditManifestRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RegisterAuditManifestRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RegisterAuditManifestRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: RegisterAuditManifestRequest.$_createMessage)
    ..aOM<AuditManifest>(1, _omitFieldNames ? '' : 'manifest',
        subBuilder: AuditManifest.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RegisterAuditManifestRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RegisterAuditManifestRequest copyWith(
          void Function(RegisterAuditManifestRequest) updates) =>
      super.copyWith(
              (message) => updates(message as RegisterAuditManifestRequest))
          as RegisterAuditManifestRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RegisterAuditManifestRequest() / RegisterAuditManifestRequest.new instead')
  static RegisterAuditManifestRequest create() =>
      RegisterAuditManifestRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      RegisterAuditManifestRequest._();
  @$core.override
  RegisterAuditManifestRequest createEmptyInstance() =>
      RegisterAuditManifestRequest._();
  @$core.pragma('dart2js:noInline')
  static RegisterAuditManifestRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RegisterAuditManifestRequest>(
          RegisterAuditManifestRequest.$_createMessage);
  static RegisterAuditManifestRequest? _defaultInstance;

  @$pb.TagNumber(1)
  AuditManifest get manifest => $_getN(0);
  @$pb.TagNumber(1)
  set manifest(AuditManifest value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasManifest() => $_has(0);
  @$pb.TagNumber(1)
  void clearManifest() => $_clearField(1);
  @$pb.TagNumber(1)
  AuditManifest ensureManifest() => $_ensure(0);
}

class RegisterAuditManifestResponse extends $pb.GeneratedMessage {
  factory RegisterAuditManifestResponse({
    $core.String? service,
    $core.int? version,
    $core.bool? unchanged,
  }) {
    final result = RegisterAuditManifestResponse._();
    if (service != null) result.service = service;
    if (version != null) result.version = version;
    if (unchanged != null) result.unchanged = unchanged;
    return result;
  }

  RegisterAuditManifestResponse._();

  factory RegisterAuditManifestResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RegisterAuditManifestResponse()..mergeFromBuffer(data, registry);
  factory RegisterAuditManifestResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RegisterAuditManifestResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RegisterAuditManifestResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: RegisterAuditManifestResponse.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'service')
    ..aI(2, _omitFieldNames ? '' : 'version')
    ..aOB(3, _omitFieldNames ? '' : 'unchanged')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RegisterAuditManifestResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RegisterAuditManifestResponse copyWith(
          void Function(RegisterAuditManifestResponse) updates) =>
      super.copyWith(
              (message) => updates(message as RegisterAuditManifestResponse))
          as RegisterAuditManifestResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RegisterAuditManifestResponse() / RegisterAuditManifestResponse.new instead')
  static RegisterAuditManifestResponse create() =>
      RegisterAuditManifestResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      RegisterAuditManifestResponse._();
  @$core.override
  RegisterAuditManifestResponse createEmptyInstance() =>
      RegisterAuditManifestResponse._();
  @$core.pragma('dart2js:noInline')
  static RegisterAuditManifestResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RegisterAuditManifestResponse>(
          RegisterAuditManifestResponse.$_createMessage);
  static RegisterAuditManifestResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get service => $_getSZ(0);
  @$pb.TagNumber(1)
  set service($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasService() => $_has(0);
  @$pb.TagNumber(1)
  void clearService() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.int get version => $_getIZ(1);
  @$pb.TagNumber(2)
  set version($core.int value) => $_setSignedInt32(1, value);
  @$pb.TagNumber(2)
  $core.bool hasVersion() => $_has(1);
  @$pb.TagNumber(2)
  void clearVersion() => $_clearField(2);

  /// True when the content matched the latest version and nothing was written.
  @$pb.TagNumber(3)
  $core.bool get unchanged => $_getBF(2);
  @$pb.TagNumber(3)
  set unchanged($core.bool value) => $_setBool(2, value);
  @$pb.TagNumber(3)
  $core.bool hasUnchanged() => $_has(2);
  @$pb.TagNumber(3)
  void clearUnchanged() => $_clearField(3);
}

class GetAuditManifestRequest extends $pb.GeneratedMessage {
  factory GetAuditManifestRequest({
    $core.String? service,
  }) {
    final result = GetAuditManifestRequest._();
    if (service != null) result.service = service;
    return result;
  }

  GetAuditManifestRequest._();

  factory GetAuditManifestRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetAuditManifestRequest()..mergeFromBuffer(data, registry);
  factory GetAuditManifestRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetAuditManifestRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetAuditManifestRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: GetAuditManifestRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'service')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetAuditManifestRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetAuditManifestRequest copyWith(
          void Function(GetAuditManifestRequest) updates) =>
      super.copyWith((message) => updates(message as GetAuditManifestRequest))
          as GetAuditManifestRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetAuditManifestRequest() / GetAuditManifestRequest.new instead')
  static GetAuditManifestRequest create() => GetAuditManifestRequest._();
  static $pb.GeneratedMessage $_createMessage() => GetAuditManifestRequest._();
  @$core.override
  GetAuditManifestRequest createEmptyInstance() => GetAuditManifestRequest._();
  @$core.pragma('dart2js:noInline')
  static GetAuditManifestRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetAuditManifestRequest>(
          GetAuditManifestRequest.$_createMessage);
  static GetAuditManifestRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get service => $_getSZ(0);
  @$pb.TagNumber(1)
  set service($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasService() => $_has(0);
  @$pb.TagNumber(1)
  void clearService() => $_clearField(1);
}

class GetAuditManifestResponse extends $pb.GeneratedMessage {
  factory GetAuditManifestResponse({
    AuditManifest? manifest,
    $core.int? version,
    $1.Timestamp? createdAt,
  }) {
    final result = GetAuditManifestResponse._();
    if (manifest != null) result.manifest = manifest;
    if (version != null) result.version = version;
    if (createdAt != null) result.createdAt = createdAt;
    return result;
  }

  GetAuditManifestResponse._();

  factory GetAuditManifestResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetAuditManifestResponse()..mergeFromBuffer(data, registry);
  factory GetAuditManifestResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetAuditManifestResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetAuditManifestResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: GetAuditManifestResponse.$_createMessage)
    ..aOM<AuditManifest>(1, _omitFieldNames ? '' : 'manifest',
        subBuilder: AuditManifest.$_createMessage)
    ..aI(2, _omitFieldNames ? '' : 'version')
    ..aOM<$1.Timestamp>(3, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetAuditManifestResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetAuditManifestResponse copyWith(
          void Function(GetAuditManifestResponse) updates) =>
      super.copyWith((message) => updates(message as GetAuditManifestResponse))
          as GetAuditManifestResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetAuditManifestResponse() / GetAuditManifestResponse.new instead')
  static GetAuditManifestResponse create() => GetAuditManifestResponse._();
  static $pb.GeneratedMessage $_createMessage() => GetAuditManifestResponse._();
  @$core.override
  GetAuditManifestResponse createEmptyInstance() =>
      GetAuditManifestResponse._();
  @$core.pragma('dart2js:noInline')
  static GetAuditManifestResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetAuditManifestResponse>(
          GetAuditManifestResponse.$_createMessage);
  static GetAuditManifestResponse? _defaultInstance;

  @$pb.TagNumber(1)
  AuditManifest get manifest => $_getN(0);
  @$pb.TagNumber(1)
  set manifest(AuditManifest value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasManifest() => $_has(0);
  @$pb.TagNumber(1)
  void clearManifest() => $_clearField(1);
  @$pb.TagNumber(1)
  AuditManifest ensureManifest() => $_ensure(0);

  @$pb.TagNumber(2)
  $core.int get version => $_getIZ(1);
  @$pb.TagNumber(2)
  set version($core.int value) => $_setSignedInt32(1, value);
  @$pb.TagNumber(2)
  $core.bool hasVersion() => $_has(1);
  @$pb.TagNumber(2)
  void clearVersion() => $_clearField(2);

  @$pb.TagNumber(3)
  $1.Timestamp get createdAt => $_getN(2);
  @$pb.TagNumber(3)
  set createdAt($1.Timestamp value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasCreatedAt() => $_has(2);
  @$pb.TagNumber(3)
  void clearCreatedAt() => $_clearField(3);
  @$pb.TagNumber(3)
  $1.Timestamp ensureCreatedAt() => $_ensure(2);
}

/// RequeueIntakeRequest moves FAILED intake rows back to ACCEPTED.
class RequeueIntakeRequest extends $pb.GeneratedMessage {
  factory RequeueIntakeRequest({
    $core.Iterable<$core.String>? intakeIds,
  }) {
    final result = RequeueIntakeRequest._();
    if (intakeIds != null) result.intakeIds.addAll(intakeIds);
    return result;
  }

  RequeueIntakeRequest._();

  factory RequeueIntakeRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RequeueIntakeRequest()..mergeFromBuffer(data, registry);
  factory RequeueIntakeRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RequeueIntakeRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RequeueIntakeRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: RequeueIntakeRequest.$_createMessage)
    ..pPS(1, _omitFieldNames ? '' : 'intakeIds')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RequeueIntakeRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RequeueIntakeRequest copyWith(void Function(RequeueIntakeRequest) updates) =>
      super.copyWith((message) => updates(message as RequeueIntakeRequest))
          as RequeueIntakeRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RequeueIntakeRequest() / RequeueIntakeRequest.new instead')
  static RequeueIntakeRequest create() => RequeueIntakeRequest._();
  static $pb.GeneratedMessage $_createMessage() => RequeueIntakeRequest._();
  @$core.override
  RequeueIntakeRequest createEmptyInstance() => RequeueIntakeRequest._();
  @$core.pragma('dart2js:noInline')
  static RequeueIntakeRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RequeueIntakeRequest>(
          RequeueIntakeRequest.$_createMessage);
  static RequeueIntakeRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<$core.String> get intakeIds => $_getList(0);
}

class RequeueIntakeResponse extends $pb.GeneratedMessage {
  factory RequeueIntakeResponse({
    $fixnum.Int64? requeued,
  }) {
    final result = RequeueIntakeResponse._();
    if (requeued != null) result.requeued = requeued;
    return result;
  }

  RequeueIntakeResponse._();

  factory RequeueIntakeResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RequeueIntakeResponse()..mergeFromBuffer(data, registry);
  factory RequeueIntakeResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RequeueIntakeResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RequeueIntakeResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: RequeueIntakeResponse.$_createMessage)
    ..aInt64(1, _omitFieldNames ? '' : 'requeued')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RequeueIntakeResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RequeueIntakeResponse copyWith(
          void Function(RequeueIntakeResponse) updates) =>
      super.copyWith((message) => updates(message as RequeueIntakeResponse))
          as RequeueIntakeResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RequeueIntakeResponse() / RequeueIntakeResponse.new instead')
  static RequeueIntakeResponse create() => RequeueIntakeResponse._();
  static $pb.GeneratedMessage $_createMessage() => RequeueIntakeResponse._();
  @$core.override
  RequeueIntakeResponse createEmptyInstance() => RequeueIntakeResponse._();
  @$core.pragma('dart2js:noInline')
  static RequeueIntakeResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RequeueIntakeResponse>(
          RequeueIntakeResponse.$_createMessage);
  static RequeueIntakeResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $fixnum.Int64 get requeued => $_getI64(0);
  @$pb.TagNumber(1)
  set requeued($fixnum.Int64 value) => $_setInt64(0, value);
  @$pb.TagNumber(1)
  $core.bool hasRequeued() => $_has(0);
  @$pb.TagNumber(1)
  void clearRequeued() => $_clearField(1);
}

class RetireSigningKeyRequest extends $pb.GeneratedMessage {
  factory RetireSigningKeyRequest({
    $core.String? keyId,
  }) {
    final result = RetireSigningKeyRequest._();
    if (keyId != null) result.keyId = keyId;
    return result;
  }

  RetireSigningKeyRequest._();

  factory RetireSigningKeyRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RetireSigningKeyRequest()..mergeFromBuffer(data, registry);
  factory RetireSigningKeyRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RetireSigningKeyRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RetireSigningKeyRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: RetireSigningKeyRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'keyId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RetireSigningKeyRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RetireSigningKeyRequest copyWith(
          void Function(RetireSigningKeyRequest) updates) =>
      super.copyWith((message) => updates(message as RetireSigningKeyRequest))
          as RetireSigningKeyRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RetireSigningKeyRequest() / RetireSigningKeyRequest.new instead')
  static RetireSigningKeyRequest create() => RetireSigningKeyRequest._();
  static $pb.GeneratedMessage $_createMessage() => RetireSigningKeyRequest._();
  @$core.override
  RetireSigningKeyRequest createEmptyInstance() => RetireSigningKeyRequest._();
  @$core.pragma('dart2js:noInline')
  static RetireSigningKeyRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RetireSigningKeyRequest>(
          RetireSigningKeyRequest.$_createMessage);
  static RetireSigningKeyRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get keyId => $_getSZ(0);
  @$pb.TagNumber(1)
  set keyId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasKeyId() => $_has(0);
  @$pb.TagNumber(1)
  void clearKeyId() => $_clearField(1);
}

class RetireSigningKeyResponse extends $pb.GeneratedMessage {
  factory RetireSigningKeyResponse({
    SigningKey? key,
  }) {
    final result = RetireSigningKeyResponse._();
    if (key != null) result.key = key;
    return result;
  }

  RetireSigningKeyResponse._();

  factory RetireSigningKeyResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RetireSigningKeyResponse()..mergeFromBuffer(data, registry);
  factory RetireSigningKeyResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      RetireSigningKeyResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RetireSigningKeyResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'audit.v1'),
      createEmptyInstance: RetireSigningKeyResponse.$_createMessage)
    ..aOM<SigningKey>(1, _omitFieldNames ? '' : 'key',
        subBuilder: SigningKey.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RetireSigningKeyResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RetireSigningKeyResponse copyWith(
          void Function(RetireSigningKeyResponse) updates) =>
      super.copyWith((message) => updates(message as RetireSigningKeyResponse))
          as RetireSigningKeyResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use RetireSigningKeyResponse() / RetireSigningKeyResponse.new instead')
  static RetireSigningKeyResponse create() => RetireSigningKeyResponse._();
  static $pb.GeneratedMessage $_createMessage() => RetireSigningKeyResponse._();
  @$core.override
  RetireSigningKeyResponse createEmptyInstance() =>
      RetireSigningKeyResponse._();
  @$core.pragma('dart2js:noInline')
  static RetireSigningKeyResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RetireSigningKeyResponse>(
          RetireSigningKeyResponse.$_createMessage);
  static RetireSigningKeyResponse? _defaultInstance;

  @$pb.TagNumber(1)
  SigningKey get key => $_getN(0);
  @$pb.TagNumber(1)
  set key(SigningKey value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasKey() => $_has(0);
  @$pb.TagNumber(1)
  void clearKey() => $_clearField(1);
  @$pb.TagNumber(1)
  SigningKey ensureKey() => $_ensure(0);
}

/// AuditService provides a tamper-proof, append-only audit trail.
/// All RPCs require authentication via Bearer token.
class AuditServiceApi {
  final $pb.RpcClient _client;

  AuditServiceApi(this._client);

  /// CreateAuditEntry appends a new entry to the audit trail.
  $async.Future<CreateAuditEntryResponse> createAuditEntry(
          $pb.ClientContext? ctx, CreateAuditEntryRequest request) =>
      _client.invoke<CreateAuditEntryResponse>(ctx, 'AuditService',
          'CreateAuditEntry', request, CreateAuditEntryResponse());

  /// BatchCreateAuditEntries appends multiple entries atomically.
  $async.Future<BatchCreateAuditEntriesResponse> batchCreateAuditEntries(
          $pb.ClientContext? ctx, BatchCreateAuditEntriesRequest request) =>
      _client.invoke<BatchCreateAuditEntriesResponse>(
          ctx,
          'AuditService',
          'BatchCreateAuditEntries',
          request,
          BatchCreateAuditEntriesResponse());

  /// GetAuditEntry retrieves a single audit entry by ID.
  $async.Future<GetAuditEntryResponse> getAuditEntry(
          $pb.ClientContext? ctx, GetAuditEntryRequest request) =>
      _client.invoke<GetAuditEntryResponse>(ctx, 'AuditService',
          'GetAuditEntry', request, GetAuditEntryResponse());

  /// ListAuditEntries queries audit entries with filtering and pagination.
  $async.Future<ListAuditEntriesResponse> listAuditEntries(
          $pb.ClientContext? ctx, ListAuditEntriesRequest request) =>
      _client.invoke<ListAuditEntriesResponse>(ctx, 'AuditService',
          'ListAuditEntries', request, ListAuditEntriesResponse());

  /// SearchAuditEntries performs free-text search across audit entries.
  $async.Future<SearchAuditEntriesResponse> searchAuditEntries(
          $pb.ClientContext? ctx, SearchAuditEntriesRequest request) =>
      _client.invoke<SearchAuditEntriesResponse>(ctx, 'AuditService',
          'SearchAuditEntries', request, SearchAuditEntriesResponse());

  /// VerifyIntegrity verifies the hash chain integrity over a sequence range.
  $async.Future<VerifyIntegrityResponse> verifyIntegrity(
          $pb.ClientContext? ctx, VerifyIntegrityRequest request) =>
      _client.invoke<VerifyIntegrityResponse>(ctx, 'AuditService',
          'VerifyIntegrity', request, VerifyIntegrityResponse());

  /// ExportAuditEntries streams entries with bounding checkpoints and keys for offline verification.
  $async.Future<ExportAuditEntriesResponse> exportAuditEntries(
          $pb.ClientContext? ctx, ExportAuditEntriesRequest request) =>
      _client.invoke<ExportAuditEntriesResponse>(ctx, 'AuditService',
          'ExportAuditEntries', request, ExportAuditEntriesResponse());

  /// ListCheckpoints lists signed checkpoints for the caller's tenant.
  $async.Future<ListCheckpointsResponse> listCheckpoints(
          $pb.ClientContext? ctx, ListCheckpointsRequest request) =>
      _client.invoke<ListCheckpointsResponse>(ctx, 'AuditService',
          'ListCheckpoints', request, ListCheckpointsResponse());

  /// GetSigningKeys returns all signing public keys, including retired ones.
  $async.Future<GetSigningKeysResponse> getSigningKeys(
          $pb.ClientContext? ctx, GetSigningKeysRequest request) =>
      _client.invoke<GetSigningKeysResponse>(ctx, 'AuditService',
          'GetSigningKeys', request, GetSigningKeysResponse());

  /// RegisterAuditManifest registers or updates a producing service's audit vocabulary.
  $async.Future<RegisterAuditManifestResponse> registerAuditManifest(
          $pb.ClientContext? ctx, RegisterAuditManifestRequest request) =>
      _client.invoke<RegisterAuditManifestResponse>(ctx, 'AuditService',
          'RegisterAuditManifest', request, RegisterAuditManifestResponse());

  /// GetAuditManifest returns the latest manifest for a service.
  $async.Future<GetAuditManifestResponse> getAuditManifest(
          $pb.ClientContext? ctx, GetAuditManifestRequest request) =>
      _client.invoke<GetAuditManifestResponse>(ctx, 'AuditService',
          'GetAuditManifest', request, GetAuditManifestResponse());

  /// RequeueIntake returns FAILED intake rows to ACCEPTED after operator remediation.
  $async.Future<RequeueIntakeResponse> requeueIntake(
          $pb.ClientContext? ctx, RequeueIntakeRequest request) =>
      _client.invoke<RequeueIntakeResponse>(ctx, 'AuditService',
          'RequeueIntake', request, RequeueIntakeResponse());

  /// RetireSigningKey marks a signing key retired; it keeps verifying but can no longer sign.
  $async.Future<RetireSigningKeyResponse> retireSigningKey(
          $pb.ClientContext? ctx, RetireSigningKeyRequest request) =>
      _client.invoke<RetireSigningKeyResponse>(ctx, 'AuditService',
          'RetireSigningKey', request, RetireSigningKeyResponse());
}

const $core.bool _omitFieldNames =
    $core.bool.fromEnvironment('protobuf.omit_field_names');
const $core.bool _omitMessageNames =
    $core.bool.fromEnvironment('protobuf.omit_message_names');
