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
import 'package:protobuf/well_known_types/google/protobuf/struct.pb.dart' as $0;
import 'package:protobuf/well_known_types/google/protobuf/timestamp.pb.dart'
    as $1;

export 'package:protobuf/protobuf.dart' show GeneratedMessageGenericExtensions;

export 'authentication.pbenum.dart';

/// LoginEventObject represents a single completed authentication event.
class LoginEventObject extends $pb.GeneratedMessage {
  factory LoginEventObject({
    $core.String? id,
    $core.String? tenantId,
    $core.String? partitionId,
    $core.String? profileId,
    $core.String? clientId,
    $core.String? source,
    $core.String? contactId,
    $core.String? deviceId,
    $core.String? ipAddress,
    $core.String? userAgent,
    $core.int? status,
    $0.Struct? properties,
    $1.Timestamp? createdAt,
  }) {
    final result = LoginEventObject._();
    if (id != null) result.id = id;
    if (tenantId != null) result.tenantId = tenantId;
    if (partitionId != null) result.partitionId = partitionId;
    if (profileId != null) result.profileId = profileId;
    if (clientId != null) result.clientId = clientId;
    if (source != null) result.source = source;
    if (contactId != null) result.contactId = contactId;
    if (deviceId != null) result.deviceId = deviceId;
    if (ipAddress != null) result.ipAddress = ipAddress;
    if (userAgent != null) result.userAgent = userAgent;
    if (status != null) result.status = status;
    if (properties != null) result.properties = properties;
    if (createdAt != null) result.createdAt = createdAt;
    return result;
  }

  LoginEventObject._();

  factory LoginEventObject.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      LoginEventObject()..mergeFromBuffer(data, registry);
  factory LoginEventObject.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      LoginEventObject()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'LoginEventObject',
      package:
          const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'),
      createEmptyInstance: LoginEventObject.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aOS(2, _omitFieldNames ? '' : 'tenantId')
    ..aOS(3, _omitFieldNames ? '' : 'partitionId')
    ..aOS(4, _omitFieldNames ? '' : 'profileId')
    ..aOS(5, _omitFieldNames ? '' : 'clientId')
    ..aOS(6, _omitFieldNames ? '' : 'source')
    ..aOS(7, _omitFieldNames ? '' : 'contactId')
    ..aOS(8, _omitFieldNames ? '' : 'deviceId')
    ..aOS(9, _omitFieldNames ? '' : 'ipAddress')
    ..aOS(10, _omitFieldNames ? '' : 'userAgent')
    ..aI(11, _omitFieldNames ? '' : 'status')
    ..aOM<$0.Struct>(12, _omitFieldNames ? '' : 'properties',
        subBuilder: $0.Struct.$_createMessage)
    ..aOM<$1.Timestamp>(13, _omitFieldNames ? '' : 'createdAt',
        subBuilder: $1.Timestamp.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  LoginEventObject clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  LoginEventObject copyWith(void Function(LoginEventObject) updates) =>
      super.copyWith((message) => updates(message as LoginEventObject))
          as LoginEventObject;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use LoginEventObject() / LoginEventObject.new instead')
  static LoginEventObject create() => LoginEventObject._();
  static $pb.GeneratedMessage $_createMessage() => LoginEventObject._();
  @$core.override
  LoginEventObject createEmptyInstance() => LoginEventObject._();
  @$core.pragma('dart2js:noInline')
  static LoginEventObject getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<LoginEventObject>(
          LoginEventObject.$_createMessage);
  static LoginEventObject? _defaultInstance;

  /// Unique identifier for this login event.
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

  /// Profile ID of the user who authenticated.
  @$pb.TagNumber(4)
  $core.String get profileId => $_getSZ(3);
  @$pb.TagNumber(4)
  set profileId($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasProfileId() => $_has(3);
  @$pb.TagNumber(4)
  void clearProfileId() => $_clearField(4);

  /// OAuth2 client ID used for authentication.
  @$pb.TagNumber(5)
  $core.String get clientId => $_getSZ(4);
  @$pb.TagNumber(5)
  set clientId($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasClientId() => $_has(4);
  @$pb.TagNumber(5)
  void clearClientId() => $_clearField(5);

  /// How the user authenticated.
  @$pb.TagNumber(6)
  $core.String get source => $_getSZ(5);
  @$pb.TagNumber(6)
  set source($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasSource() => $_has(5);
  @$pb.TagNumber(6)
  void clearSource() => $_clearField(6);

  /// Contact (email or phone) used for authentication.
  @$pb.TagNumber(7)
  $core.String get contactId => $_getSZ(6);
  @$pb.TagNumber(7)
  set contactId($core.String value) => $_setString(6, value);
  @$pb.TagNumber(7)
  $core.bool hasContactId() => $_has(6);
  @$pb.TagNumber(7)
  void clearContactId() => $_clearField(7);

  /// Device ID from which the authentication occurred.
  @$pb.TagNumber(8)
  $core.String get deviceId => $_getSZ(7);
  @$pb.TagNumber(8)
  set deviceId($core.String value) => $_setString(7, value);
  @$pb.TagNumber(8)
  $core.bool hasDeviceId() => $_has(7);
  @$pb.TagNumber(8)
  void clearDeviceId() => $_clearField(8);

  /// IP address of the authenticating client.
  @$pb.TagNumber(9)
  $core.String get ipAddress => $_getSZ(8);
  @$pb.TagNumber(9)
  set ipAddress($core.String value) => $_setString(8, value);
  @$pb.TagNumber(9)
  $core.bool hasIpAddress() => $_has(8);
  @$pb.TagNumber(9)
  void clearIpAddress() => $_clearField(9);

  /// User agent string of the authenticating client.
  @$pb.TagNumber(10)
  $core.String get userAgent => $_getSZ(9);
  @$pb.TagNumber(10)
  set userAgent($core.String value) => $_setString(9, value);
  @$pb.TagNumber(10)
  $core.bool hasUserAgent() => $_has(9);
  @$pb.TagNumber(10)
  void clearUserAgent() => $_clearField(10);

  /// Login status code (0 = success).
  @$pb.TagNumber(11)
  $core.int get status => $_getIZ(10);
  @$pb.TagNumber(11)
  set status($core.int value) => $_setSignedInt32(10, value);
  @$pb.TagNumber(11)
  $core.bool hasStatus() => $_has(10);
  @$pb.TagNumber(11)
  void clearStatus() => $_clearField(11);

  /// Additional properties as structured data.
  @$pb.TagNumber(12)
  $0.Struct get properties => $_getN(11);
  @$pb.TagNumber(12)
  set properties($0.Struct value) => $_setField(12, value);
  @$pb.TagNumber(12)
  $core.bool hasProperties() => $_has(11);
  @$pb.TagNumber(12)
  void clearProperties() => $_clearField(12);
  @$pb.TagNumber(12)
  $0.Struct ensureProperties() => $_ensure(11);

  /// Timestamp when the login event was created.
  @$pb.TagNumber(13)
  $1.Timestamp get createdAt => $_getN(12);
  @$pb.TagNumber(13)
  set createdAt($1.Timestamp value) => $_setField(13, value);
  @$pb.TagNumber(13)
  $core.bool hasCreatedAt() => $_has(12);
  @$pb.TagNumber(13)
  void clearCreatedAt() => $_clearField(13);
  @$pb.TagNumber(13)
  $1.Timestamp ensureCreatedAt() => $_ensure(12);
}

/// GetLoginEventRequest retrieves a single login event by ID.
class GetLoginEventRequest extends $pb.GeneratedMessage {
  factory GetLoginEventRequest({
    $core.String? id,
  }) {
    final result = GetLoginEventRequest._();
    if (id != null) result.id = id;
    return result;
  }

  GetLoginEventRequest._();

  factory GetLoginEventRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetLoginEventRequest()..mergeFromBuffer(data, registry);
  factory GetLoginEventRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetLoginEventRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetLoginEventRequest',
      package:
          const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'),
      createEmptyInstance: GetLoginEventRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetLoginEventRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetLoginEventRequest copyWith(void Function(GetLoginEventRequest) updates) =>
      super.copyWith((message) => updates(message as GetLoginEventRequest))
          as GetLoginEventRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetLoginEventRequest() / GetLoginEventRequest.new instead')
  static GetLoginEventRequest create() => GetLoginEventRequest._();
  static $pb.GeneratedMessage $_createMessage() => GetLoginEventRequest._();
  @$core.override
  GetLoginEventRequest createEmptyInstance() => GetLoginEventRequest._();
  @$core.pragma('dart2js:noInline')
  static GetLoginEventRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetLoginEventRequest>(
          GetLoginEventRequest.$_createMessage);
  static GetLoginEventRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);
}

class GetLoginEventResponse extends $pb.GeneratedMessage {
  factory GetLoginEventResponse({
    LoginEventObject? data,
  }) {
    final result = GetLoginEventResponse._();
    if (data != null) result.data = data;
    return result;
  }

  GetLoginEventResponse._();

  factory GetLoginEventResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetLoginEventResponse()..mergeFromBuffer(data, registry);
  factory GetLoginEventResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GetLoginEventResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetLoginEventResponse',
      package:
          const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'),
      createEmptyInstance: GetLoginEventResponse.$_createMessage)
    ..aOM<LoginEventObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: LoginEventObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetLoginEventResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetLoginEventResponse copyWith(
          void Function(GetLoginEventResponse) updates) =>
      super.copyWith((message) => updates(message as GetLoginEventResponse))
          as GetLoginEventResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GetLoginEventResponse() / GetLoginEventResponse.new instead')
  static GetLoginEventResponse create() => GetLoginEventResponse._();
  static $pb.GeneratedMessage $_createMessage() => GetLoginEventResponse._();
  @$core.override
  GetLoginEventResponse createEmptyInstance() => GetLoginEventResponse._();
  @$core.pragma('dart2js:noInline')
  static GetLoginEventResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetLoginEventResponse>(
          GetLoginEventResponse.$_createMessage);
  static GetLoginEventResponse? _defaultInstance;

  @$pb.TagNumber(1)
  LoginEventObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(LoginEventObject value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => $_clearField(1);
  @$pb.TagNumber(1)
  LoginEventObject ensureData() => $_ensure(0);
}

/// ListLoginEventsRequest lists login events with filtering and pagination.
class ListLoginEventsRequest extends $pb.GeneratedMessage {
  factory ListLoginEventsRequest({
    $core.String? profileId,
    $core.String? clientId,
    $core.String? source,
    $core.String? deviceId,
    $1.Timestamp? startDate,
    $1.Timestamp? endDate,
    $core.int? count,
    $core.String? page,
  }) {
    final result = ListLoginEventsRequest._();
    if (profileId != null) result.profileId = profileId;
    if (clientId != null) result.clientId = clientId;
    if (source != null) result.source = source;
    if (deviceId != null) result.deviceId = deviceId;
    if (startDate != null) result.startDate = startDate;
    if (endDate != null) result.endDate = endDate;
    if (count != null) result.count = count;
    if (page != null) result.page = page;
    return result;
  }

  ListLoginEventsRequest._();

  factory ListLoginEventsRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListLoginEventsRequest()..mergeFromBuffer(data, registry);
  factory ListLoginEventsRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListLoginEventsRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListLoginEventsRequest',
      package:
          const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'),
      createEmptyInstance: ListLoginEventsRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'profileId')
    ..aOS(2, _omitFieldNames ? '' : 'clientId')
    ..aOS(3, _omitFieldNames ? '' : 'source')
    ..aOS(4, _omitFieldNames ? '' : 'deviceId')
    ..aOM<$1.Timestamp>(5, _omitFieldNames ? '' : 'startDate',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aOM<$1.Timestamp>(6, _omitFieldNames ? '' : 'endDate',
        subBuilder: $1.Timestamp.$_createMessage)
    ..aI(7, _omitFieldNames ? '' : 'count')
    ..aOS(8, _omitFieldNames ? '' : 'page')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListLoginEventsRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListLoginEventsRequest copyWith(
          void Function(ListLoginEventsRequest) updates) =>
      super.copyWith((message) => updates(message as ListLoginEventsRequest))
          as ListLoginEventsRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListLoginEventsRequest() / ListLoginEventsRequest.new instead')
  static ListLoginEventsRequest create() => ListLoginEventsRequest._();
  static $pb.GeneratedMessage $_createMessage() => ListLoginEventsRequest._();
  @$core.override
  ListLoginEventsRequest createEmptyInstance() => ListLoginEventsRequest._();
  @$core.pragma('dart2js:noInline')
  static ListLoginEventsRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListLoginEventsRequest>(
          ListLoginEventsRequest.$_createMessage);
  static ListLoginEventsRequest? _defaultInstance;

  /// Filter by profile ID. Required for non-admin users.
  @$pb.TagNumber(1)
  $core.String get profileId => $_getSZ(0);
  @$pb.TagNumber(1)
  set profileId($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasProfileId() => $_has(0);
  @$pb.TagNumber(1)
  void clearProfileId() => $_clearField(1);

  /// Filter by OAuth2 client ID.
  @$pb.TagNumber(2)
  $core.String get clientId => $_getSZ(1);
  @$pb.TagNumber(2)
  set clientId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasClientId() => $_has(1);
  @$pb.TagNumber(2)
  void clearClientId() => $_clearField(2);

  /// Filter by login source (e.g., "direct", "google").
  @$pb.TagNumber(3)
  $core.String get source => $_getSZ(2);
  @$pb.TagNumber(3)
  set source($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasSource() => $_has(2);
  @$pb.TagNumber(3)
  void clearSource() => $_clearField(3);

  /// Filter by device ID.
  @$pb.TagNumber(4)
  $core.String get deviceId => $_getSZ(3);
  @$pb.TagNumber(4)
  set deviceId($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasDeviceId() => $_has(3);
  @$pb.TagNumber(4)
  void clearDeviceId() => $_clearField(4);

  /// Filter events created after this timestamp.
  @$pb.TagNumber(5)
  $1.Timestamp get startDate => $_getN(4);
  @$pb.TagNumber(5)
  set startDate($1.Timestamp value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasStartDate() => $_has(4);
  @$pb.TagNumber(5)
  void clearStartDate() => $_clearField(5);
  @$pb.TagNumber(5)
  $1.Timestamp ensureStartDate() => $_ensure(4);

  /// Filter events created before this timestamp.
  @$pb.TagNumber(6)
  $1.Timestamp get endDate => $_getN(5);
  @$pb.TagNumber(6)
  set endDate($1.Timestamp value) => $_setField(6, value);
  @$pb.TagNumber(6)
  $core.bool hasEndDate() => $_has(5);
  @$pb.TagNumber(6)
  void clearEndDate() => $_clearField(6);
  @$pb.TagNumber(6)
  $1.Timestamp ensureEndDate() => $_ensure(5);

  /// Maximum number of events per page. Default 50, max 500.
  @$pb.TagNumber(7)
  $core.int get count => $_getIZ(6);
  @$pb.TagNumber(7)
  set count($core.int value) => $_setSignedInt32(6, value);
  @$pb.TagNumber(7)
  $core.bool hasCount() => $_has(6);
  @$pb.TagNumber(7)
  void clearCount() => $_clearField(7);

  /// Pagination cursor (ID of the last event from previous page).
  @$pb.TagNumber(8)
  $core.String get page => $_getSZ(7);
  @$pb.TagNumber(8)
  set page($core.String value) => $_setString(7, value);
  @$pb.TagNumber(8)
  $core.bool hasPage() => $_has(7);
  @$pb.TagNumber(8)
  void clearPage() => $_clearField(8);
}

class ListLoginEventsResponse extends $pb.GeneratedMessage {
  factory ListLoginEventsResponse({
    $core.Iterable<LoginEventObject>? data,
  }) {
    final result = ListLoginEventsResponse._();
    if (data != null) result.data.addAll(data);
    return result;
  }

  ListLoginEventsResponse._();

  factory ListLoginEventsResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListLoginEventsResponse()..mergeFromBuffer(data, registry);
  factory ListLoginEventsResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      ListLoginEventsResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListLoginEventsResponse',
      package:
          const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'),
      createEmptyInstance: ListLoginEventsResponse.$_createMessage)
    ..pPM<LoginEventObject>(1, _omitFieldNames ? '' : 'data',
        subBuilder: LoginEventObject.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListLoginEventsResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListLoginEventsResponse copyWith(
          void Function(ListLoginEventsResponse) updates) =>
      super.copyWith((message) => updates(message as ListLoginEventsResponse))
          as ListLoginEventsResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use ListLoginEventsResponse() / ListLoginEventsResponse.new instead')
  static ListLoginEventsResponse create() => ListLoginEventsResponse._();
  static $pb.GeneratedMessage $_createMessage() => ListLoginEventsResponse._();
  @$core.override
  ListLoginEventsResponse createEmptyInstance() => ListLoginEventsResponse._();
  @$core.pragma('dart2js:noInline')
  static ListLoginEventsResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListLoginEventsResponse>(
          ListLoginEventsResponse.$_createMessage);
  static ListLoginEventsResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<LoginEventObject> get data => $_getList(0);
}

/// GenesisSessionProofClaims is the signed payload of a genesis session proof.
/// The time fields are the exact claim text (RFC 3339 UTC with microseconds)
/// because they are part of the signed binding pre-image.
class GenesisSessionProofClaims extends $pb.GeneratedMessage {
  factory GenesisSessionProofClaims({
    $core.String? version,
    $core.String? keyId,
    $core.String? algorithm,
    $core.String? profileId,
    $core.String? deviceId,
    $core.String? pubkeyHash,
    $core.String? deviceKeyId,
    $core.String? nonce,
    $core.String? issuedAt,
    $core.String? expiresAt,
    $core.String? sessionId,
    $core.String? tenantId,
    $core.String? partitionId,
    $core.String? audience,
  }) {
    final result = GenesisSessionProofClaims._();
    if (version != null) result.version = version;
    if (keyId != null) result.keyId = keyId;
    if (algorithm != null) result.algorithm = algorithm;
    if (profileId != null) result.profileId = profileId;
    if (deviceId != null) result.deviceId = deviceId;
    if (pubkeyHash != null) result.pubkeyHash = pubkeyHash;
    if (deviceKeyId != null) result.deviceKeyId = deviceKeyId;
    if (nonce != null) result.nonce = nonce;
    if (issuedAt != null) result.issuedAt = issuedAt;
    if (expiresAt != null) result.expiresAt = expiresAt;
    if (sessionId != null) result.sessionId = sessionId;
    if (tenantId != null) result.tenantId = tenantId;
    if (partitionId != null) result.partitionId = partitionId;
    if (audience != null) result.audience = audience;
    return result;
  }

  GenesisSessionProofClaims._();

  factory GenesisSessionProofClaims.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GenesisSessionProofClaims()..mergeFromBuffer(data, registry);
  factory GenesisSessionProofClaims.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      GenesisSessionProofClaims()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GenesisSessionProofClaims',
      package:
          const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'),
      createEmptyInstance: GenesisSessionProofClaims.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'version')
    ..aOS(2, _omitFieldNames ? '' : 'keyId')
    ..aOS(3, _omitFieldNames ? '' : 'algorithm')
    ..aOS(4, _omitFieldNames ? '' : 'profileId')
    ..aOS(5, _omitFieldNames ? '' : 'deviceId')
    ..aOS(6, _omitFieldNames ? '' : 'pubkeyHash')
    ..aOS(7, _omitFieldNames ? '' : 'deviceKeyId')
    ..aOS(8, _omitFieldNames ? '' : 'nonce')
    ..aOS(9, _omitFieldNames ? '' : 'issuedAt')
    ..aOS(10, _omitFieldNames ? '' : 'expiresAt')
    ..aOS(11, _omitFieldNames ? '' : 'sessionId')
    ..aOS(12, _omitFieldNames ? '' : 'tenantId')
    ..aOS(13, _omitFieldNames ? '' : 'partitionId')
    ..aOS(14, _omitFieldNames ? '' : 'audience')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GenesisSessionProofClaims clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GenesisSessionProofClaims copyWith(
          void Function(GenesisSessionProofClaims) updates) =>
      super.copyWith((message) => updates(message as GenesisSessionProofClaims))
          as GenesisSessionProofClaims;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use GenesisSessionProofClaims() / GenesisSessionProofClaims.new instead')
  static GenesisSessionProofClaims create() => GenesisSessionProofClaims._();
  static $pb.GeneratedMessage $_createMessage() =>
      GenesisSessionProofClaims._();
  @$core.override
  GenesisSessionProofClaims createEmptyInstance() =>
      GenesisSessionProofClaims._();
  @$core.pragma('dart2js:noInline')
  static GenesisSessionProofClaims getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GenesisSessionProofClaims>(
          GenesisSessionProofClaims.$_createMessage);
  static GenesisSessionProofClaims? _defaultInstance;

  /// Format version ("GSP1").
  @$pb.TagNumber(1)
  $core.String get version => $_getSZ(0);
  @$pb.TagNumber(1)
  set version($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasVersion() => $_has(0);
  @$pb.TagNumber(1)
  void clearVersion() => $_clearField(1);

  /// Signing key id in /.well-known/genesis-session-proof-keys.json.
  @$pb.TagNumber(2)
  $core.String get keyId => $_getSZ(1);
  @$pb.TagNumber(2)
  set keyId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasKeyId() => $_has(1);
  @$pb.TagNumber(2)
  void clearKeyId() => $_clearField(2);

  /// Always "ed25519" for GSP1.
  @$pb.TagNumber(3)
  $core.String get algorithm => $_getSZ(2);
  @$pb.TagNumber(3)
  set algorithm($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasAlgorithm() => $_has(2);
  @$pb.TagNumber(3)
  void clearAlgorithm() => $_clearField(3);

  /// The person the proof is about (JWT sub === profile_id).
  @$pb.TagNumber(4)
  $core.String get profileId => $_getSZ(3);
  @$pb.TagNumber(4)
  set profileId($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasProfileId() => $_has(3);
  @$pb.TagNumber(4)
  void clearProfileId() => $_clearField(4);

  /// The device the live session ran on.
  @$pb.TagNumber(5)
  $core.String get deviceId => $_getSZ(4);
  @$pb.TagNumber(5)
  set deviceId($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasDeviceId() => $_has(4);
  @$pb.TagNumber(5)
  void clearDeviceId() => $_clearField(5);

  /// Lowercase hex hash of the device public key being registered.
  @$pb.TagNumber(6)
  $core.String get pubkeyHash => $_getSZ(5);
  @$pb.TagNumber(6)
  set pubkeyHash($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasPubkeyHash() => $_has(5);
  @$pb.TagNumber(6)
  void clearPubkeyHash() => $_clearField(6);

  /// Devices-service identifier of that key, when known.
  @$pb.TagNumber(7)
  $core.String get deviceKeyId => $_getSZ(6);
  @$pb.TagNumber(7)
  set deviceKeyId($core.String value) => $_setString(6, value);
  @$pb.TagNumber(7)
  $core.bool hasDeviceKeyId() => $_has(6);
  @$pb.TagNumber(7)
  void clearDeviceKeyId() => $_clearField(7);

  /// Single-use nonce.
  @$pb.TagNumber(8)
  $core.String get nonce => $_getSZ(7);
  @$pb.TagNumber(8)
  set nonce($core.String value) => $_setString(7, value);
  @$pb.TagNumber(8)
  $core.bool hasNonce() => $_has(7);
  @$pb.TagNumber(8)
  void clearNonce() => $_clearField(8);

  @$pb.TagNumber(9)
  $core.String get issuedAt => $_getSZ(8);
  @$pb.TagNumber(9)
  set issuedAt($core.String value) => $_setString(8, value);
  @$pb.TagNumber(9)
  $core.bool hasIssuedAt() => $_has(8);
  @$pb.TagNumber(9)
  void clearIssuedAt() => $_clearField(9);

  @$pb.TagNumber(10)
  $core.String get expiresAt => $_getSZ(9);
  @$pb.TagNumber(10)
  set expiresAt($core.String value) => $_setString(9, value);
  @$pb.TagNumber(10)
  $core.bool hasExpiresAt() => $_has(9);
  @$pb.TagNumber(10)
  void clearExpiresAt() => $_clearField(10);

  /// The login event the proof was issued inside.
  @$pb.TagNumber(11)
  $core.String get sessionId => $_getSZ(10);
  @$pb.TagNumber(11)
  set sessionId($core.String value) => $_setString(10, value);
  @$pb.TagNumber(11)
  $core.bool hasSessionId() => $_has(10);
  @$pb.TagNumber(11)
  void clearSessionId() => $_clearField(11);

  @$pb.TagNumber(12)
  $core.String get tenantId => $_getSZ(11);
  @$pb.TagNumber(12)
  set tenantId($core.String value) => $_setString(11, value);
  @$pb.TagNumber(12)
  $core.bool hasTenantId() => $_has(11);
  @$pb.TagNumber(12)
  void clearTenantId() => $_clearField(12);

  @$pb.TagNumber(13)
  $core.String get partitionId => $_getSZ(12);
  @$pb.TagNumber(13)
  set partitionId($core.String value) => $_setString(12, value);
  @$pb.TagNumber(13)
  $core.bool hasPartitionId() => $_has(12);
  @$pb.TagNumber(13)
  void clearPartitionId() => $_clearField(13);

  /// The consumer the proof is meant for.
  @$pb.TagNumber(14)
  $core.String get audience => $_getSZ(13);
  @$pb.TagNumber(14)
  set audience($core.String value) => $_setString(13, value);
  @$pb.TagNumber(14)
  $core.bool hasAudience() => $_has(13);
  @$pb.TagNumber(14)
  void clearAudience() => $_clearField(14);
}

/// IssueGenesisSessionProofRequest asks for a proof bound to the caller's own
/// live session and device. Profile, device and session come from the verified
/// bearer token, never from the request.
class IssueGenesisSessionProofRequest extends $pb.GeneratedMessage {
  factory IssueGenesisSessionProofRequest({
    $core.String? pubkeyHash,
    $core.String? deviceKeyId,
    $core.String? deviceId,
  }) {
    final result = IssueGenesisSessionProofRequest._();
    if (pubkeyHash != null) result.pubkeyHash = pubkeyHash;
    if (deviceKeyId != null) result.deviceKeyId = deviceKeyId;
    if (deviceId != null) result.deviceId = deviceId;
    return result;
  }

  IssueGenesisSessionProofRequest._();

  factory IssueGenesisSessionProofRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      IssueGenesisSessionProofRequest()..mergeFromBuffer(data, registry);
  factory IssueGenesisSessionProofRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      IssueGenesisSessionProofRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'IssueGenesisSessionProofRequest',
      package:
          const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'),
      createEmptyInstance: IssueGenesisSessionProofRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'pubkeyHash')
    ..aOS(2, _omitFieldNames ? '' : 'deviceKeyId')
    ..aOS(3, _omitFieldNames ? '' : 'deviceId')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  IssueGenesisSessionProofRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  IssueGenesisSessionProofRequest copyWith(
          void Function(IssueGenesisSessionProofRequest) updates) =>
      super.copyWith(
              (message) => updates(message as IssueGenesisSessionProofRequest))
          as IssueGenesisSessionProofRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use IssueGenesisSessionProofRequest() / IssueGenesisSessionProofRequest.new instead')
  static IssueGenesisSessionProofRequest create() =>
      IssueGenesisSessionProofRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      IssueGenesisSessionProofRequest._();
  @$core.override
  IssueGenesisSessionProofRequest createEmptyInstance() =>
      IssueGenesisSessionProofRequest._();
  @$core.pragma('dart2js:noInline')
  static IssueGenesisSessionProofRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<IssueGenesisSessionProofRequest>(
          IssueGenesisSessionProofRequest.$_createMessage);
  static IssueGenesisSessionProofRequest? _defaultInstance;

  /// 32-byte hex digest of the device public key being registered (on EVM,
  /// keccak256 of the device address). Normalised to lowercase.
  @$pb.TagNumber(1)
  $core.String get pubkeyHash => $_getSZ(0);
  @$pb.TagNumber(1)
  set pubkeyHash($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasPubkeyHash() => $_has(0);
  @$pb.TagNumber(1)
  void clearPubkeyHash() => $_clearField(1);

  /// Devices-service identifier of the key, when known.
  @$pb.TagNumber(2)
  $core.String get deviceKeyId => $_getSZ(1);
  @$pb.TagNumber(2)
  set deviceKeyId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasDeviceKeyId() => $_has(1);
  @$pb.TagNumber(2)
  void clearDeviceKeyId() => $_clearField(2);

  /// Optional; when set it must equal the session's device.
  @$pb.TagNumber(3)
  $core.String get deviceId => $_getSZ(2);
  @$pb.TagNumber(3)
  set deviceId($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasDeviceId() => $_has(2);
  @$pb.TagNumber(3)
  void clearDeviceId() => $_clearField(3);
}

class IssueGenesisSessionProofResponse extends $pb.GeneratedMessage {
  factory IssueGenesisSessionProofResponse({
    $core.String? token,
    $core.String? keyId,
    $core.String? algorithm,
    $core.String? nonce,
    $core.String? issuedAt,
    $core.String? expiresAt,
    $core.String? bindingHash,
    $core.String? audience,
  }) {
    final result = IssueGenesisSessionProofResponse._();
    if (token != null) result.token = token;
    if (keyId != null) result.keyId = keyId;
    if (algorithm != null) result.algorithm = algorithm;
    if (nonce != null) result.nonce = nonce;
    if (issuedAt != null) result.issuedAt = issuedAt;
    if (expiresAt != null) result.expiresAt = expiresAt;
    if (bindingHash != null) result.bindingHash = bindingHash;
    if (audience != null) result.audience = audience;
    return result;
  }

  IssueGenesisSessionProofResponse._();

  factory IssueGenesisSessionProofResponse.fromBuffer(
          $core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      IssueGenesisSessionProofResponse()..mergeFromBuffer(data, registry);
  factory IssueGenesisSessionProofResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      IssueGenesisSessionProofResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'IssueGenesisSessionProofResponse',
      package:
          const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'),
      createEmptyInstance: IssueGenesisSessionProofResponse.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'token')
    ..aOS(2, _omitFieldNames ? '' : 'keyId')
    ..aOS(3, _omitFieldNames ? '' : 'algorithm')
    ..aOS(4, _omitFieldNames ? '' : 'nonce')
    ..aOS(5, _omitFieldNames ? '' : 'issuedAt')
    ..aOS(6, _omitFieldNames ? '' : 'expiresAt')
    ..aOS(7, _omitFieldNames ? '' : 'bindingHash')
    ..aOS(8, _omitFieldNames ? '' : 'audience')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  IssueGenesisSessionProofResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  IssueGenesisSessionProofResponse copyWith(
          void Function(IssueGenesisSessionProofResponse) updates) =>
      super.copyWith(
              (message) => updates(message as IssueGenesisSessionProofResponse))
          as IssueGenesisSessionProofResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use IssueGenesisSessionProofResponse() / IssueGenesisSessionProofResponse.new instead')
  static IssueGenesisSessionProofResponse create() =>
      IssueGenesisSessionProofResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      IssueGenesisSessionProofResponse._();
  @$core.override
  IssueGenesisSessionProofResponse createEmptyInstance() =>
      IssueGenesisSessionProofResponse._();
  @$core.pragma('dart2js:noInline')
  static IssueGenesisSessionProofResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<IssueGenesisSessionProofResponse>(
          IssueGenesisSessionProofResponse.$_createMessage);
  static IssueGenesisSessionProofResponse? _defaultInstance;

  /// The proof to present to the consumer (for example settlement's
  /// DeployAccount session_proof, as its UTF-8 bytes).
  @$pb.TagNumber(1)
  $core.String get token => $_getSZ(0);
  @$pb.TagNumber(1)
  set token($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasToken() => $_has(0);
  @$pb.TagNumber(1)
  void clearToken() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get keyId => $_getSZ(1);
  @$pb.TagNumber(2)
  set keyId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasKeyId() => $_has(1);
  @$pb.TagNumber(2)
  void clearKeyId() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get algorithm => $_getSZ(2);
  @$pb.TagNumber(3)
  set algorithm($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasAlgorithm() => $_has(2);
  @$pb.TagNumber(3)
  void clearAlgorithm() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get nonce => $_getSZ(3);
  @$pb.TagNumber(4)
  set nonce($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasNonce() => $_has(3);
  @$pb.TagNumber(4)
  void clearNonce() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.String get issuedAt => $_getSZ(4);
  @$pb.TagNumber(5)
  set issuedAt($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasIssuedAt() => $_has(4);
  @$pb.TagNumber(5)
  void clearIssuedAt() => $_clearField(5);

  @$pb.TagNumber(6)
  $core.String get expiresAt => $_getSZ(5);
  @$pb.TagNumber(6)
  set expiresAt($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasExpiresAt() => $_has(5);
  @$pb.TagNumber(6)
  void clearExpiresAt() => $_clearField(6);

  /// Lowercase hex SHA-256 of the binding pre-image.
  @$pb.TagNumber(7)
  $core.String get bindingHash => $_getSZ(6);
  @$pb.TagNumber(7)
  set bindingHash($core.String value) => $_setString(6, value);
  @$pb.TagNumber(7)
  $core.bool hasBindingHash() => $_has(6);
  @$pb.TagNumber(7)
  void clearBindingHash() => $_clearField(7);

  @$pb.TagNumber(8)
  $core.String get audience => $_getSZ(7);
  @$pb.TagNumber(8)
  set audience($core.String value) => $_setString(7, value);
  @$pb.TagNumber(8)
  $core.bool hasAudience() => $_has(7);
  @$pb.TagNumber(8)
  void clearAudience() => $_clearField(8);
}

/// VerifyGenesisSessionProofRequest checks a proof against what the consumer
/// expects, and optionally spends its nonce. Empty expectations are not checked.
class VerifyGenesisSessionProofRequest extends $pb.GeneratedMessage {
  factory VerifyGenesisSessionProofRequest({
    $core.String? token,
    $core.String? profileId,
    $core.String? deviceId,
    $core.String? pubkeyHash,
    $core.String? deviceKeyId,
    $core.bool? consume,
  }) {
    final result = VerifyGenesisSessionProofRequest._();
    if (token != null) result.token = token;
    if (profileId != null) result.profileId = profileId;
    if (deviceId != null) result.deviceId = deviceId;
    if (pubkeyHash != null) result.pubkeyHash = pubkeyHash;
    if (deviceKeyId != null) result.deviceKeyId = deviceKeyId;
    if (consume != null) result.consume = consume;
    return result;
  }

  VerifyGenesisSessionProofRequest._();

  factory VerifyGenesisSessionProofRequest.fromBuffer(
          $core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      VerifyGenesisSessionProofRequest()..mergeFromBuffer(data, registry);
  factory VerifyGenesisSessionProofRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      VerifyGenesisSessionProofRequest()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'VerifyGenesisSessionProofRequest',
      package:
          const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'),
      createEmptyInstance: VerifyGenesisSessionProofRequest.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'token')
    ..aOS(2, _omitFieldNames ? '' : 'profileId')
    ..aOS(3, _omitFieldNames ? '' : 'deviceId')
    ..aOS(4, _omitFieldNames ? '' : 'pubkeyHash')
    ..aOS(5, _omitFieldNames ? '' : 'deviceKeyId')
    ..aOB(6, _omitFieldNames ? '' : 'consume')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  VerifyGenesisSessionProofRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  VerifyGenesisSessionProofRequest copyWith(
          void Function(VerifyGenesisSessionProofRequest) updates) =>
      super.copyWith(
              (message) => updates(message as VerifyGenesisSessionProofRequest))
          as VerifyGenesisSessionProofRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use VerifyGenesisSessionProofRequest() / VerifyGenesisSessionProofRequest.new instead')
  static VerifyGenesisSessionProofRequest create() =>
      VerifyGenesisSessionProofRequest._();
  static $pb.GeneratedMessage $_createMessage() =>
      VerifyGenesisSessionProofRequest._();
  @$core.override
  VerifyGenesisSessionProofRequest createEmptyInstance() =>
      VerifyGenesisSessionProofRequest._();
  @$core.pragma('dart2js:noInline')
  static VerifyGenesisSessionProofRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<VerifyGenesisSessionProofRequest>(
          VerifyGenesisSessionProofRequest.$_createMessage);
  static VerifyGenesisSessionProofRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get token => $_getSZ(0);
  @$pb.TagNumber(1)
  set token($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasToken() => $_has(0);
  @$pb.TagNumber(1)
  void clearToken() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get profileId => $_getSZ(1);
  @$pb.TagNumber(2)
  set profileId($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasProfileId() => $_has(1);
  @$pb.TagNumber(2)
  void clearProfileId() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get deviceId => $_getSZ(2);
  @$pb.TagNumber(3)
  set deviceId($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasDeviceId() => $_has(2);
  @$pb.TagNumber(3)
  void clearDeviceId() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get pubkeyHash => $_getSZ(3);
  @$pb.TagNumber(4)
  set pubkeyHash($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasPubkeyHash() => $_has(3);
  @$pb.TagNumber(4)
  void clearPubkeyHash() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.String get deviceKeyId => $_getSZ(4);
  @$pb.TagNumber(5)
  set deviceKeyId($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasDeviceKeyId() => $_has(4);
  @$pb.TagNumber(5)
  void clearDeviceKeyId() => $_clearField(5);

  /// Spend the nonce. A consumer about to act on the proof sets it.
  @$pb.TagNumber(6)
  $core.bool get consume => $_getBF(5);
  @$pb.TagNumber(6)
  set consume($core.bool value) => $_setBool(5, value);
  @$pb.TagNumber(6)
  $core.bool hasConsume() => $_has(5);
  @$pb.TagNumber(6)
  void clearConsume() => $_clearField(6);
}

class VerifyGenesisSessionProofResponse extends $pb.GeneratedMessage {
  factory VerifyGenesisSessionProofResponse({
    $core.bool? valid,
    $core.String? reason,
    GenesisSessionProofClaims? claims,
    $core.String? bindingHash,
  }) {
    final result = VerifyGenesisSessionProofResponse._();
    if (valid != null) result.valid = valid;
    if (reason != null) result.reason = reason;
    if (claims != null) result.claims = claims;
    if (bindingHash != null) result.bindingHash = bindingHash;
    return result;
  }

  VerifyGenesisSessionProofResponse._();

  factory VerifyGenesisSessionProofResponse.fromBuffer(
          $core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      VerifyGenesisSessionProofResponse()..mergeFromBuffer(data, registry);
  factory VerifyGenesisSessionProofResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      VerifyGenesisSessionProofResponse()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'VerifyGenesisSessionProofResponse',
      package:
          const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'),
      createEmptyInstance: VerifyGenesisSessionProofResponse.$_createMessage)
    ..aOB(1, _omitFieldNames ? '' : 'valid')
    ..aOS(2, _omitFieldNames ? '' : 'reason')
    ..aOM<GenesisSessionProofClaims>(3, _omitFieldNames ? '' : 'claims',
        subBuilder: GenesisSessionProofClaims.$_createMessage)
    ..aOS(4, _omitFieldNames ? '' : 'bindingHash')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  VerifyGenesisSessionProofResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  VerifyGenesisSessionProofResponse copyWith(
          void Function(VerifyGenesisSessionProofResponse) updates) =>
      super.copyWith((message) =>
              updates(message as VerifyGenesisSessionProofResponse))
          as VerifyGenesisSessionProofResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated(
      'Use VerifyGenesisSessionProofResponse() / VerifyGenesisSessionProofResponse.new instead')
  static VerifyGenesisSessionProofResponse create() =>
      VerifyGenesisSessionProofResponse._();
  static $pb.GeneratedMessage $_createMessage() =>
      VerifyGenesisSessionProofResponse._();
  @$core.override
  VerifyGenesisSessionProofResponse createEmptyInstance() =>
      VerifyGenesisSessionProofResponse._();
  @$core.pragma('dart2js:noInline')
  static VerifyGenesisSessionProofResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<VerifyGenesisSessionProofResponse>(
          VerifyGenesisSessionProofResponse.$_createMessage);
  static VerifyGenesisSessionProofResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get valid => $_getBF(0);
  @$pb.TagNumber(1)
  set valid($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasValid() => $_has(0);
  @$pb.TagNumber(1)
  void clearValid() => $_clearField(1);

  /// Why the proof was refused, when it was.
  @$pb.TagNumber(2)
  $core.String get reason => $_getSZ(1);
  @$pb.TagNumber(2)
  set reason($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasReason() => $_has(1);
  @$pb.TagNumber(2)
  void clearReason() => $_clearField(2);

  @$pb.TagNumber(3)
  GenesisSessionProofClaims get claims => $_getN(2);
  @$pb.TagNumber(3)
  set claims(GenesisSessionProofClaims value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasClaims() => $_has(2);
  @$pb.TagNumber(3)
  void clearClaims() => $_clearField(3);
  @$pb.TagNumber(3)
  GenesisSessionProofClaims ensureClaims() => $_ensure(2);

  /// Lowercase hex SHA-256 of the binding pre-image.
  @$pb.TagNumber(4)
  $core.String get bindingHash => $_getSZ(3);
  @$pb.TagNumber(4)
  set bindingHash($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasBindingHash() => $_has(3);
  @$pb.TagNumber(4)
  void clearBindingHash() => $_clearField(4);
}

/// AuthenticationService provides read-only access to login history.
/// All RPCs require authentication via Bearer token.
class AuthenticationServiceApi {
  final $pb.RpcClient _client;

  AuthenticationServiceApi(this._client);

  /// GetLoginEvent retrieves a single login event by ID.
  $async.Future<GetLoginEventResponse> getLoginEvent(
          $pb.ClientContext? ctx, GetLoginEventRequest request) =>
      _client.invoke<GetLoginEventResponse>(ctx, 'AuthenticationService',
          'GetLoginEvent', request, GetLoginEventResponse());

  /// ListLoginEvents queries login events with filtering and pagination.
  $async.Future<ListLoginEventsResponse> listLoginEvents(
          $pb.ClientContext? ctx, ListLoginEventsRequest request) =>
      _client.invoke<ListLoginEventsResponse>(ctx, 'AuthenticationService',
          'ListLoginEvents', request, ListLoginEventsResponse());

  /// IssueGenesisSessionProof mints a short-lived, single-use proof that the
  /// caller holds a live authenticated session on this device (P26). It is
  /// refused for service accounts and for sessions whose login event is not
  /// this profile on this device. The verifying keys are published at
  /// /.well-known/genesis-session-proof-keys.json.
  $async.Future<IssueGenesisSessionProofResponse> issueGenesisSessionProof(
          $pb.ClientContext? ctx, IssueGenesisSessionProofRequest request) =>
      _client.invoke<IssueGenesisSessionProofResponse>(
          ctx,
          'AuthenticationService',
          'IssueGenesisSessionProof',
          request,
          IssueGenesisSessionProofResponse());

  /// VerifyGenesisSessionProof checks a proof and, with consume set, spends
  /// its nonce so it cannot be presented again.
  /// Restricted to auth_genesis_verify, which no role carries: it is granted
  /// only to the consumer that acts on a proof (settlement's service account),
  /// because consume burns the person's proof.
  $async.Future<VerifyGenesisSessionProofResponse> verifyGenesisSessionProof(
          $pb.ClientContext? ctx, VerifyGenesisSessionProofRequest request) =>
      _client.invoke<VerifyGenesisSessionProofResponse>(
          ctx,
          'AuthenticationService',
          'VerifyGenesisSessionProof',
          request,
          VerifyGenesisSessionProofResponse());
}

const $core.bool _omitFieldNames =
    $core.bool.fromEnvironment('protobuf.omit_field_names');
const $core.bool _omitMessageNames =
    $core.bool.fromEnvironment('protobuf.omit_message_names');
