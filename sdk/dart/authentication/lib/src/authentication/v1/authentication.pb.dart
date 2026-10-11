//
//  Generated code. Do not modify.
//  source: authentication/v1/authentication.proto
//
// @dart = 2.12

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_final_fields
// ignore_for_file: unnecessary_import, unnecessary_this, unused_import

import 'dart:async' as $async;
import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;

import '../../google/protobuf/struct.pb.dart' as $6;
import '../../google/protobuf/timestamp.pb.dart' as $2;

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
    $6.Struct? properties,
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
    if (clientId != null) {
      $result.clientId = clientId;
    }
    if (source != null) {
      $result.source = source;
    }
    if (contactId != null) {
      $result.contactId = contactId;
    }
    if (deviceId != null) {
      $result.deviceId = deviceId;
    }
    if (ipAddress != null) {
      $result.ipAddress = ipAddress;
    }
    if (userAgent != null) {
      $result.userAgent = userAgent;
    }
    if (status != null) {
      $result.status = status;
    }
    if (properties != null) {
      $result.properties = properties;
    }
    if (createdAt != null) {
      $result.createdAt = createdAt;
    }
    return $result;
  }
  LoginEventObject._() : super();
  factory LoginEventObject.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory LoginEventObject.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'LoginEventObject', package: const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'), createEmptyInstance: create)
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
    ..a<$core.int>(11, _omitFieldNames ? '' : 'status', $pb.PbFieldType.O3)
    ..aOM<$6.Struct>(12, _omitFieldNames ? '' : 'properties', subBuilder: $6.Struct.create)
    ..aOM<$2.Timestamp>(13, _omitFieldNames ? '' : 'createdAt', subBuilder: $2.Timestamp.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  LoginEventObject clone() => LoginEventObject()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  LoginEventObject copyWith(void Function(LoginEventObject) updates) => super.copyWith((message) => updates(message as LoginEventObject)) as LoginEventObject;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static LoginEventObject create() => LoginEventObject._();
  LoginEventObject createEmptyInstance() => create();
  static $pb.PbList<LoginEventObject> createRepeated() => $pb.PbList<LoginEventObject>();
  @$core.pragma('dart2js:noInline')
  static LoginEventObject getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<LoginEventObject>(create);
  static LoginEventObject? _defaultInstance;

  /// Unique identifier for this login event.
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

  /// Profile ID of the user who authenticated.
  @$pb.TagNumber(4)
  $core.String get profileId => $_getSZ(3);
  @$pb.TagNumber(4)
  set profileId($core.String v) { $_setString(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasProfileId() => $_has(3);
  @$pb.TagNumber(4)
  void clearProfileId() => clearField(4);

  /// OAuth2 client ID used for authentication.
  @$pb.TagNumber(5)
  $core.String get clientId => $_getSZ(4);
  @$pb.TagNumber(5)
  set clientId($core.String v) { $_setString(4, v); }
  @$pb.TagNumber(5)
  $core.bool hasClientId() => $_has(4);
  @$pb.TagNumber(5)
  void clearClientId() => clearField(5);

  /// How the user authenticated.
  @$pb.TagNumber(6)
  $core.String get source => $_getSZ(5);
  @$pb.TagNumber(6)
  set source($core.String v) { $_setString(5, v); }
  @$pb.TagNumber(6)
  $core.bool hasSource() => $_has(5);
  @$pb.TagNumber(6)
  void clearSource() => clearField(6);

  /// Contact (email or phone) used for authentication.
  @$pb.TagNumber(7)
  $core.String get contactId => $_getSZ(6);
  @$pb.TagNumber(7)
  set contactId($core.String v) { $_setString(6, v); }
  @$pb.TagNumber(7)
  $core.bool hasContactId() => $_has(6);
  @$pb.TagNumber(7)
  void clearContactId() => clearField(7);

  /// Device ID from which the authentication occurred.
  @$pb.TagNumber(8)
  $core.String get deviceId => $_getSZ(7);
  @$pb.TagNumber(8)
  set deviceId($core.String v) { $_setString(7, v); }
  @$pb.TagNumber(8)
  $core.bool hasDeviceId() => $_has(7);
  @$pb.TagNumber(8)
  void clearDeviceId() => clearField(8);

  /// IP address of the authenticating client.
  @$pb.TagNumber(9)
  $core.String get ipAddress => $_getSZ(8);
  @$pb.TagNumber(9)
  set ipAddress($core.String v) { $_setString(8, v); }
  @$pb.TagNumber(9)
  $core.bool hasIpAddress() => $_has(8);
  @$pb.TagNumber(9)
  void clearIpAddress() => clearField(9);

  /// User agent string of the authenticating client.
  @$pb.TagNumber(10)
  $core.String get userAgent => $_getSZ(9);
  @$pb.TagNumber(10)
  set userAgent($core.String v) { $_setString(9, v); }
  @$pb.TagNumber(10)
  $core.bool hasUserAgent() => $_has(9);
  @$pb.TagNumber(10)
  void clearUserAgent() => clearField(10);

  /// Login status code (0 = success).
  @$pb.TagNumber(11)
  $core.int get status => $_getIZ(10);
  @$pb.TagNumber(11)
  set status($core.int v) { $_setSignedInt32(10, v); }
  @$pb.TagNumber(11)
  $core.bool hasStatus() => $_has(10);
  @$pb.TagNumber(11)
  void clearStatus() => clearField(11);

  /// Additional properties as structured data.
  @$pb.TagNumber(12)
  $6.Struct get properties => $_getN(11);
  @$pb.TagNumber(12)
  set properties($6.Struct v) { setField(12, v); }
  @$pb.TagNumber(12)
  $core.bool hasProperties() => $_has(11);
  @$pb.TagNumber(12)
  void clearProperties() => clearField(12);
  @$pb.TagNumber(12)
  $6.Struct ensureProperties() => $_ensure(11);

  /// Timestamp when the login event was created.
  @$pb.TagNumber(13)
  $2.Timestamp get createdAt => $_getN(12);
  @$pb.TagNumber(13)
  set createdAt($2.Timestamp v) { setField(13, v); }
  @$pb.TagNumber(13)
  $core.bool hasCreatedAt() => $_has(12);
  @$pb.TagNumber(13)
  void clearCreatedAt() => clearField(13);
  @$pb.TagNumber(13)
  $2.Timestamp ensureCreatedAt() => $_ensure(12);
}

/// GetLoginEventRequest retrieves a single login event by ID.
class GetLoginEventRequest extends $pb.GeneratedMessage {
  factory GetLoginEventRequest({
    $core.String? id,
  }) {
    final $result = create();
    if (id != null) {
      $result.id = id;
    }
    return $result;
  }
  GetLoginEventRequest._() : super();
  factory GetLoginEventRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory GetLoginEventRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'GetLoginEventRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  GetLoginEventRequest clone() => GetLoginEventRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  GetLoginEventRequest copyWith(void Function(GetLoginEventRequest) updates) => super.copyWith((message) => updates(message as GetLoginEventRequest)) as GetLoginEventRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetLoginEventRequest create() => GetLoginEventRequest._();
  GetLoginEventRequest createEmptyInstance() => create();
  static $pb.PbList<GetLoginEventRequest> createRepeated() => $pb.PbList<GetLoginEventRequest>();
  @$core.pragma('dart2js:noInline')
  static GetLoginEventRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetLoginEventRequest>(create);
  static GetLoginEventRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => clearField(1);
}

class GetLoginEventResponse extends $pb.GeneratedMessage {
  factory GetLoginEventResponse({
    LoginEventObject? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data = data;
    }
    return $result;
  }
  GetLoginEventResponse._() : super();
  factory GetLoginEventResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory GetLoginEventResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'GetLoginEventResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'), createEmptyInstance: create)
    ..aOM<LoginEventObject>(1, _omitFieldNames ? '' : 'data', subBuilder: LoginEventObject.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  GetLoginEventResponse clone() => GetLoginEventResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  GetLoginEventResponse copyWith(void Function(GetLoginEventResponse) updates) => super.copyWith((message) => updates(message as GetLoginEventResponse)) as GetLoginEventResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetLoginEventResponse create() => GetLoginEventResponse._();
  GetLoginEventResponse createEmptyInstance() => create();
  static $pb.PbList<GetLoginEventResponse> createRepeated() => $pb.PbList<GetLoginEventResponse>();
  @$core.pragma('dart2js:noInline')
  static GetLoginEventResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GetLoginEventResponse>(create);
  static GetLoginEventResponse? _defaultInstance;

  @$pb.TagNumber(1)
  LoginEventObject get data => $_getN(0);
  @$pb.TagNumber(1)
  set data(LoginEventObject v) { setField(1, v); }
  @$pb.TagNumber(1)
  $core.bool hasData() => $_has(0);
  @$pb.TagNumber(1)
  void clearData() => clearField(1);
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
    $2.Timestamp? startDate,
    $2.Timestamp? endDate,
    $core.int? count,
    $core.String? page,
  }) {
    final $result = create();
    if (profileId != null) {
      $result.profileId = profileId;
    }
    if (clientId != null) {
      $result.clientId = clientId;
    }
    if (source != null) {
      $result.source = source;
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
  ListLoginEventsRequest._() : super();
  factory ListLoginEventsRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory ListLoginEventsRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'ListLoginEventsRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'profileId')
    ..aOS(2, _omitFieldNames ? '' : 'clientId')
    ..aOS(3, _omitFieldNames ? '' : 'source')
    ..aOS(4, _omitFieldNames ? '' : 'deviceId')
    ..aOM<$2.Timestamp>(5, _omitFieldNames ? '' : 'startDate', subBuilder: $2.Timestamp.create)
    ..aOM<$2.Timestamp>(6, _omitFieldNames ? '' : 'endDate', subBuilder: $2.Timestamp.create)
    ..a<$core.int>(7, _omitFieldNames ? '' : 'count', $pb.PbFieldType.O3)
    ..aOS(8, _omitFieldNames ? '' : 'page')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  ListLoginEventsRequest clone() => ListLoginEventsRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  ListLoginEventsRequest copyWith(void Function(ListLoginEventsRequest) updates) => super.copyWith((message) => updates(message as ListLoginEventsRequest)) as ListLoginEventsRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListLoginEventsRequest create() => ListLoginEventsRequest._();
  ListLoginEventsRequest createEmptyInstance() => create();
  static $pb.PbList<ListLoginEventsRequest> createRepeated() => $pb.PbList<ListLoginEventsRequest>();
  @$core.pragma('dart2js:noInline')
  static ListLoginEventsRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ListLoginEventsRequest>(create);
  static ListLoginEventsRequest? _defaultInstance;

  /// Filter by profile ID. Required for non-admin users.
  @$pb.TagNumber(1)
  $core.String get profileId => $_getSZ(0);
  @$pb.TagNumber(1)
  set profileId($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasProfileId() => $_has(0);
  @$pb.TagNumber(1)
  void clearProfileId() => clearField(1);

  /// Filter by OAuth2 client ID.
  @$pb.TagNumber(2)
  $core.String get clientId => $_getSZ(1);
  @$pb.TagNumber(2)
  set clientId($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasClientId() => $_has(1);
  @$pb.TagNumber(2)
  void clearClientId() => clearField(2);

  /// Filter by login source (e.g., "direct", "google").
  @$pb.TagNumber(3)
  $core.String get source => $_getSZ(2);
  @$pb.TagNumber(3)
  set source($core.String v) { $_setString(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasSource() => $_has(2);
  @$pb.TagNumber(3)
  void clearSource() => clearField(3);

  /// Filter by device ID.
  @$pb.TagNumber(4)
  $core.String get deviceId => $_getSZ(3);
  @$pb.TagNumber(4)
  set deviceId($core.String v) { $_setString(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasDeviceId() => $_has(3);
  @$pb.TagNumber(4)
  void clearDeviceId() => clearField(4);

  /// Filter events created after this timestamp.
  @$pb.TagNumber(5)
  $2.Timestamp get startDate => $_getN(4);
  @$pb.TagNumber(5)
  set startDate($2.Timestamp v) { setField(5, v); }
  @$pb.TagNumber(5)
  $core.bool hasStartDate() => $_has(4);
  @$pb.TagNumber(5)
  void clearStartDate() => clearField(5);
  @$pb.TagNumber(5)
  $2.Timestamp ensureStartDate() => $_ensure(4);

  /// Filter events created before this timestamp.
  @$pb.TagNumber(6)
  $2.Timestamp get endDate => $_getN(5);
  @$pb.TagNumber(6)
  set endDate($2.Timestamp v) { setField(6, v); }
  @$pb.TagNumber(6)
  $core.bool hasEndDate() => $_has(5);
  @$pb.TagNumber(6)
  void clearEndDate() => clearField(6);
  @$pb.TagNumber(6)
  $2.Timestamp ensureEndDate() => $_ensure(5);

  /// Maximum number of events per page. Default 50, max 500.
  @$pb.TagNumber(7)
  $core.int get count => $_getIZ(6);
  @$pb.TagNumber(7)
  set count($core.int v) { $_setSignedInt32(6, v); }
  @$pb.TagNumber(7)
  $core.bool hasCount() => $_has(6);
  @$pb.TagNumber(7)
  void clearCount() => clearField(7);

  /// Pagination cursor (ID of the last event from previous page).
  @$pb.TagNumber(8)
  $core.String get page => $_getSZ(7);
  @$pb.TagNumber(8)
  set page($core.String v) { $_setString(7, v); }
  @$pb.TagNumber(8)
  $core.bool hasPage() => $_has(7);
  @$pb.TagNumber(8)
  void clearPage() => clearField(8);
}

class ListLoginEventsResponse extends $pb.GeneratedMessage {
  factory ListLoginEventsResponse({
    $core.Iterable<LoginEventObject>? data,
  }) {
    final $result = create();
    if (data != null) {
      $result.data.addAll(data);
    }
    return $result;
  }
  ListLoginEventsResponse._() : super();
  factory ListLoginEventsResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory ListLoginEventsResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'ListLoginEventsResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'), createEmptyInstance: create)
    ..pc<LoginEventObject>(1, _omitFieldNames ? '' : 'data', $pb.PbFieldType.PM, subBuilder: LoginEventObject.create)
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  ListLoginEventsResponse clone() => ListLoginEventsResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  ListLoginEventsResponse copyWith(void Function(ListLoginEventsResponse) updates) => super.copyWith((message) => updates(message as ListLoginEventsResponse)) as ListLoginEventsResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListLoginEventsResponse create() => ListLoginEventsResponse._();
  ListLoginEventsResponse createEmptyInstance() => create();
  static $pb.PbList<ListLoginEventsResponse> createRepeated() => $pb.PbList<ListLoginEventsResponse>();
  @$core.pragma('dart2js:noInline')
  static ListLoginEventsResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<ListLoginEventsResponse>(create);
  static ListLoginEventsResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<LoginEventObject> get data => $_getList(0);
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
    final $result = create();
    if (version != null) {
      $result.version = version;
    }
    if (keyId != null) {
      $result.keyId = keyId;
    }
    if (algorithm != null) {
      $result.algorithm = algorithm;
    }
    if (profileId != null) {
      $result.profileId = profileId;
    }
    if (deviceId != null) {
      $result.deviceId = deviceId;
    }
    if (pubkeyHash != null) {
      $result.pubkeyHash = pubkeyHash;
    }
    if (deviceKeyId != null) {
      $result.deviceKeyId = deviceKeyId;
    }
    if (nonce != null) {
      $result.nonce = nonce;
    }
    if (issuedAt != null) {
      $result.issuedAt = issuedAt;
    }
    if (expiresAt != null) {
      $result.expiresAt = expiresAt;
    }
    if (sessionId != null) {
      $result.sessionId = sessionId;
    }
    if (tenantId != null) {
      $result.tenantId = tenantId;
    }
    if (partitionId != null) {
      $result.partitionId = partitionId;
    }
    if (audience != null) {
      $result.audience = audience;
    }
    return $result;
  }
  GenesisSessionProofClaims._() : super();
  factory GenesisSessionProofClaims.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory GenesisSessionProofClaims.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'GenesisSessionProofClaims', package: const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'), createEmptyInstance: create)
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
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  GenesisSessionProofClaims clone() => GenesisSessionProofClaims()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  GenesisSessionProofClaims copyWith(void Function(GenesisSessionProofClaims) updates) => super.copyWith((message) => updates(message as GenesisSessionProofClaims)) as GenesisSessionProofClaims;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GenesisSessionProofClaims create() => GenesisSessionProofClaims._();
  GenesisSessionProofClaims createEmptyInstance() => create();
  static $pb.PbList<GenesisSessionProofClaims> createRepeated() => $pb.PbList<GenesisSessionProofClaims>();
  @$core.pragma('dart2js:noInline')
  static GenesisSessionProofClaims getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<GenesisSessionProofClaims>(create);
  static GenesisSessionProofClaims? _defaultInstance;

  /// Format version ("GSP1").
  @$pb.TagNumber(1)
  $core.String get version => $_getSZ(0);
  @$pb.TagNumber(1)
  set version($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasVersion() => $_has(0);
  @$pb.TagNumber(1)
  void clearVersion() => clearField(1);

  /// Signing key id in /.well-known/genesis-session-proof-keys.json.
  @$pb.TagNumber(2)
  $core.String get keyId => $_getSZ(1);
  @$pb.TagNumber(2)
  set keyId($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasKeyId() => $_has(1);
  @$pb.TagNumber(2)
  void clearKeyId() => clearField(2);

  /// Always "ed25519" for GSP1.
  @$pb.TagNumber(3)
  $core.String get algorithm => $_getSZ(2);
  @$pb.TagNumber(3)
  set algorithm($core.String v) { $_setString(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasAlgorithm() => $_has(2);
  @$pb.TagNumber(3)
  void clearAlgorithm() => clearField(3);

  /// The person the proof is about (JWT sub === profile_id).
  @$pb.TagNumber(4)
  $core.String get profileId => $_getSZ(3);
  @$pb.TagNumber(4)
  set profileId($core.String v) { $_setString(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasProfileId() => $_has(3);
  @$pb.TagNumber(4)
  void clearProfileId() => clearField(4);

  /// The device the live session ran on.
  @$pb.TagNumber(5)
  $core.String get deviceId => $_getSZ(4);
  @$pb.TagNumber(5)
  set deviceId($core.String v) { $_setString(4, v); }
  @$pb.TagNumber(5)
  $core.bool hasDeviceId() => $_has(4);
  @$pb.TagNumber(5)
  void clearDeviceId() => clearField(5);

  /// Lowercase hex hash of the device public key being registered.
  @$pb.TagNumber(6)
  $core.String get pubkeyHash => $_getSZ(5);
  @$pb.TagNumber(6)
  set pubkeyHash($core.String v) { $_setString(5, v); }
  @$pb.TagNumber(6)
  $core.bool hasPubkeyHash() => $_has(5);
  @$pb.TagNumber(6)
  void clearPubkeyHash() => clearField(6);

  /// Devices-service identifier of that key, when known.
  @$pb.TagNumber(7)
  $core.String get deviceKeyId => $_getSZ(6);
  @$pb.TagNumber(7)
  set deviceKeyId($core.String v) { $_setString(6, v); }
  @$pb.TagNumber(7)
  $core.bool hasDeviceKeyId() => $_has(6);
  @$pb.TagNumber(7)
  void clearDeviceKeyId() => clearField(7);

  /// Single-use nonce.
  @$pb.TagNumber(8)
  $core.String get nonce => $_getSZ(7);
  @$pb.TagNumber(8)
  set nonce($core.String v) { $_setString(7, v); }
  @$pb.TagNumber(8)
  $core.bool hasNonce() => $_has(7);
  @$pb.TagNumber(8)
  void clearNonce() => clearField(8);

  @$pb.TagNumber(9)
  $core.String get issuedAt => $_getSZ(8);
  @$pb.TagNumber(9)
  set issuedAt($core.String v) { $_setString(8, v); }
  @$pb.TagNumber(9)
  $core.bool hasIssuedAt() => $_has(8);
  @$pb.TagNumber(9)
  void clearIssuedAt() => clearField(9);

  @$pb.TagNumber(10)
  $core.String get expiresAt => $_getSZ(9);
  @$pb.TagNumber(10)
  set expiresAt($core.String v) { $_setString(9, v); }
  @$pb.TagNumber(10)
  $core.bool hasExpiresAt() => $_has(9);
  @$pb.TagNumber(10)
  void clearExpiresAt() => clearField(10);

  /// The login event the proof was issued inside.
  @$pb.TagNumber(11)
  $core.String get sessionId => $_getSZ(10);
  @$pb.TagNumber(11)
  set sessionId($core.String v) { $_setString(10, v); }
  @$pb.TagNumber(11)
  $core.bool hasSessionId() => $_has(10);
  @$pb.TagNumber(11)
  void clearSessionId() => clearField(11);

  @$pb.TagNumber(12)
  $core.String get tenantId => $_getSZ(11);
  @$pb.TagNumber(12)
  set tenantId($core.String v) { $_setString(11, v); }
  @$pb.TagNumber(12)
  $core.bool hasTenantId() => $_has(11);
  @$pb.TagNumber(12)
  void clearTenantId() => clearField(12);

  @$pb.TagNumber(13)
  $core.String get partitionId => $_getSZ(12);
  @$pb.TagNumber(13)
  set partitionId($core.String v) { $_setString(12, v); }
  @$pb.TagNumber(13)
  $core.bool hasPartitionId() => $_has(12);
  @$pb.TagNumber(13)
  void clearPartitionId() => clearField(13);

  /// The consumer the proof is meant for.
  @$pb.TagNumber(14)
  $core.String get audience => $_getSZ(13);
  @$pb.TagNumber(14)
  set audience($core.String v) { $_setString(13, v); }
  @$pb.TagNumber(14)
  $core.bool hasAudience() => $_has(13);
  @$pb.TagNumber(14)
  void clearAudience() => clearField(14);
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
    final $result = create();
    if (pubkeyHash != null) {
      $result.pubkeyHash = pubkeyHash;
    }
    if (deviceKeyId != null) {
      $result.deviceKeyId = deviceKeyId;
    }
    if (deviceId != null) {
      $result.deviceId = deviceId;
    }
    return $result;
  }
  IssueGenesisSessionProofRequest._() : super();
  factory IssueGenesisSessionProofRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory IssueGenesisSessionProofRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'IssueGenesisSessionProofRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'pubkeyHash')
    ..aOS(2, _omitFieldNames ? '' : 'deviceKeyId')
    ..aOS(3, _omitFieldNames ? '' : 'deviceId')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  IssueGenesisSessionProofRequest clone() => IssueGenesisSessionProofRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  IssueGenesisSessionProofRequest copyWith(void Function(IssueGenesisSessionProofRequest) updates) => super.copyWith((message) => updates(message as IssueGenesisSessionProofRequest)) as IssueGenesisSessionProofRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static IssueGenesisSessionProofRequest create() => IssueGenesisSessionProofRequest._();
  IssueGenesisSessionProofRequest createEmptyInstance() => create();
  static $pb.PbList<IssueGenesisSessionProofRequest> createRepeated() => $pb.PbList<IssueGenesisSessionProofRequest>();
  @$core.pragma('dart2js:noInline')
  static IssueGenesisSessionProofRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<IssueGenesisSessionProofRequest>(create);
  static IssueGenesisSessionProofRequest? _defaultInstance;

  /// 32-byte hex digest of the device public key being registered (on EVM,
  /// keccak256 of the device address). Normalised to lowercase.
  @$pb.TagNumber(1)
  $core.String get pubkeyHash => $_getSZ(0);
  @$pb.TagNumber(1)
  set pubkeyHash($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasPubkeyHash() => $_has(0);
  @$pb.TagNumber(1)
  void clearPubkeyHash() => clearField(1);

  /// Devices-service identifier of the key, when known.
  @$pb.TagNumber(2)
  $core.String get deviceKeyId => $_getSZ(1);
  @$pb.TagNumber(2)
  set deviceKeyId($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasDeviceKeyId() => $_has(1);
  @$pb.TagNumber(2)
  void clearDeviceKeyId() => clearField(2);

  /// Optional; when set it must equal the session's device.
  @$pb.TagNumber(3)
  $core.String get deviceId => $_getSZ(2);
  @$pb.TagNumber(3)
  set deviceId($core.String v) { $_setString(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasDeviceId() => $_has(2);
  @$pb.TagNumber(3)
  void clearDeviceId() => clearField(3);
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
    final $result = create();
    if (token != null) {
      $result.token = token;
    }
    if (keyId != null) {
      $result.keyId = keyId;
    }
    if (algorithm != null) {
      $result.algorithm = algorithm;
    }
    if (nonce != null) {
      $result.nonce = nonce;
    }
    if (issuedAt != null) {
      $result.issuedAt = issuedAt;
    }
    if (expiresAt != null) {
      $result.expiresAt = expiresAt;
    }
    if (bindingHash != null) {
      $result.bindingHash = bindingHash;
    }
    if (audience != null) {
      $result.audience = audience;
    }
    return $result;
  }
  IssueGenesisSessionProofResponse._() : super();
  factory IssueGenesisSessionProofResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory IssueGenesisSessionProofResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'IssueGenesisSessionProofResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'token')
    ..aOS(2, _omitFieldNames ? '' : 'keyId')
    ..aOS(3, _omitFieldNames ? '' : 'algorithm')
    ..aOS(4, _omitFieldNames ? '' : 'nonce')
    ..aOS(5, _omitFieldNames ? '' : 'issuedAt')
    ..aOS(6, _omitFieldNames ? '' : 'expiresAt')
    ..aOS(7, _omitFieldNames ? '' : 'bindingHash')
    ..aOS(8, _omitFieldNames ? '' : 'audience')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  IssueGenesisSessionProofResponse clone() => IssueGenesisSessionProofResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  IssueGenesisSessionProofResponse copyWith(void Function(IssueGenesisSessionProofResponse) updates) => super.copyWith((message) => updates(message as IssueGenesisSessionProofResponse)) as IssueGenesisSessionProofResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static IssueGenesisSessionProofResponse create() => IssueGenesisSessionProofResponse._();
  IssueGenesisSessionProofResponse createEmptyInstance() => create();
  static $pb.PbList<IssueGenesisSessionProofResponse> createRepeated() => $pb.PbList<IssueGenesisSessionProofResponse>();
  @$core.pragma('dart2js:noInline')
  static IssueGenesisSessionProofResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<IssueGenesisSessionProofResponse>(create);
  static IssueGenesisSessionProofResponse? _defaultInstance;

  /// The proof to present to the consumer (for example settlement's
  /// DeployAccount session_proof, as its UTF-8 bytes).
  @$pb.TagNumber(1)
  $core.String get token => $_getSZ(0);
  @$pb.TagNumber(1)
  set token($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasToken() => $_has(0);
  @$pb.TagNumber(1)
  void clearToken() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get keyId => $_getSZ(1);
  @$pb.TagNumber(2)
  set keyId($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasKeyId() => $_has(1);
  @$pb.TagNumber(2)
  void clearKeyId() => clearField(2);

  @$pb.TagNumber(3)
  $core.String get algorithm => $_getSZ(2);
  @$pb.TagNumber(3)
  set algorithm($core.String v) { $_setString(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasAlgorithm() => $_has(2);
  @$pb.TagNumber(3)
  void clearAlgorithm() => clearField(3);

  @$pb.TagNumber(4)
  $core.String get nonce => $_getSZ(3);
  @$pb.TagNumber(4)
  set nonce($core.String v) { $_setString(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasNonce() => $_has(3);
  @$pb.TagNumber(4)
  void clearNonce() => clearField(4);

  @$pb.TagNumber(5)
  $core.String get issuedAt => $_getSZ(4);
  @$pb.TagNumber(5)
  set issuedAt($core.String v) { $_setString(4, v); }
  @$pb.TagNumber(5)
  $core.bool hasIssuedAt() => $_has(4);
  @$pb.TagNumber(5)
  void clearIssuedAt() => clearField(5);

  @$pb.TagNumber(6)
  $core.String get expiresAt => $_getSZ(5);
  @$pb.TagNumber(6)
  set expiresAt($core.String v) { $_setString(5, v); }
  @$pb.TagNumber(6)
  $core.bool hasExpiresAt() => $_has(5);
  @$pb.TagNumber(6)
  void clearExpiresAt() => clearField(6);

  /// Lowercase hex SHA-256 of the binding pre-image.
  @$pb.TagNumber(7)
  $core.String get bindingHash => $_getSZ(6);
  @$pb.TagNumber(7)
  set bindingHash($core.String v) { $_setString(6, v); }
  @$pb.TagNumber(7)
  $core.bool hasBindingHash() => $_has(6);
  @$pb.TagNumber(7)
  void clearBindingHash() => clearField(7);

  @$pb.TagNumber(8)
  $core.String get audience => $_getSZ(7);
  @$pb.TagNumber(8)
  set audience($core.String v) { $_setString(7, v); }
  @$pb.TagNumber(8)
  $core.bool hasAudience() => $_has(7);
  @$pb.TagNumber(8)
  void clearAudience() => clearField(8);
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
    final $result = create();
    if (token != null) {
      $result.token = token;
    }
    if (profileId != null) {
      $result.profileId = profileId;
    }
    if (deviceId != null) {
      $result.deviceId = deviceId;
    }
    if (pubkeyHash != null) {
      $result.pubkeyHash = pubkeyHash;
    }
    if (deviceKeyId != null) {
      $result.deviceKeyId = deviceKeyId;
    }
    if (consume != null) {
      $result.consume = consume;
    }
    return $result;
  }
  VerifyGenesisSessionProofRequest._() : super();
  factory VerifyGenesisSessionProofRequest.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory VerifyGenesisSessionProofRequest.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'VerifyGenesisSessionProofRequest', package: const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'), createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'token')
    ..aOS(2, _omitFieldNames ? '' : 'profileId')
    ..aOS(3, _omitFieldNames ? '' : 'deviceId')
    ..aOS(4, _omitFieldNames ? '' : 'pubkeyHash')
    ..aOS(5, _omitFieldNames ? '' : 'deviceKeyId')
    ..aOB(6, _omitFieldNames ? '' : 'consume')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  VerifyGenesisSessionProofRequest clone() => VerifyGenesisSessionProofRequest()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  VerifyGenesisSessionProofRequest copyWith(void Function(VerifyGenesisSessionProofRequest) updates) => super.copyWith((message) => updates(message as VerifyGenesisSessionProofRequest)) as VerifyGenesisSessionProofRequest;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static VerifyGenesisSessionProofRequest create() => VerifyGenesisSessionProofRequest._();
  VerifyGenesisSessionProofRequest createEmptyInstance() => create();
  static $pb.PbList<VerifyGenesisSessionProofRequest> createRepeated() => $pb.PbList<VerifyGenesisSessionProofRequest>();
  @$core.pragma('dart2js:noInline')
  static VerifyGenesisSessionProofRequest getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<VerifyGenesisSessionProofRequest>(create);
  static VerifyGenesisSessionProofRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get token => $_getSZ(0);
  @$pb.TagNumber(1)
  set token($core.String v) { $_setString(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasToken() => $_has(0);
  @$pb.TagNumber(1)
  void clearToken() => clearField(1);

  @$pb.TagNumber(2)
  $core.String get profileId => $_getSZ(1);
  @$pb.TagNumber(2)
  set profileId($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasProfileId() => $_has(1);
  @$pb.TagNumber(2)
  void clearProfileId() => clearField(2);

  @$pb.TagNumber(3)
  $core.String get deviceId => $_getSZ(2);
  @$pb.TagNumber(3)
  set deviceId($core.String v) { $_setString(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasDeviceId() => $_has(2);
  @$pb.TagNumber(3)
  void clearDeviceId() => clearField(3);

  @$pb.TagNumber(4)
  $core.String get pubkeyHash => $_getSZ(3);
  @$pb.TagNumber(4)
  set pubkeyHash($core.String v) { $_setString(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasPubkeyHash() => $_has(3);
  @$pb.TagNumber(4)
  void clearPubkeyHash() => clearField(4);

  @$pb.TagNumber(5)
  $core.String get deviceKeyId => $_getSZ(4);
  @$pb.TagNumber(5)
  set deviceKeyId($core.String v) { $_setString(4, v); }
  @$pb.TagNumber(5)
  $core.bool hasDeviceKeyId() => $_has(4);
  @$pb.TagNumber(5)
  void clearDeviceKeyId() => clearField(5);

  /// Spend the nonce. A consumer about to act on the proof sets it.
  @$pb.TagNumber(6)
  $core.bool get consume => $_getBF(5);
  @$pb.TagNumber(6)
  set consume($core.bool v) { $_setBool(5, v); }
  @$pb.TagNumber(6)
  $core.bool hasConsume() => $_has(5);
  @$pb.TagNumber(6)
  void clearConsume() => clearField(6);
}

class VerifyGenesisSessionProofResponse extends $pb.GeneratedMessage {
  factory VerifyGenesisSessionProofResponse({
    $core.bool? valid,
    $core.String? reason,
    GenesisSessionProofClaims? claims,
    $core.String? bindingHash,
  }) {
    final $result = create();
    if (valid != null) {
      $result.valid = valid;
    }
    if (reason != null) {
      $result.reason = reason;
    }
    if (claims != null) {
      $result.claims = claims;
    }
    if (bindingHash != null) {
      $result.bindingHash = bindingHash;
    }
    return $result;
  }
  VerifyGenesisSessionProofResponse._() : super();
  factory VerifyGenesisSessionProofResponse.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory VerifyGenesisSessionProofResponse.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(_omitMessageNames ? '' : 'VerifyGenesisSessionProofResponse', package: const $pb.PackageName(_omitMessageNames ? '' : 'authentication.v1'), createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'valid')
    ..aOS(2, _omitFieldNames ? '' : 'reason')
    ..aOM<GenesisSessionProofClaims>(3, _omitFieldNames ? '' : 'claims', subBuilder: GenesisSessionProofClaims.create)
    ..aOS(4, _omitFieldNames ? '' : 'bindingHash')
    ..hasRequiredFields = false
  ;

  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  VerifyGenesisSessionProofResponse clone() => VerifyGenesisSessionProofResponse()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  VerifyGenesisSessionProofResponse copyWith(void Function(VerifyGenesisSessionProofResponse) updates) => super.copyWith((message) => updates(message as VerifyGenesisSessionProofResponse)) as VerifyGenesisSessionProofResponse;

  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static VerifyGenesisSessionProofResponse create() => VerifyGenesisSessionProofResponse._();
  VerifyGenesisSessionProofResponse createEmptyInstance() => create();
  static $pb.PbList<VerifyGenesisSessionProofResponse> createRepeated() => $pb.PbList<VerifyGenesisSessionProofResponse>();
  @$core.pragma('dart2js:noInline')
  static VerifyGenesisSessionProofResponse getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<VerifyGenesisSessionProofResponse>(create);
  static VerifyGenesisSessionProofResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get valid => $_getBF(0);
  @$pb.TagNumber(1)
  set valid($core.bool v) { $_setBool(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasValid() => $_has(0);
  @$pb.TagNumber(1)
  void clearValid() => clearField(1);

  /// Why the proof was refused, when it was.
  @$pb.TagNumber(2)
  $core.String get reason => $_getSZ(1);
  @$pb.TagNumber(2)
  set reason($core.String v) { $_setString(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasReason() => $_has(1);
  @$pb.TagNumber(2)
  void clearReason() => clearField(2);

  @$pb.TagNumber(3)
  GenesisSessionProofClaims get claims => $_getN(2);
  @$pb.TagNumber(3)
  set claims(GenesisSessionProofClaims v) { setField(3, v); }
  @$pb.TagNumber(3)
  $core.bool hasClaims() => $_has(2);
  @$pb.TagNumber(3)
  void clearClaims() => clearField(3);
  @$pb.TagNumber(3)
  GenesisSessionProofClaims ensureClaims() => $_ensure(2);

  /// Lowercase hex SHA-256 of the binding pre-image.
  @$pb.TagNumber(4)
  $core.String get bindingHash => $_getSZ(3);
  @$pb.TagNumber(4)
  set bindingHash($core.String v) { $_setString(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasBindingHash() => $_has(3);
  @$pb.TagNumber(4)
  void clearBindingHash() => clearField(4);
}

class AuthenticationServiceApi {
  $pb.RpcClient _client;
  AuthenticationServiceApi(this._client);

  $async.Future<GetLoginEventResponse> getLoginEvent($pb.ClientContext? ctx, GetLoginEventRequest request) =>
    _client.invoke<GetLoginEventResponse>(ctx, 'AuthenticationService', 'GetLoginEvent', request, GetLoginEventResponse())
  ;
  $async.Future<ListLoginEventsResponse> listLoginEvents($pb.ClientContext? ctx, ListLoginEventsRequest request) =>
    _client.invoke<ListLoginEventsResponse>(ctx, 'AuthenticationService', 'ListLoginEvents', request, ListLoginEventsResponse())
  ;
  $async.Future<IssueGenesisSessionProofResponse> issueGenesisSessionProof($pb.ClientContext? ctx, IssueGenesisSessionProofRequest request) =>
    _client.invoke<IssueGenesisSessionProofResponse>(ctx, 'AuthenticationService', 'IssueGenesisSessionProof', request, IssueGenesisSessionProofResponse())
  ;
  $async.Future<VerifyGenesisSessionProofResponse> verifyGenesisSessionProof($pb.ClientContext? ctx, VerifyGenesisSessionProofRequest request) =>
    _client.invoke<VerifyGenesisSessionProofResponse>(ctx, 'AuthenticationService', 'VerifyGenesisSessionProof', request, VerifyGenesisSessionProofResponse())
  ;
}


const _omitFieldNames = $core.bool.fromEnvironment('protobuf.omit_field_names');
const _omitMessageNames = $core.bool.fromEnvironment('protobuf.omit_message_names');
