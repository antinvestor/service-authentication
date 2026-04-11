//
//  Generated code. Do not modify.
//  source: audit/v1/audit.proto
//
// @dart = 2.12

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_final_fields
// ignore_for_file: unnecessary_import, unnecessary_this, unused_import

import 'dart:convert' as $convert;
import 'dart:core' as $core;
import 'dart:typed_data' as $typed_data;

import '../../google/protobuf/struct.pbjson.dart' as $6;
import '../../google/protobuf/timestamp.pbjson.dart' as $2;

@$core.Deprecated('Use auditEntryObjectDescriptor instead')
const AuditEntryObject$json = {
  '1': 'AuditEntryObject',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '10': 'id'},
    {'1': 'tenant_id', '3': 2, '4': 1, '5': 9, '10': 'tenantId'},
    {'1': 'partition_id', '3': 3, '4': 1, '5': 9, '10': 'partitionId'},
    {'1': 'profile_id', '3': 4, '4': 1, '5': 9, '10': 'profileId'},
    {'1': 'action', '3': 5, '4': 1, '5': 9, '10': 'action'},
    {'1': 'resource_type', '3': 6, '4': 1, '5': 9, '10': 'resourceType'},
    {'1': 'resource_id', '3': 7, '4': 1, '5': 9, '10': 'resourceId'},
    {'1': 'service', '3': 8, '4': 1, '5': 9, '10': 'service'},
    {'1': 'details', '3': 9, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'details'},
    {'1': 'ip_address', '3': 10, '4': 1, '5': 9, '10': 'ipAddress'},
    {'1': 'user_agent', '3': 11, '4': 1, '5': 9, '10': 'userAgent'},
    {'1': 'device_id', '3': 12, '4': 1, '5': 9, '10': 'deviceId'},
    {'1': 'target_profile_id', '3': 13, '4': 1, '5': 9, '10': 'targetProfileId'},
    {'1': 'trace_id', '3': 14, '4': 1, '5': 9, '10': 'traceId'},
    {'1': 'created_at', '3': 15, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'createdAt'},
    {'1': 'previous_hash', '3': 16, '4': 1, '5': 9, '10': 'previousHash'},
    {'1': 'entry_hash', '3': 17, '4': 1, '5': 9, '10': 'entryHash'},
    {'1': 'signature', '3': 18, '4': 1, '5': 9, '10': 'signature'},
  ],
};

/// Descriptor for `AuditEntryObject`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List auditEntryObjectDescriptor = $convert.base64Decode(
    'ChBBdWRpdEVudHJ5T2JqZWN0Eg4KAmlkGAEgASgJUgJpZBIbCgl0ZW5hbnRfaWQYAiABKAlSCH'
    'RlbmFudElkEiEKDHBhcnRpdGlvbl9pZBgDIAEoCVILcGFydGl0aW9uSWQSHQoKcHJvZmlsZV9p'
    'ZBgEIAEoCVIJcHJvZmlsZUlkEhYKBmFjdGlvbhgFIAEoCVIGYWN0aW9uEiMKDXJlc291cmNlX3'
    'R5cGUYBiABKAlSDHJlc291cmNlVHlwZRIfCgtyZXNvdXJjZV9pZBgHIAEoCVIKcmVzb3VyY2VJ'
    'ZBIYCgdzZXJ2aWNlGAggASgJUgdzZXJ2aWNlEjEKB2RldGFpbHMYCSABKAsyFy5nb29nbGUucH'
    'JvdG9idWYuU3RydWN0UgdkZXRhaWxzEh0KCmlwX2FkZHJlc3MYCiABKAlSCWlwQWRkcmVzcxId'
    'Cgp1c2VyX2FnZW50GAsgASgJUgl1c2VyQWdlbnQSGwoJZGV2aWNlX2lkGAwgASgJUghkZXZpY2'
    'VJZBIqChF0YXJnZXRfcHJvZmlsZV9pZBgNIAEoCVIPdGFyZ2V0UHJvZmlsZUlkEhkKCHRyYWNl'
    'X2lkGA4gASgJUgd0cmFjZUlkEjkKCmNyZWF0ZWRfYXQYDyABKAsyGi5nb29nbGUucHJvdG9idW'
    'YuVGltZXN0YW1wUgljcmVhdGVkQXQSIwoNcHJldmlvdXNfaGFzaBgQIAEoCVIMcHJldmlvdXNI'
    'YXNoEh0KCmVudHJ5X2hhc2gYESABKAlSCWVudHJ5SGFzaBIcCglzaWduYXR1cmUYEiABKAlSCX'
    'NpZ25hdHVyZQ==');

@$core.Deprecated('Use createAuditEntryRequestDescriptor instead')
const CreateAuditEntryRequest$json = {
  '1': 'CreateAuditEntryRequest',
  '2': [
    {'1': 'profile_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'profileId'},
    {'1': 'action', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'action'},
    {'1': 'resource_type', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'resourceType'},
    {'1': 'resource_id', '3': 4, '4': 1, '5': 9, '10': 'resourceId'},
    {'1': 'service', '3': 5, '4': 1, '5': 9, '8': {}, '10': 'service'},
    {'1': 'details', '3': 6, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'details'},
    {'1': 'ip_address', '3': 7, '4': 1, '5': 9, '10': 'ipAddress'},
    {'1': 'user_agent', '3': 8, '4': 1, '5': 9, '10': 'userAgent'},
    {'1': 'device_id', '3': 9, '4': 1, '5': 9, '10': 'deviceId'},
    {'1': 'target_profile_id', '3': 10, '4': 1, '5': 9, '10': 'targetProfileId'},
    {'1': 'trace_id', '3': 11, '4': 1, '5': 9, '10': 'traceId'},
  ],
};

/// Descriptor for `CreateAuditEntryRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createAuditEntryRequestDescriptor = $convert.base64Decode(
    'ChdDcmVhdGVBdWRpdEVudHJ5UmVxdWVzdBImCgpwcm9maWxlX2lkGAEgASgJQge6SARyAhABUg'
    'lwcm9maWxlSWQSHwoGYWN0aW9uGAIgASgJQge6SARyAhABUgZhY3Rpb24SLAoNcmVzb3VyY2Vf'
    'dHlwZRgDIAEoCUIHukgEcgIQAVIMcmVzb3VyY2VUeXBlEh8KC3Jlc291cmNlX2lkGAQgASgJUg'
    'pyZXNvdXJjZUlkEiEKB3NlcnZpY2UYBSABKAlCB7pIBHICEAFSB3NlcnZpY2USMQoHZGV0YWls'
    'cxgGIAEoCzIXLmdvb2dsZS5wcm90b2J1Zi5TdHJ1Y3RSB2RldGFpbHMSHQoKaXBfYWRkcmVzcx'
    'gHIAEoCVIJaXBBZGRyZXNzEh0KCnVzZXJfYWdlbnQYCCABKAlSCXVzZXJBZ2VudBIbCglkZXZp'
    'Y2VfaWQYCSABKAlSCGRldmljZUlkEioKEXRhcmdldF9wcm9maWxlX2lkGAogASgJUg90YXJnZX'
    'RQcm9maWxlSWQSGQoIdHJhY2VfaWQYCyABKAlSB3RyYWNlSWQ=');

@$core.Deprecated('Use createAuditEntryResponseDescriptor instead')
const CreateAuditEntryResponse$json = {
  '1': 'CreateAuditEntryResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.audit.v1.AuditEntryObject', '10': 'data'},
  ],
};

/// Descriptor for `CreateAuditEntryResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createAuditEntryResponseDescriptor = $convert.base64Decode(
    'ChhDcmVhdGVBdWRpdEVudHJ5UmVzcG9uc2USLgoEZGF0YRgBIAEoCzIaLmF1ZGl0LnYxLkF1ZG'
    'l0RW50cnlPYmplY3RSBGRhdGE=');

@$core.Deprecated('Use batchCreateAuditEntriesRequestDescriptor instead')
const BatchCreateAuditEntriesRequest$json = {
  '1': 'BatchCreateAuditEntriesRequest',
  '2': [
    {'1': 'entries', '3': 1, '4': 3, '5': 11, '6': '.audit.v1.CreateAuditEntryRequest', '8': {}, '10': 'entries'},
  ],
};

/// Descriptor for `BatchCreateAuditEntriesRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List batchCreateAuditEntriesRequestDescriptor = $convert.base64Decode(
    'Ch5CYXRjaENyZWF0ZUF1ZGl0RW50cmllc1JlcXVlc3QSRwoHZW50cmllcxgBIAMoCzIhLmF1ZG'
    'l0LnYxLkNyZWF0ZUF1ZGl0RW50cnlSZXF1ZXN0Qgq6SAeSAQQIARBkUgdlbnRyaWVz');

@$core.Deprecated('Use batchCreateAuditEntriesResponseDescriptor instead')
const BatchCreateAuditEntriesResponse$json = {
  '1': 'BatchCreateAuditEntriesResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.audit.v1.AuditEntryObject', '10': 'data'},
  ],
};

/// Descriptor for `BatchCreateAuditEntriesResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List batchCreateAuditEntriesResponseDescriptor = $convert.base64Decode(
    'Ch9CYXRjaENyZWF0ZUF1ZGl0RW50cmllc1Jlc3BvbnNlEi4KBGRhdGEYASADKAsyGi5hdWRpdC'
    '52MS5BdWRpdEVudHJ5T2JqZWN0UgRkYXRh');

@$core.Deprecated('Use getAuditEntryRequestDescriptor instead')
const GetAuditEntryRequest$json = {
  '1': 'GetAuditEntryRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `GetAuditEntryRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getAuditEntryRequestDescriptor = $convert.base64Decode(
    'ChRHZXRBdWRpdEVudHJ5UmVxdWVzdBIXCgJpZBgBIAEoCUIHukgEcgIQAVICaWQ=');

@$core.Deprecated('Use getAuditEntryResponseDescriptor instead')
const GetAuditEntryResponse$json = {
  '1': 'GetAuditEntryResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.audit.v1.AuditEntryObject', '10': 'data'},
  ],
};

/// Descriptor for `GetAuditEntryResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getAuditEntryResponseDescriptor = $convert.base64Decode(
    'ChVHZXRBdWRpdEVudHJ5UmVzcG9uc2USLgoEZGF0YRgBIAEoCzIaLmF1ZGl0LnYxLkF1ZGl0RW'
    '50cnlPYmplY3RSBGRhdGE=');

@$core.Deprecated('Use listAuditEntriesRequestDescriptor instead')
const ListAuditEntriesRequest$json = {
  '1': 'ListAuditEntriesRequest',
  '2': [
    {'1': 'profile_id', '3': 1, '4': 1, '5': 9, '10': 'profileId'},
    {'1': 'action', '3': 2, '4': 1, '5': 9, '10': 'action'},
    {'1': 'resource_type', '3': 3, '4': 1, '5': 9, '10': 'resourceType'},
    {'1': 'resource_id', '3': 4, '4': 1, '5': 9, '10': 'resourceId'},
    {'1': 'service', '3': 5, '4': 1, '5': 9, '10': 'service'},
    {'1': 'target_profile_id', '3': 6, '4': 1, '5': 9, '10': 'targetProfileId'},
    {'1': 'device_id', '3': 7, '4': 1, '5': 9, '10': 'deviceId'},
    {'1': 'start_date', '3': 8, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'startDate'},
    {'1': 'end_date', '3': 9, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'endDate'},
    {'1': 'count', '3': 10, '4': 1, '5': 5, '10': 'count'},
    {'1': 'page', '3': 11, '4': 1, '5': 9, '10': 'page'},
  ],
};

/// Descriptor for `ListAuditEntriesRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listAuditEntriesRequestDescriptor = $convert.base64Decode(
    'ChdMaXN0QXVkaXRFbnRyaWVzUmVxdWVzdBIdCgpwcm9maWxlX2lkGAEgASgJUglwcm9maWxlSW'
    'QSFgoGYWN0aW9uGAIgASgJUgZhY3Rpb24SIwoNcmVzb3VyY2VfdHlwZRgDIAEoCVIMcmVzb3Vy'
    'Y2VUeXBlEh8KC3Jlc291cmNlX2lkGAQgASgJUgpyZXNvdXJjZUlkEhgKB3NlcnZpY2UYBSABKA'
    'lSB3NlcnZpY2USKgoRdGFyZ2V0X3Byb2ZpbGVfaWQYBiABKAlSD3RhcmdldFByb2ZpbGVJZBIb'
    'CglkZXZpY2VfaWQYByABKAlSCGRldmljZUlkEjkKCnN0YXJ0X2RhdGUYCCABKAsyGi5nb29nbG'
    'UucHJvdG9idWYuVGltZXN0YW1wUglzdGFydERhdGUSNQoIZW5kX2RhdGUYCSABKAsyGi5nb29n'
    'bGUucHJvdG9idWYuVGltZXN0YW1wUgdlbmREYXRlEhQKBWNvdW50GAogASgFUgVjb3VudBISCg'
    'RwYWdlGAsgASgJUgRwYWdl');

@$core.Deprecated('Use listAuditEntriesResponseDescriptor instead')
const ListAuditEntriesResponse$json = {
  '1': 'ListAuditEntriesResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.audit.v1.AuditEntryObject', '10': 'data'},
  ],
};

/// Descriptor for `ListAuditEntriesResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listAuditEntriesResponseDescriptor = $convert.base64Decode(
    'ChhMaXN0QXVkaXRFbnRyaWVzUmVzcG9uc2USLgoEZGF0YRgBIAMoCzIaLmF1ZGl0LnYxLkF1ZG'
    'l0RW50cnlPYmplY3RSBGRhdGE=');

@$core.Deprecated('Use searchAuditEntriesRequestDescriptor instead')
const SearchAuditEntriesRequest$json = {
  '1': 'SearchAuditEntriesRequest',
  '2': [
    {'1': 'query', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'query'},
    {'1': 'start_date', '3': 2, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'startDate'},
    {'1': 'end_date', '3': 3, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'endDate'},
    {'1': 'count', '3': 4, '4': 1, '5': 5, '10': 'count'},
    {'1': 'page', '3': 5, '4': 1, '5': 9, '10': 'page'},
  ],
};

/// Descriptor for `SearchAuditEntriesRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List searchAuditEntriesRequestDescriptor = $convert.base64Decode(
    'ChlTZWFyY2hBdWRpdEVudHJpZXNSZXF1ZXN0Eh0KBXF1ZXJ5GAEgASgJQge6SARyAhABUgVxdW'
    'VyeRI5CgpzdGFydF9kYXRlGAIgASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcFIJc3Rh'
    'cnREYXRlEjUKCGVuZF9kYXRlGAMgASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcFIHZW'
    '5kRGF0ZRIUCgVjb3VudBgEIAEoBVIFY291bnQSEgoEcGFnZRgFIAEoCVIEcGFnZQ==');

@$core.Deprecated('Use searchAuditEntriesResponseDescriptor instead')
const SearchAuditEntriesResponse$json = {
  '1': 'SearchAuditEntriesResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.audit.v1.AuditEntryObject', '10': 'data'},
  ],
};

/// Descriptor for `SearchAuditEntriesResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List searchAuditEntriesResponseDescriptor = $convert.base64Decode(
    'ChpTZWFyY2hBdWRpdEVudHJpZXNSZXNwb25zZRIuCgRkYXRhGAEgAygLMhouYXVkaXQudjEuQX'
    'VkaXRFbnRyeU9iamVjdFIEZGF0YQ==');

@$core.Deprecated('Use verifyIntegrityRequestDescriptor instead')
const VerifyIntegrityRequest$json = {
  '1': 'VerifyIntegrityRequest',
  '2': [
    {'1': 'start_date', '3': 1, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'startDate'},
    {'1': 'end_date', '3': 2, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'endDate'},
  ],
};

/// Descriptor for `VerifyIntegrityRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List verifyIntegrityRequestDescriptor = $convert.base64Decode(
    'ChZWZXJpZnlJbnRlZ3JpdHlSZXF1ZXN0EjkKCnN0YXJ0X2RhdGUYASABKAsyGi5nb29nbGUucH'
    'JvdG9idWYuVGltZXN0YW1wUglzdGFydERhdGUSNQoIZW5kX2RhdGUYAiABKAsyGi5nb29nbGUu'
    'cHJvdG9idWYuVGltZXN0YW1wUgdlbmREYXRl');

@$core.Deprecated('Use verifyIntegrityResponseDescriptor instead')
const VerifyIntegrityResponse$json = {
  '1': 'VerifyIntegrityResponse',
  '2': [
    {'1': 'valid', '3': 1, '4': 1, '5': 8, '10': 'valid'},
    {'1': 'entries_verified', '3': 2, '4': 1, '5': 3, '10': 'entriesVerified'},
    {'1': 'first_invalid_entry_id', '3': 3, '4': 1, '5': 9, '10': 'firstInvalidEntryId'},
    {'1': 'message', '3': 4, '4': 1, '5': 9, '10': 'message'},
  ],
};

/// Descriptor for `VerifyIntegrityResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List verifyIntegrityResponseDescriptor = $convert.base64Decode(
    'ChdWZXJpZnlJbnRlZ3JpdHlSZXNwb25zZRIUCgV2YWxpZBgBIAEoCFIFdmFsaWQSKQoQZW50cm'
    'llc192ZXJpZmllZBgCIAEoA1IPZW50cmllc1ZlcmlmaWVkEjMKFmZpcnN0X2ludmFsaWRfZW50'
    'cnlfaWQYAyABKAlSE2ZpcnN0SW52YWxpZEVudHJ5SWQSGAoHbWVzc2FnZRgEIAEoCVIHbWVzc2'
    'FnZQ==');

const $core.Map<$core.String, $core.dynamic> AuditServiceBase$json = {
  '1': 'AuditService',
  '2': [
    {'1': 'CreateAuditEntry', '2': '.audit.v1.CreateAuditEntryRequest', '3': '.audit.v1.CreateAuditEntryResponse', '4': {}},
    {'1': 'BatchCreateAuditEntries', '2': '.audit.v1.BatchCreateAuditEntriesRequest', '3': '.audit.v1.BatchCreateAuditEntriesResponse', '4': {}},
    {
      '1': 'GetAuditEntry',
      '2': '.audit.v1.GetAuditEntryRequest',
      '3': '.audit.v1.GetAuditEntryResponse',
      '4': {'34': 1},
    },
    {
      '1': 'ListAuditEntries',
      '2': '.audit.v1.ListAuditEntriesRequest',
      '3': '.audit.v1.ListAuditEntriesResponse',
      '4': {'34': 1},
      '6': true,
    },
    {
      '1': 'SearchAuditEntries',
      '2': '.audit.v1.SearchAuditEntriesRequest',
      '3': '.audit.v1.SearchAuditEntriesResponse',
      '4': {'34': 1},
      '6': true,
    },
    {
      '1': 'VerifyIntegrity',
      '2': '.audit.v1.VerifyIntegrityRequest',
      '3': '.audit.v1.VerifyIntegrityResponse',
      '4': {'34': 1},
    },
  ],
  '3': {},
};

@$core.Deprecated('Use auditServiceDescriptor instead')
const $core.Map<$core.String, $core.Map<$core.String, $core.dynamic>> AuditServiceBase$messageJson = {
  '.audit.v1.CreateAuditEntryRequest': CreateAuditEntryRequest$json,
  '.google.protobuf.Struct': $6.Struct$json,
  '.google.protobuf.Struct.FieldsEntry': $6.Struct_FieldsEntry$json,
  '.google.protobuf.Value': $6.Value$json,
  '.google.protobuf.ListValue': $6.ListValue$json,
  '.audit.v1.CreateAuditEntryResponse': CreateAuditEntryResponse$json,
  '.audit.v1.AuditEntryObject': AuditEntryObject$json,
  '.google.protobuf.Timestamp': $2.Timestamp$json,
  '.audit.v1.BatchCreateAuditEntriesRequest': BatchCreateAuditEntriesRequest$json,
  '.audit.v1.BatchCreateAuditEntriesResponse': BatchCreateAuditEntriesResponse$json,
  '.audit.v1.GetAuditEntryRequest': GetAuditEntryRequest$json,
  '.audit.v1.GetAuditEntryResponse': GetAuditEntryResponse$json,
  '.audit.v1.ListAuditEntriesRequest': ListAuditEntriesRequest$json,
  '.audit.v1.ListAuditEntriesResponse': ListAuditEntriesResponse$json,
  '.audit.v1.SearchAuditEntriesRequest': SearchAuditEntriesRequest$json,
  '.audit.v1.SearchAuditEntriesResponse': SearchAuditEntriesResponse$json,
  '.audit.v1.VerifyIntegrityRequest': VerifyIntegrityRequest$json,
  '.audit.v1.VerifyIntegrityResponse': VerifyIntegrityResponse$json,
};

/// Descriptor for `AuditService`. Decode as a `google.protobuf.ServiceDescriptorProto`.
final $typed_data.Uint8List auditServiceDescriptor = $convert.base64Decode(
    'CgxBdWRpdFNlcnZpY2USlAIKEENyZWF0ZUF1ZGl0RW50cnkSIS5hdWRpdC52MS5DcmVhdGVBdW'
    'RpdEVudHJ5UmVxdWVzdBoiLmF1ZGl0LnYxLkNyZWF0ZUF1ZGl0RW50cnlSZXNwb25zZSK4AbpH'
    'ogEKBUF1ZGl0EhJDcmVhdGUgYXVkaXQgZW50cnkac0FwcGVuZHMgYSBuZXcgdGFtcGVyLXByb2'
    '9mIGVudHJ5IHRvIHRoZSBhdWRpdCB0cmFpbC4gVGhlIGhhc2ggY2hhaW4gYW5kIGRpZ2l0YWwg'
    'c2lnbmF0dXJlIGFyZSBjb21wdXRlZCBzZXJ2ZXItc2lkZS4qEGNyZWF0ZUF1ZGl0RW50cnmCtR'
    'gOCgxhdWRpdF9jcmVhdGUSlgIKF0JhdGNoQ3JlYXRlQXVkaXRFbnRyaWVzEiguYXVkaXQudjEu'
    'QmF0Y2hDcmVhdGVBdWRpdEVudHJpZXNSZXF1ZXN0GikuYXVkaXQudjEuQmF0Y2hDcmVhdGVBdW'
    'RpdEVudHJpZXNSZXNwb25zZSKlAbpHjwEKBUF1ZGl0EhpCYXRjaCBjcmVhdGUgYXVkaXQgZW50'
    'cmllcxpRQXBwZW5kcyBtdWx0aXBsZSBhdWRpdCBlbnRyaWVzIGF0b21pY2FsbHkuIEFsbCBlbn'
    'RyaWVzIHNoYXJlIHRoZSBzYW1lIGhhc2ggY2hhaW4uKhdiYXRjaENyZWF0ZUF1ZGl0RW50cmll'
    'c4K1GA4KDGF1ZGl0X2NyZWF0ZRLJAQoNR2V0QXVkaXRFbnRyeRIeLmF1ZGl0LnYxLkdldEF1ZG'
    'l0RW50cnlSZXF1ZXN0Gh8uYXVkaXQudjEuR2V0QXVkaXRFbnRyeVJlc3BvbnNlIneQAgG6R2EK'
    'BUF1ZGl0Eg9HZXQgYXVkaXQgZW50cnkaOFJldHJpZXZlcyBhIHNpbmdsZSBhdWRpdCBlbnRyeS'
    'BieSBpdHMgdW5pcXVlIGlkZW50aWZpZXIuKg1nZXRBdWRpdEVudHJ5grUYDAoKYXVkaXRfdmll'
    'dxKHAgoQTGlzdEF1ZGl0RW50cmllcxIhLmF1ZGl0LnYxLkxpc3RBdWRpdEVudHJpZXNSZXF1ZX'
    'N0GiIuYXVkaXQudjEuTGlzdEF1ZGl0RW50cmllc1Jlc3BvbnNlIqkBkAIBukeSAQoFQXVkaXQS'
    'Ekxpc3QgYXVkaXQgZW50cmllcxpjTGlzdHMgYXVkaXQgZW50cmllcyB3aXRoIGZpbHRlcmluZy'
    'BieSBhY3RvciwgYWN0aW9uLCByZXNvdXJjZSwgc2VydmljZSwgdGltZSByYW5nZSwgYW5kIHBh'
    'Z2luYXRpb24uKhBsaXN0QXVkaXRFbnRyaWVzgrUYDAoKYXVkaXRfdmlldzABEoMCChJTZWFyY2'
    'hBdWRpdEVudHJpZXMSIy5hdWRpdC52MS5TZWFyY2hBdWRpdEVudHJpZXNSZXF1ZXN0GiQuYXVk'
    'aXQudjEuU2VhcmNoQXVkaXRFbnRyaWVzUmVzcG9uc2UinwGQAgG6R4gBCgVBdWRpdBIUU2Vhcm'
    'NoIGF1ZGl0IGVudHJpZXMaVVBlcmZvcm1zIGZyZWUtdGV4dCBzZWFyY2ggYWNyb3NzIGF1ZGl0'
    'IGVudHJpZXMgbWF0Y2hpbmcgYWN0aW9uLCByZXNvdXJjZSwgb3IgZGV0YWlscy4qEnNlYXJjaE'
    'F1ZGl0RW50cmllc4K1GAwKCmF1ZGl0X3ZpZXcwARKxAgoPVmVyaWZ5SW50ZWdyaXR5EiAuYXVk'
    'aXQudjEuVmVyaWZ5SW50ZWdyaXR5UmVxdWVzdBohLmF1ZGl0LnYxLlZlcmlmeUludGVncml0eV'
    'Jlc3BvbnNlItgBkAIBuke/AQoFQXVkaXQSFlZlcmlmeSBhdWRpdCBpbnRlZ3JpdHkajAFWZXJp'
    'ZmllcyB0aGUgaGFzaCBjaGFpbiBhbmQgZGlnaXRhbCBzaWduYXR1cmVzIG9mIGF1ZGl0IGVudH'
    'JpZXMgb3ZlciBhIHRpbWUgcmFuZ2UuIFJldHVybnMgdGhlIGZpcnN0IGludmFsaWQgZW50cnkg'
    'aWYgdGFtcGVyaW5nIGlzIGRldGVjdGVkLioPdmVyaWZ5SW50ZWdyaXR5grUYDgoMYXVkaXRfdm'
    'VyaWZ5GuIBgrUY3QEKDXNlcnZpY2VfYXVkaXQSCmF1ZGl0X3ZpZXcSDGF1ZGl0X2NyZWF0ZRIM'
    'YXVkaXRfdmVyaWZ5GioIARIKYXVkaXRfdmlldxIMYXVkaXRfY3JlYXRlEgxhdWRpdF92ZXJpZn'
    'kaHAgCEgphdWRpdF92aWV3EgxhdWRpdF92ZXJpZnkaDggDEgphdWRpdF92aWV3Gg4IBBIKYXVk'
    'aXRfdmlldxoOCAUSCmF1ZGl0X3ZpZXcaKggGEgphdWRpdF92aWV3EgxhdWRpdF9jcmVhdGUSDG'
    'F1ZGl0X3ZlcmlmeQ==');

