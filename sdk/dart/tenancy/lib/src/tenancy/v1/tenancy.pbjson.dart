//
//  Generated code. Do not modify.
//  source: tenancy/v1/tenancy.proto
//
// @dart = 2.12

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_final_fields
// ignore_for_file: unnecessary_import, unnecessary_this, unused_import

import 'dart:convert' as $convert;
import 'dart:core' as $core;
import 'dart:typed_data' as $typed_data;

import '../../common/v1/common.pbjson.dart' as $7;
import '../../google/protobuf/struct.pbjson.dart' as $6;
import '../../google/protobuf/timestamp.pbjson.dart' as $2;

@$core.Deprecated('Use tenantEnvironmentDescriptor instead')
const TenantEnvironment$json = {
  '1': 'TenantEnvironment',
  '2': [
    {'1': 'TENANT_ENVIRONMENT_UNSPECIFIED', '2': 0},
    {'1': 'TENANT_ENVIRONMENT_PRODUCTION', '2': 1},
    {'1': 'TENANT_ENVIRONMENT_STAGING', '2': 2},
  ],
};

/// Descriptor for `TenantEnvironment`. Decode as a `google.protobuf.EnumDescriptorProto`.
final $typed_data.Uint8List tenantEnvironmentDescriptor = $convert.base64Decode(
    'ChFUZW5hbnRFbnZpcm9ubWVudBIiCh5URU5BTlRfRU5WSVJPTk1FTlRfVU5TUEVDSUZJRUQQAB'
    'IhCh1URU5BTlRfRU5WSVJPTk1FTlRfUFJPRFVDVElPThABEh4KGlRFTkFOVF9FTlZJUk9OTUVO'
    'VF9TVEFHSU5HEAI=');

@$core.Deprecated('Use tenantObjectDescriptor instead')
const TenantObject$json = {
  '1': 'TenantObject',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'description', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'description'},
    {'1': 'properties', '3': 4, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
    {'1': 'created_at', '3': 5, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'createdAt'},
    {'1': 'state', '3': 6, '4': 1, '5': 14, '6': '.common.v1.STATE', '10': 'state'},
    {'1': 'environment', '3': 7, '4': 1, '5': 14, '6': '.tenancy.v1.TenantEnvironment', '8': {}, '10': 'environment'},
  ],
};

/// Descriptor for `TenantObject`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List tenantObjectDescriptor = $convert.base64Decode(
    'CgxUZW5hbnRPYmplY3QSKwoCaWQYASABKAlCG7pIGHIWEAMYKDIQWzAtOWEtel8tXXszLDQwfV'
    'ICaWQSHQoEbmFtZRgCIAEoCUIJukgGcgQQAxhkUgRuYW1lEioKC2Rlc2NyaXB0aW9uGAMgASgJ'
    'Qgi6SAVyAxj0A1ILZGVzY3JpcHRpb24SNwoKcHJvcGVydGllcxgEIAEoCzIXLmdvb2dsZS5wcm'
    '90b2J1Zi5TdHJ1Y3RSCnByb3BlcnRpZXMSOQoKY3JlYXRlZF9hdBgFIAEoCzIaLmdvb2dsZS5w'
    'cm90b2J1Zi5UaW1lc3RhbXBSCWNyZWF0ZWRBdBImCgVzdGF0ZRgGIAEoDjIQLmNvbW1vbi52MS'
    '5TVEFURVIFc3RhdGUSSQoLZW52aXJvbm1lbnQYByABKA4yHS50ZW5hbmN5LnYxLlRlbmFudEVu'
    'dmlyb25tZW50Qgi6SAWCAQIQAVILZW52aXJvbm1lbnQ=');

@$core.Deprecated('Use partitionObjectDescriptor instead')
const PartitionObject$json = {
  '1': 'PartitionObject',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'tenant_id', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'tenantId'},
    {'1': 'parent_id', '3': 4, '4': 1, '5': 9, '8': {}, '10': 'parentId'},
    {'1': 'description', '3': 5, '4': 1, '5': 9, '8': {}, '10': 'description'},
    {'1': 'state', '3': 6, '4': 1, '5': 14, '6': '.common.v1.STATE', '10': 'state'},
    {'1': 'properties', '3': 7, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
    {'1': 'created_at', '3': 8, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'createdAt'},
    {'1': 'domain', '3': 9, '4': 1, '5': 9, '8': {}, '10': 'domain'},
  ],
};

/// Descriptor for `PartitionObject`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List partitionObjectDescriptor = $convert.base64Decode(
    'Cg9QYXJ0aXRpb25PYmplY3QSKwoCaWQYASABKAlCG7pIGHIWEAMYKDIQWzAtOWEtel8tXXszLD'
    'QwfVICaWQSHQoEbmFtZRgCIAEoCUIJukgGcgQQAxhkUgRuYW1lEjgKCXRlbmFudF9pZBgDIAEo'
    'CUIbukgYchYQAxgoMhBbMC05YS16Xy1dezMsNDB9Ugh0ZW5hbnRJZBI7CglwYXJlbnRfaWQYBC'
    'ABKAlCHrpIG9gBAXIWEAMYKDIQWzAtOWEtel8tXXszLDQwfVIIcGFyZW50SWQSKgoLZGVzY3Jp'
    'cHRpb24YBSABKAlCCLpIBXIDGPQDUgtkZXNjcmlwdGlvbhImCgVzdGF0ZRgGIAEoDjIQLmNvbW'
    '1vbi52MS5TVEFURVIFc3RhdGUSNwoKcHJvcGVydGllcxgHIAEoCzIXLmdvb2dsZS5wcm90b2J1'
    'Zi5TdHJ1Y3RSCnByb3BlcnRpZXMSOQoKY3JlYXRlZF9hdBgIIAEoCzIaLmdvb2dsZS5wcm90b2'
    'J1Zi5UaW1lc3RhbXBSCWNyZWF0ZWRBdBIjCgZkb21haW4YCSABKAlCC7pICNgBAXIDGP8BUgZk'
    'b21haW4=');

@$core.Deprecated('Use partitionRoleObjectDescriptor instead')
const PartitionRoleObject$json = {
  '1': 'PartitionRoleObject',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'partition_id', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
    {'1': 'name', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'properties', '3': 4, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
    {'1': 'created_at', '3': 5, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'createdAt'},
    {'1': 'state', '3': 6, '4': 1, '5': 14, '6': '.common.v1.STATE', '10': 'state'},
  ],
};

/// Descriptor for `PartitionRoleObject`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List partitionRoleObjectDescriptor = $convert.base64Decode(
    'ChNQYXJ0aXRpb25Sb2xlT2JqZWN0EisKAmlkGAEgASgJQhu6SBhyFhADGCgyEFswLTlhLXpfLV'
    '17Myw0MH1SAmlkEj4KDHBhcnRpdGlvbl9pZBgCIAEoCUIbukgYchYQAxgoMhBbMC05YS16Xy1d'
    'ezMsNDB9UgtwYXJ0aXRpb25JZBIdCgRuYW1lGAMgASgJQgm6SAZyBBADGGRSBG5hbWUSNwoKcH'
    'JvcGVydGllcxgEIAEoCzIXLmdvb2dsZS5wcm90b2J1Zi5TdHJ1Y3RSCnByb3BlcnRpZXMSOQoK'
    'Y3JlYXRlZF9hdBgFIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXBSCWNyZWF0ZWRBdB'
    'ImCgVzdGF0ZRgGIAEoDjIQLmNvbW1vbi52MS5TVEFURVIFc3RhdGU=');

@$core.Deprecated('Use pageObjectDescriptor instead')
const PageObject$json = {
  '1': 'PageObject',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'html', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'html'},
    {'1': 'state', '3': 4, '4': 1, '5': 14, '6': '.common.v1.STATE', '10': 'state'},
    {'1': 'created_at', '3': 5, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'createdAt'},
    {'1': 'properties', '3': 6, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
    {'1': 'partition_id', '3': 7, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
  ],
};

/// Descriptor for `PageObject`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List pageObjectDescriptor = $convert.base64Decode(
    'CgpQYWdlT2JqZWN0EisKAmlkGAEgASgJQhu6SBhyFhADGCgyEFswLTlhLXpfLV17Myw0MH1SAm'
    'lkEh0KBG5hbWUYAiABKAlCCbpIBnIEEAMYZFIEbmFtZRIeCgRodG1sGAMgASgJQgq6SAdyBRAE'
    'GIgnUgRodG1sEiYKBXN0YXRlGAQgASgOMhAuY29tbW9uLnYxLlNUQVRFUgVzdGF0ZRI5Cgpjcm'
    'VhdGVkX2F0GAUgASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcFIJY3JlYXRlZEF0EjcK'
    'CnByb3BlcnRpZXMYBiABKAsyFy5nb29nbGUucHJvdG9idWYuU3RydWN0Ugpwcm9wZXJ0aWVzEj'
    '4KDHBhcnRpdGlvbl9pZBgHIAEoCUIbukgYchYQAxgoMhBbMC05YS16Xy1dezMsNDB9UgtwYXJ0'
    'aXRpb25JZA==');

@$core.Deprecated('Use accessObjectDescriptor instead')
const AccessObject$json = {
  '1': 'AccessObject',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'profile_id', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'profileId'},
    {'1': 'partition', '3': 3, '4': 1, '5': 11, '6': '.tenancy.v1.PartitionObject', '10': 'partition'},
    {'1': 'state', '3': 4, '4': 1, '5': 14, '6': '.common.v1.STATE', '10': 'state'},
    {'1': 'created_at', '3': 5, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'createdAt'},
  ],
};

/// Descriptor for `AccessObject`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List accessObjectDescriptor = $convert.base64Decode(
    'CgxBY2Nlc3NPYmplY3QSKwoCaWQYASABKAlCG7pIGHIWEAMYKDIQWzAtOWEtel8tXXszLDQwfV'
    'ICaWQSOgoKcHJvZmlsZV9pZBgCIAEoCUIbukgYchYQAxgoMhBbMC05YS16Xy1dezMsNDB9Uglw'
    'cm9maWxlSWQSOQoJcGFydGl0aW9uGAMgASgLMhsudGVuYW5jeS52MS5QYXJ0aXRpb25PYmplY3'
    'RSCXBhcnRpdGlvbhImCgVzdGF0ZRgEIAEoDjIQLmNvbW1vbi52MS5TVEFURVIFc3RhdGUSOQoK'
    'Y3JlYXRlZF9hdBgFIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXBSCWNyZWF0ZWRBdA'
    '==');

@$core.Deprecated('Use accessRoleObjectDescriptor instead')
const AccessRoleObject$json = {
  '1': 'AccessRoleObject',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'access_id', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'accessId'},
    {'1': 'role', '3': 3, '4': 1, '5': 11, '6': '.tenancy.v1.PartitionRoleObject', '10': 'role'},
  ],
};

/// Descriptor for `AccessRoleObject`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List accessRoleObjectDescriptor = $convert.base64Decode(
    'ChBBY2Nlc3NSb2xlT2JqZWN0EisKAmlkGAEgASgJQhu6SBhyFhADGCgyEFswLTlhLXpfLV17My'
    'w0MH1SAmlkEjgKCWFjY2Vzc19pZBgCIAEoCUIbukgYchYQAxgoMhBbMC05YS16Xy1dezMsNDB9'
    'UghhY2Nlc3NJZBIzCgRyb2xlGAMgASgLMh8udGVuYW5jeS52MS5QYXJ0aXRpb25Sb2xlT2JqZW'
    'N0UgRyb2xl');

@$core.Deprecated('Use getTenantRequestDescriptor instead')
const GetTenantRequest$json = {
  '1': 'GetTenantRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `GetTenantRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getTenantRequestDescriptor = $convert.base64Decode(
    'ChBHZXRUZW5hbnRSZXF1ZXN0EisKAmlkGAEgASgJQhu6SBhyFhADGCgyEFswLTlhLXpfLV17My'
    'w0MH1SAmlk');

@$core.Deprecated('Use getTenantResponseDescriptor instead')
const GetTenantResponse$json = {
  '1': 'GetTenantResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.TenantObject', '10': 'data'},
  ],
};

/// Descriptor for `GetTenantResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getTenantResponseDescriptor = $convert.base64Decode(
    'ChFHZXRUZW5hbnRSZXNwb25zZRIsCgRkYXRhGAEgASgLMhgudGVuYW5jeS52MS5UZW5hbnRPYm'
    'plY3RSBGRhdGE=');

@$core.Deprecated('Use listTenantRequestDescriptor instead')
const ListTenantRequest$json = {
  '1': 'ListTenantRequest',
  '2': [
    {'1': 'query', '3': 1, '4': 1, '5': 9, '10': 'query'},
    {'1': 'cursor', '3': 2, '4': 1, '5': 11, '6': '.common.v1.PageCursor', '10': 'cursor'},
    {'1': 'start_date', '3': 4, '4': 1, '5': 9, '10': 'startDate'},
    {'1': 'end_date', '3': 5, '4': 1, '5': 9, '10': 'endDate'},
    {'1': 'properties', '3': 6, '4': 3, '5': 9, '10': 'properties'},
    {'1': 'extras', '3': 7, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'extras'},
    {'1': 'environment', '3': 8, '4': 1, '5': 14, '6': '.tenancy.v1.TenantEnvironment', '8': {}, '10': 'environment'},
  ],
};

/// Descriptor for `ListTenantRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listTenantRequestDescriptor = $convert.base64Decode(
    'ChFMaXN0VGVuYW50UmVxdWVzdBIUCgVxdWVyeRgBIAEoCVIFcXVlcnkSLQoGY3Vyc29yGAIgAS'
    'gLMhUuY29tbW9uLnYxLlBhZ2VDdXJzb3JSBmN1cnNvchIdCgpzdGFydF9kYXRlGAQgASgJUglz'
    'dGFydERhdGUSGQoIZW5kX2RhdGUYBSABKAlSB2VuZERhdGUSHgoKcHJvcGVydGllcxgGIAMoCV'
    'IKcHJvcGVydGllcxIvCgZleHRyYXMYByABKAsyFy5nb29nbGUucHJvdG9idWYuU3RydWN0UgZl'
    'eHRyYXMSSQoLZW52aXJvbm1lbnQYCCABKA4yHS50ZW5hbmN5LnYxLlRlbmFudEVudmlyb25tZW'
    '50Qgi6SAWCAQIQAVILZW52aXJvbm1lbnQ=');

@$core.Deprecated('Use listTenantResponseDescriptor instead')
const ListTenantResponse$json = {
  '1': 'ListTenantResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.tenancy.v1.TenantObject', '10': 'data'},
  ],
};

/// Descriptor for `ListTenantResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listTenantResponseDescriptor = $convert.base64Decode(
    'ChJMaXN0VGVuYW50UmVzcG9uc2USLAoEZGF0YRgBIAMoCzIYLnRlbmFuY3kudjEuVGVuYW50T2'
    'JqZWN0UgRkYXRh');

@$core.Deprecated('Use createTenantRequestDescriptor instead')
const CreateTenantRequest$json = {
  '1': 'CreateTenantRequest',
  '2': [
    {'1': 'name', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'description', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'description'},
    {'1': 'properties', '3': 3, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
    {'1': 'environment', '3': 4, '4': 1, '5': 14, '6': '.tenancy.v1.TenantEnvironment', '8': {}, '10': 'environment'},
  ],
};

/// Descriptor for `CreateTenantRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createTenantRequestDescriptor = $convert.base64Decode(
    'ChNDcmVhdGVUZW5hbnRSZXF1ZXN0Eh0KBG5hbWUYASABKAlCCbpIBnIEEAMYZFIEbmFtZRIsCg'
    'tkZXNjcmlwdGlvbhgCIAEoCUIKukgHcgUQChj0A1ILZGVzY3JpcHRpb24SNwoKcHJvcGVydGll'
    'cxgDIAEoCzIXLmdvb2dsZS5wcm90b2J1Zi5TdHJ1Y3RSCnByb3BlcnRpZXMSSQoLZW52aXJvbm'
    '1lbnQYBCABKA4yHS50ZW5hbmN5LnYxLlRlbmFudEVudmlyb25tZW50Qgi6SAWCAQIQAVILZW52'
    'aXJvbm1lbnQ=');

@$core.Deprecated('Use createTenantResponseDescriptor instead')
const CreateTenantResponse$json = {
  '1': 'CreateTenantResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.TenantObject', '10': 'data'},
  ],
};

/// Descriptor for `CreateTenantResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createTenantResponseDescriptor = $convert.base64Decode(
    'ChRDcmVhdGVUZW5hbnRSZXNwb25zZRIsCgRkYXRhGAEgASgLMhgudGVuYW5jeS52MS5UZW5hbn'
    'RPYmplY3RSBGRhdGE=');

@$core.Deprecated('Use updateTenantRequestDescriptor instead')
const UpdateTenantRequest$json = {
  '1': 'UpdateTenantRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'description', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'description'},
    {'1': 'state', '3': 4, '4': 1, '5': 14, '6': '.common.v1.STATE', '10': 'state'},
    {'1': 'properties', '3': 5, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
    {'1': 'environment', '3': 6, '4': 1, '5': 14, '6': '.tenancy.v1.TenantEnvironment', '8': {}, '10': 'environment'},
  ],
};

/// Descriptor for `UpdateTenantRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List updateTenantRequestDescriptor = $convert.base64Decode(
    'ChNVcGRhdGVUZW5hbnRSZXF1ZXN0EisKAmlkGAEgASgJQhu6SBhyFhADGCgyEFswLTlhLXpfLV'
    '17Myw0MH1SAmlkEiAKBG5hbWUYAiABKAlCDLpICdgBAXIEEAMYZFIEbmFtZRIvCgtkZXNjcmlw'
    'dGlvbhgDIAEoCUINukgK2AEBcgUQChj0A1ILZGVzY3JpcHRpb24SJgoFc3RhdGUYBCABKA4yEC'
    '5jb21tb24udjEuU1RBVEVSBXN0YXRlEjcKCnByb3BlcnRpZXMYBSABKAsyFy5nb29nbGUucHJv'
    'dG9idWYuU3RydWN0Ugpwcm9wZXJ0aWVzEkkKC2Vudmlyb25tZW50GAYgASgOMh0udGVuYW5jeS'
    '52MS5UZW5hbnRFbnZpcm9ubWVudEIIukgFggECEAFSC2Vudmlyb25tZW50');

@$core.Deprecated('Use updateTenantResponseDescriptor instead')
const UpdateTenantResponse$json = {
  '1': 'UpdateTenantResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.TenantObject', '10': 'data'},
  ],
};

/// Descriptor for `UpdateTenantResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List updateTenantResponseDescriptor = $convert.base64Decode(
    'ChRVcGRhdGVUZW5hbnRSZXNwb25zZRIsCgRkYXRhGAEgASgLMhgudGVuYW5jeS52MS5UZW5hbn'
    'RPYmplY3RSBGRhdGE=');

@$core.Deprecated('Use removeTenantRequestDescriptor instead')
const RemoveTenantRequest$json = {
  '1': 'RemoveTenantRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `RemoveTenantRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removeTenantRequestDescriptor = $convert.base64Decode(
    'ChNSZW1vdmVUZW5hbnRSZXF1ZXN0EisKAmlkGAEgASgJQhu6SBhyFhADGCgyEFswLTlhLXpfLV'
    '17Myw0MH1SAmlk');

@$core.Deprecated('Use removeTenantResponseDescriptor instead')
const RemoveTenantResponse$json = {
  '1': 'RemoveTenantResponse',
  '2': [
    {'1': 'succeeded', '3': 1, '4': 1, '5': 8, '10': 'succeeded'},
  ],
};

/// Descriptor for `RemoveTenantResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removeTenantResponseDescriptor = $convert.base64Decode(
    'ChRSZW1vdmVUZW5hbnRSZXNwb25zZRIcCglzdWNjZWVkZWQYASABKAhSCXN1Y2NlZWRlZA==');

@$core.Deprecated('Use getPartitionRequestDescriptor instead')
const GetPartitionRequest$json = {
  '1': 'GetPartitionRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'domain', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'domain'},
  ],
};

/// Descriptor for `GetPartitionRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getPartitionRequestDescriptor = $convert.base64Decode(
    'ChNHZXRQYXJ0aXRpb25SZXF1ZXN0Ei4KAmlkGAEgASgJQh66SBvYAQFyFhADGCgyEFswLTlhLX'
    'pfLV17Myw0MH1SAmlkEiMKBmRvbWFpbhgCIAEoCUILukgI2AEBcgMY/wFSBmRvbWFpbg==');

@$core.Deprecated('Use getPartitionResponseDescriptor instead')
const GetPartitionResponse$json = {
  '1': 'GetPartitionResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.PartitionObject', '10': 'data'},
  ],
};

/// Descriptor for `GetPartitionResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getPartitionResponseDescriptor = $convert.base64Decode(
    'ChRHZXRQYXJ0aXRpb25SZXNwb25zZRIvCgRkYXRhGAEgASgLMhsudGVuYW5jeS52MS5QYXJ0aX'
    'Rpb25PYmplY3RSBGRhdGE=');

@$core.Deprecated('Use getPartitionParentsRequestDescriptor instead')
const GetPartitionParentsRequest$json = {
  '1': 'GetPartitionParentsRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `GetPartitionParentsRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getPartitionParentsRequestDescriptor = $convert.base64Decode(
    'ChpHZXRQYXJ0aXRpb25QYXJlbnRzUmVxdWVzdBIrCgJpZBgBIAEoCUIbukgYchYQAxgoMhBbMC'
    '05YS16Xy1dezMsNDB9UgJpZA==');

@$core.Deprecated('Use getPartitionParentsResponseDescriptor instead')
const GetPartitionParentsResponse$json = {
  '1': 'GetPartitionParentsResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.tenancy.v1.PartitionObject', '10': 'data'},
  ],
};

/// Descriptor for `GetPartitionParentsResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getPartitionParentsResponseDescriptor = $convert.base64Decode(
    'ChtHZXRQYXJ0aXRpb25QYXJlbnRzUmVzcG9uc2USLwoEZGF0YRgBIAMoCzIbLnRlbmFuY3kudj'
    'EuUGFydGl0aW9uT2JqZWN0UgRkYXRh');

@$core.Deprecated('Use listPartitionRequestDescriptor instead')
const ListPartitionRequest$json = {
  '1': 'ListPartitionRequest',
  '2': [
    {'1': 'query', '3': 1, '4': 1, '5': 9, '10': 'query'},
    {'1': 'cursor', '3': 2, '4': 1, '5': 11, '6': '.common.v1.PageCursor', '10': 'cursor'},
    {'1': 'start_date', '3': 4, '4': 1, '5': 9, '10': 'startDate'},
    {'1': 'end_date', '3': 5, '4': 1, '5': 9, '10': 'endDate'},
    {'1': 'properties', '3': 6, '4': 3, '5': 9, '10': 'properties'},
    {'1': 'extras', '3': 7, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'extras'},
  ],
};

/// Descriptor for `ListPartitionRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listPartitionRequestDescriptor = $convert.base64Decode(
    'ChRMaXN0UGFydGl0aW9uUmVxdWVzdBIUCgVxdWVyeRgBIAEoCVIFcXVlcnkSLQoGY3Vyc29yGA'
    'IgASgLMhUuY29tbW9uLnYxLlBhZ2VDdXJzb3JSBmN1cnNvchIdCgpzdGFydF9kYXRlGAQgASgJ'
    'UglzdGFydERhdGUSGQoIZW5kX2RhdGUYBSABKAlSB2VuZERhdGUSHgoKcHJvcGVydGllcxgGIA'
    'MoCVIKcHJvcGVydGllcxIvCgZleHRyYXMYByABKAsyFy5nb29nbGUucHJvdG9idWYuU3RydWN0'
    'UgZleHRyYXM=');

@$core.Deprecated('Use listPartitionResponseDescriptor instead')
const ListPartitionResponse$json = {
  '1': 'ListPartitionResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.tenancy.v1.PartitionObject', '10': 'data'},
  ],
};

/// Descriptor for `ListPartitionResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listPartitionResponseDescriptor = $convert.base64Decode(
    'ChVMaXN0UGFydGl0aW9uUmVzcG9uc2USLwoEZGF0YRgBIAMoCzIbLnRlbmFuY3kudjEuUGFydG'
    'l0aW9uT2JqZWN0UgRkYXRh');

@$core.Deprecated('Use createPartitionRequestDescriptor instead')
const CreatePartitionRequest$json = {
  '1': 'CreatePartitionRequest',
  '2': [
    {'1': 'tenant_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'tenantId'},
    {'1': 'parent_id', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'parentId'},
    {'1': 'name', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'description', '3': 4, '4': 1, '5': 9, '8': {}, '10': 'description'},
    {'1': 'properties', '3': 5, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
    {'1': 'domain', '3': 6, '4': 1, '5': 9, '8': {}, '10': 'domain'},
  ],
};

/// Descriptor for `CreatePartitionRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createPartitionRequestDescriptor = $convert.base64Decode(
    'ChZDcmVhdGVQYXJ0aXRpb25SZXF1ZXN0EjgKCXRlbmFudF9pZBgBIAEoCUIbukgYchYQAxgoMh'
    'BbMC05YS16Xy1dezMsNDB9Ugh0ZW5hbnRJZBI7CglwYXJlbnRfaWQYAiABKAlCHrpIG9gBAXIW'
    'EAMYKDIQWzAtOWEtel8tXXszLDQwfVIIcGFyZW50SWQSHQoEbmFtZRgDIAEoCUIJukgGcgQQAx'
    'hkUgRuYW1lEiwKC2Rlc2NyaXB0aW9uGAQgASgJQgq6SAdyBRAKGPQDUgtkZXNjcmlwdGlvbhI3'
    'Cgpwcm9wZXJ0aWVzGAUgASgLMhcuZ29vZ2xlLnByb3RvYnVmLlN0cnVjdFIKcHJvcGVydGllcx'
    'IjCgZkb21haW4YBiABKAlCC7pICNgBAXIDGP8BUgZkb21haW4=');

@$core.Deprecated('Use createPartitionResponseDescriptor instead')
const CreatePartitionResponse$json = {
  '1': 'CreatePartitionResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.PartitionObject', '10': 'data'},
  ],
};

/// Descriptor for `CreatePartitionResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createPartitionResponseDescriptor = $convert.base64Decode(
    'ChdDcmVhdGVQYXJ0aXRpb25SZXNwb25zZRIvCgRkYXRhGAEgASgLMhsudGVuYW5jeS52MS5QYX'
    'J0aXRpb25PYmplY3RSBGRhdGE=');

@$core.Deprecated('Use updatePartitionRequestDescriptor instead')
const UpdatePartitionRequest$json = {
  '1': 'UpdatePartitionRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'description', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'description'},
    {'1': 'state', '3': 4, '4': 1, '5': 14, '6': '.common.v1.STATE', '10': 'state'},
    {'1': 'properties', '3': 5, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
    {'1': 'domain', '3': 6, '4': 1, '5': 9, '8': {}, '10': 'domain'},
  ],
};

/// Descriptor for `UpdatePartitionRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List updatePartitionRequestDescriptor = $convert.base64Decode(
    'ChZVcGRhdGVQYXJ0aXRpb25SZXF1ZXN0EisKAmlkGAEgASgJQhu6SBhyFhADGCgyEFswLTlhLX'
    'pfLV17Myw0MH1SAmlkEiAKBG5hbWUYAiABKAlCDLpICdgBAXIEEAMYZFIEbmFtZRIvCgtkZXNj'
    'cmlwdGlvbhgDIAEoCUINukgK2AEBcgUQChj0A1ILZGVzY3JpcHRpb24SJgoFc3RhdGUYBCABKA'
    '4yEC5jb21tb24udjEuU1RBVEVSBXN0YXRlEjcKCnByb3BlcnRpZXMYBSABKAsyFy5nb29nbGUu'
    'cHJvdG9idWYuU3RydWN0Ugpwcm9wZXJ0aWVzEiMKBmRvbWFpbhgGIAEoCUILukgI2AEBcgMY/w'
    'FSBmRvbWFpbg==');

@$core.Deprecated('Use updatePartitionResponseDescriptor instead')
const UpdatePartitionResponse$json = {
  '1': 'UpdatePartitionResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.PartitionObject', '10': 'data'},
  ],
};

/// Descriptor for `UpdatePartitionResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List updatePartitionResponseDescriptor = $convert.base64Decode(
    'ChdVcGRhdGVQYXJ0aXRpb25SZXNwb25zZRIvCgRkYXRhGAEgASgLMhsudGVuYW5jeS52MS5QYX'
    'J0aXRpb25PYmplY3RSBGRhdGE=');

@$core.Deprecated('Use removePartitionRequestDescriptor instead')
const RemovePartitionRequest$json = {
  '1': 'RemovePartitionRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `RemovePartitionRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removePartitionRequestDescriptor = $convert.base64Decode(
    'ChZSZW1vdmVQYXJ0aXRpb25SZXF1ZXN0EisKAmlkGAEgASgJQhu6SBhyFhADGCgyEFswLTlhLX'
    'pfLV17Myw0MH1SAmlk');

@$core.Deprecated('Use removePartitionResponseDescriptor instead')
const RemovePartitionResponse$json = {
  '1': 'RemovePartitionResponse',
  '2': [
    {'1': 'succeeded', '3': 1, '4': 1, '5': 8, '10': 'succeeded'},
  ],
};

/// Descriptor for `RemovePartitionResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removePartitionResponseDescriptor = $convert.base64Decode(
    'ChdSZW1vdmVQYXJ0aXRpb25SZXNwb25zZRIcCglzdWNjZWVkZWQYASABKAhSCXN1Y2NlZWRlZA'
    '==');

@$core.Deprecated('Use createPartitionRoleRequestDescriptor instead')
const CreatePartitionRoleRequest$json = {
  '1': 'CreatePartitionRoleRequest',
  '2': [
    {'1': 'partition_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'properties', '3': 3, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
  ],
};

/// Descriptor for `CreatePartitionRoleRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createPartitionRoleRequestDescriptor = $convert.base64Decode(
    'ChpDcmVhdGVQYXJ0aXRpb25Sb2xlUmVxdWVzdBI+CgxwYXJ0aXRpb25faWQYASABKAlCG7pIGH'
    'IWEAMYKDIQWzAtOWEtel8tXXszLDQwfVILcGFydGl0aW9uSWQSHQoEbmFtZRgCIAEoCUIJukgG'
    'cgQQAxhkUgRuYW1lEjcKCnByb3BlcnRpZXMYAyABKAsyFy5nb29nbGUucHJvdG9idWYuU3RydW'
    'N0Ugpwcm9wZXJ0aWVz');

@$core.Deprecated('Use createPartitionRoleResponseDescriptor instead')
const CreatePartitionRoleResponse$json = {
  '1': 'CreatePartitionRoleResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.PartitionRoleObject', '10': 'data'},
  ],
};

/// Descriptor for `CreatePartitionRoleResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createPartitionRoleResponseDescriptor = $convert.base64Decode(
    'ChtDcmVhdGVQYXJ0aXRpb25Sb2xlUmVzcG9uc2USMwoEZGF0YRgBIAEoCzIfLnRlbmFuY3kudj'
    'EuUGFydGl0aW9uUm9sZU9iamVjdFIEZGF0YQ==');

@$core.Deprecated('Use updatePartitionRoleRequestDescriptor instead')
const UpdatePartitionRoleRequest$json = {
  '1': 'UpdatePartitionRoleRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'properties', '3': 3, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
    {'1': 'state', '3': 4, '4': 1, '5': 14, '6': '.common.v1.STATE', '10': 'state'},
  ],
};

/// Descriptor for `UpdatePartitionRoleRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List updatePartitionRoleRequestDescriptor = $convert.base64Decode(
    'ChpVcGRhdGVQYXJ0aXRpb25Sb2xlUmVxdWVzdBIrCgJpZBgBIAEoCUIbukgYchYQAxgoMhBbMC'
    '05YS16Xy1dezMsNDB9UgJpZBIgCgRuYW1lGAIgASgJQgy6SAnYAQFyBBADGGRSBG5hbWUSNwoK'
    'cHJvcGVydGllcxgDIAEoCzIXLmdvb2dsZS5wcm90b2J1Zi5TdHJ1Y3RSCnByb3BlcnRpZXMSJg'
    'oFc3RhdGUYBCABKA4yEC5jb21tb24udjEuU1RBVEVSBXN0YXRl');

@$core.Deprecated('Use updatePartitionRoleResponseDescriptor instead')
const UpdatePartitionRoleResponse$json = {
  '1': 'UpdatePartitionRoleResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.PartitionRoleObject', '10': 'data'},
  ],
};

/// Descriptor for `UpdatePartitionRoleResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List updatePartitionRoleResponseDescriptor = $convert.base64Decode(
    'ChtVcGRhdGVQYXJ0aXRpb25Sb2xlUmVzcG9uc2USMwoEZGF0YRgBIAEoCzIfLnRlbmFuY3kudj'
    'EuUGFydGl0aW9uUm9sZU9iamVjdFIEZGF0YQ==');

@$core.Deprecated('Use removePartitionRoleRequestDescriptor instead')
const RemovePartitionRoleRequest$json = {
  '1': 'RemovePartitionRoleRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `RemovePartitionRoleRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removePartitionRoleRequestDescriptor = $convert.base64Decode(
    'ChpSZW1vdmVQYXJ0aXRpb25Sb2xlUmVxdWVzdBIrCgJpZBgBIAEoCUIbukgYchYQAxgoMhBbMC'
    '05YS16Xy1dezMsNDB9UgJpZA==');

@$core.Deprecated('Use removePartitionRoleResponseDescriptor instead')
const RemovePartitionRoleResponse$json = {
  '1': 'RemovePartitionRoleResponse',
  '2': [
    {'1': 'succeeded', '3': 1, '4': 1, '5': 8, '10': 'succeeded'},
  ],
};

/// Descriptor for `RemovePartitionRoleResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removePartitionRoleResponseDescriptor = $convert.base64Decode(
    'ChtSZW1vdmVQYXJ0aXRpb25Sb2xlUmVzcG9uc2USHAoJc3VjY2VlZGVkGAEgASgIUglzdWNjZW'
    'VkZWQ=');

@$core.Deprecated('Use listPartitionRoleRequestDescriptor instead')
const ListPartitionRoleRequest$json = {
  '1': 'ListPartitionRoleRequest',
  '2': [
    {'1': 'partition_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
    {'1': 'cursor', '3': 2, '4': 1, '5': 11, '6': '.common.v1.PageCursor', '10': 'cursor'},
  ],
};

/// Descriptor for `ListPartitionRoleRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listPartitionRoleRequestDescriptor = $convert.base64Decode(
    'ChhMaXN0UGFydGl0aW9uUm9sZVJlcXVlc3QSPgoMcGFydGl0aW9uX2lkGAEgASgJQhu6SBhyFh'
    'ADGCgyEFswLTlhLXpfLV17Myw0MH1SC3BhcnRpdGlvbklkEi0KBmN1cnNvchgCIAEoCzIVLmNv'
    'bW1vbi52MS5QYWdlQ3Vyc29yUgZjdXJzb3I=');

@$core.Deprecated('Use listPartitionRoleResponseDescriptor instead')
const ListPartitionRoleResponse$json = {
  '1': 'ListPartitionRoleResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.tenancy.v1.PartitionRoleObject', '10': 'data'},
  ],
};

/// Descriptor for `ListPartitionRoleResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listPartitionRoleResponseDescriptor = $convert.base64Decode(
    'ChlMaXN0UGFydGl0aW9uUm9sZVJlc3BvbnNlEjMKBGRhdGEYASADKAsyHy50ZW5hbmN5LnYxLl'
    'BhcnRpdGlvblJvbGVPYmplY3RSBGRhdGE=');

@$core.Deprecated('Use createPageRequestDescriptor instead')
const CreatePageRequest$json = {
  '1': 'CreatePageRequest',
  '2': [
    {'1': 'partition_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'html', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'html'},
    {'1': 'properties', '3': 4, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
  ],
};

/// Descriptor for `CreatePageRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createPageRequestDescriptor = $convert.base64Decode(
    'ChFDcmVhdGVQYWdlUmVxdWVzdBI+CgxwYXJ0aXRpb25faWQYASABKAlCG7pIGHIWEAMYKDIQWz'
    'AtOWEtel8tXXszLDQwfVILcGFydGl0aW9uSWQSHQoEbmFtZRgCIAEoCUIJukgGcgQQAxhkUgRu'
    'YW1lEh4KBGh0bWwYAyABKAlCCrpIB3IFEAQYiCdSBGh0bWwSNwoKcHJvcGVydGllcxgEIAEoCz'
    'IXLmdvb2dsZS5wcm90b2J1Zi5TdHJ1Y3RSCnByb3BlcnRpZXM=');

@$core.Deprecated('Use createPageResponseDescriptor instead')
const CreatePageResponse$json = {
  '1': 'CreatePageResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.PageObject', '10': 'data'},
  ],
};

/// Descriptor for `CreatePageResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createPageResponseDescriptor = $convert.base64Decode(
    'ChJDcmVhdGVQYWdlUmVzcG9uc2USKgoEZGF0YRgBIAEoCzIWLnRlbmFuY3kudjEuUGFnZU9iam'
    'VjdFIEZGF0YQ==');

@$core.Deprecated('Use getPageRequestDescriptor instead')
const GetPageRequest$json = {
  '1': 'GetPageRequest',
  '2': [
    {'1': 'page_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'pageId'},
    {'1': 'partition_id', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
    {'1': 'name', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'name'},
  ],
};

/// Descriptor for `GetPageRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getPageRequestDescriptor = $convert.base64Decode(
    'Cg5HZXRQYWdlUmVxdWVzdBI3CgdwYWdlX2lkGAEgASgJQh66SBvYAQFyFhADGCgyEFswLTlhLX'
    'pfLV17Myw0MH1SBnBhZ2VJZBJBCgxwYXJ0aXRpb25faWQYAiABKAlCHrpIG9gBAXIWEAMYKDIQ'
    'WzAtOWEtel8tXXszLDQwfVILcGFydGl0aW9uSWQSIAoEbmFtZRgDIAEoCUIMukgJ2AEBcgQQAx'
    'hkUgRuYW1l');

@$core.Deprecated('Use getPageResponseDescriptor instead')
const GetPageResponse$json = {
  '1': 'GetPageResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.PageObject', '10': 'data'},
  ],
};

/// Descriptor for `GetPageResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getPageResponseDescriptor = $convert.base64Decode(
    'Cg9HZXRQYWdlUmVzcG9uc2USKgoEZGF0YRgBIAEoCzIWLnRlbmFuY3kudjEuUGFnZU9iamVjdF'
    'IEZGF0YQ==');

@$core.Deprecated('Use updatePageRequestDescriptor instead')
const UpdatePageRequest$json = {
  '1': 'UpdatePageRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'html', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'html'},
    {'1': 'state', '3': 4, '4': 1, '5': 14, '6': '.common.v1.STATE', '10': 'state'},
    {'1': 'properties', '3': 5, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
  ],
};

/// Descriptor for `UpdatePageRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List updatePageRequestDescriptor = $convert.base64Decode(
    'ChFVcGRhdGVQYWdlUmVxdWVzdBIrCgJpZBgBIAEoCUIbukgYchYQAxgoMhBbMC05YS16Xy1dez'
    'MsNDB9UgJpZBIgCgRuYW1lGAIgASgJQgy6SAnYAQFyBBADGGRSBG5hbWUSIQoEaHRtbBgDIAEo'
    'CUINukgK2AEBcgUQBBiIJ1IEaHRtbBImCgVzdGF0ZRgEIAEoDjIQLmNvbW1vbi52MS5TVEFURV'
    'IFc3RhdGUSNwoKcHJvcGVydGllcxgFIAEoCzIXLmdvb2dsZS5wcm90b2J1Zi5TdHJ1Y3RSCnBy'
    'b3BlcnRpZXM=');

@$core.Deprecated('Use updatePageResponseDescriptor instead')
const UpdatePageResponse$json = {
  '1': 'UpdatePageResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.PageObject', '10': 'data'},
  ],
};

/// Descriptor for `UpdatePageResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List updatePageResponseDescriptor = $convert.base64Decode(
    'ChJVcGRhdGVQYWdlUmVzcG9uc2USKgoEZGF0YRgBIAEoCzIWLnRlbmFuY3kudjEuUGFnZU9iam'
    'VjdFIEZGF0YQ==');

@$core.Deprecated('Use listPageRequestDescriptor instead')
const ListPageRequest$json = {
  '1': 'ListPageRequest',
  '2': [
    {'1': 'partition_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
    {'1': 'cursor', '3': 2, '4': 1, '5': 11, '6': '.common.v1.PageCursor', '10': 'cursor'},
  ],
};

/// Descriptor for `ListPageRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listPageRequestDescriptor = $convert.base64Decode(
    'Cg9MaXN0UGFnZVJlcXVlc3QSPgoMcGFydGl0aW9uX2lkGAEgASgJQhu6SBhyFhADGCgyEFswLT'
    'lhLXpfLV17Myw0MH1SC3BhcnRpdGlvbklkEi0KBmN1cnNvchgCIAEoCzIVLmNvbW1vbi52MS5Q'
    'YWdlQ3Vyc29yUgZjdXJzb3I=');

@$core.Deprecated('Use listPageResponseDescriptor instead')
const ListPageResponse$json = {
  '1': 'ListPageResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.tenancy.v1.PageObject', '10': 'data'},
  ],
};

/// Descriptor for `ListPageResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listPageResponseDescriptor = $convert.base64Decode(
    'ChBMaXN0UGFnZVJlc3BvbnNlEioKBGRhdGEYASADKAsyFi50ZW5hbmN5LnYxLlBhZ2VPYmplY3'
    'RSBGRhdGE=');

@$core.Deprecated('Use removePageRequestDescriptor instead')
const RemovePageRequest$json = {
  '1': 'RemovePageRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `RemovePageRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removePageRequestDescriptor = $convert.base64Decode(
    'ChFSZW1vdmVQYWdlUmVxdWVzdBIrCgJpZBgBIAEoCUIbukgYchYQAxgoMhBbMC05YS16Xy1dez'
    'MsNDB9UgJpZA==');

@$core.Deprecated('Use removePageResponseDescriptor instead')
const RemovePageResponse$json = {
  '1': 'RemovePageResponse',
  '2': [
    {'1': 'succeeded', '3': 1, '4': 1, '5': 8, '10': 'succeeded'},
  ],
};

/// Descriptor for `RemovePageResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removePageResponseDescriptor = $convert.base64Decode(
    'ChJSZW1vdmVQYWdlUmVzcG9uc2USHAoJc3VjY2VlZGVkGAEgASgIUglzdWNjZWVkZWQ=');

@$core.Deprecated('Use createAccessRequestDescriptor instead')
const CreateAccessRequest$json = {
  '1': 'CreateAccessRequest',
  '2': [
    {'1': 'partition_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
    {'1': 'profile_id', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'profileId'},
  ],
  '9': [
    {'1': 3, '2': 4},
  ],
  '10': ['client_id'],
};

/// Descriptor for `CreateAccessRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createAccessRequestDescriptor = $convert.base64Decode(
    'ChNDcmVhdGVBY2Nlc3NSZXF1ZXN0Ej4KDHBhcnRpdGlvbl9pZBgBIAEoCUIbukgYchYQAxgoMh'
    'BbMC05YS16Xy1dezMsNDB9UgtwYXJ0aXRpb25JZBI6Cgpwcm9maWxlX2lkGAIgASgJQhu6SBhy'
    'FhADGCgyEFswLTlhLXpfLV17Myw0MH1SCXByb2ZpbGVJZEoECAMQBFIJY2xpZW50X2lk');

@$core.Deprecated('Use createAccessResponseDescriptor instead')
const CreateAccessResponse$json = {
  '1': 'CreateAccessResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.AccessObject', '10': 'data'},
  ],
};

/// Descriptor for `CreateAccessResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createAccessResponseDescriptor = $convert.base64Decode(
    'ChRDcmVhdGVBY2Nlc3NSZXNwb25zZRIsCgRkYXRhGAEgASgLMhgudGVuYW5jeS52MS5BY2Nlc3'
    'NPYmplY3RSBGRhdGE=');

@$core.Deprecated('Use getAccessRequestDescriptor instead')
const GetAccessRequest$json = {
  '1': 'GetAccessRequest',
  '2': [
    {'1': 'access_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'accessId'},
    {'1': 'partition_id', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
    {'1': 'profile_id', '3': 4, '4': 1, '5': 9, '8': {}, '10': 'profileId'},
  ],
  '9': [
    {'1': 3, '2': 4},
  ],
  '10': ['client_id'],
};

/// Descriptor for `GetAccessRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getAccessRequestDescriptor = $convert.base64Decode(
    'ChBHZXRBY2Nlc3NSZXF1ZXN0EjsKCWFjY2Vzc19pZBgBIAEoCUIeukgb2AEBchYQAxgoMhBbMC'
    '05YS16Xy1dezMsNDB9UghhY2Nlc3NJZBJBCgxwYXJ0aXRpb25faWQYAiABKAlCHrpIG9gBAXIW'
    'EAMYKDIQWzAtOWEtel8tXXszLDQwfVILcGFydGl0aW9uSWQSPQoKcHJvZmlsZV9pZBgEIAEoCU'
    'Ieukgb2AEBchYQAxgoMhBbMC05YS16Xy1dezMsNDB9Uglwcm9maWxlSWRKBAgDEARSCWNsaWVu'
    'dF9pZA==');

@$core.Deprecated('Use getAccessResponseDescriptor instead')
const GetAccessResponse$json = {
  '1': 'GetAccessResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.AccessObject', '10': 'data'},
  ],
};

/// Descriptor for `GetAccessResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getAccessResponseDescriptor = $convert.base64Decode(
    'ChFHZXRBY2Nlc3NSZXNwb25zZRIsCgRkYXRhGAEgASgLMhgudGVuYW5jeS52MS5BY2Nlc3NPYm'
    'plY3RSBGRhdGE=');

@$core.Deprecated('Use listAccessRequestDescriptor instead')
const ListAccessRequest$json = {
  '1': 'ListAccessRequest',
  '2': [
    {'1': 'partition_id', '3': 1, '4': 1, '5': 9, '8': {}, '9': 0, '10': 'partitionId'},
    {'1': 'profile_id', '3': 2, '4': 1, '5': 9, '8': {}, '9': 0, '10': 'profileId'},
    {'1': 'cursor', '3': 3, '4': 1, '5': 11, '6': '.common.v1.PageCursor', '10': 'cursor'},
  ],
  '8': [
    {'1': 'scope', '2': {}},
  ],
};

/// Descriptor for `ListAccessRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listAccessRequestDescriptor = $convert.base64Decode(
    'ChFMaXN0QWNjZXNzUmVxdWVzdBJACgxwYXJ0aXRpb25faWQYASABKAlCG7pIGHIWEAMYKDIQWz'
    'AtOWEtel8tXXszLDQwfUgAUgtwYXJ0aXRpb25JZBI8Cgpwcm9maWxlX2lkGAIgASgJQhu6SBhy'
    'FhADGCgyEFswLTlhLXpfLV17Myw0MH1IAFIJcHJvZmlsZUlkEi0KBmN1cnNvchgDIAEoCzIVLm'
    'NvbW1vbi52MS5QYWdlQ3Vyc29yUgZjdXJzb3JCDgoFc2NvcGUSBbpIAggB');

@$core.Deprecated('Use listAccessResponseDescriptor instead')
const ListAccessResponse$json = {
  '1': 'ListAccessResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.tenancy.v1.AccessObject', '10': 'data'},
  ],
};

/// Descriptor for `ListAccessResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listAccessResponseDescriptor = $convert.base64Decode(
    'ChJMaXN0QWNjZXNzUmVzcG9uc2USLAoEZGF0YRgBIAMoCzIYLnRlbmFuY3kudjEuQWNjZXNzT2'
    'JqZWN0UgRkYXRh');

@$core.Deprecated('Use removeAccessRequestDescriptor instead')
const RemoveAccessRequest$json = {
  '1': 'RemoveAccessRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `RemoveAccessRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removeAccessRequestDescriptor = $convert.base64Decode(
    'ChNSZW1vdmVBY2Nlc3NSZXF1ZXN0EisKAmlkGAEgASgJQhu6SBhyFhADGCgyEFswLTlhLXpfLV'
    '17Myw0MH1SAmlk');

@$core.Deprecated('Use removeAccessResponseDescriptor instead')
const RemoveAccessResponse$json = {
  '1': 'RemoveAccessResponse',
  '2': [
    {'1': 'succeeded', '3': 1, '4': 1, '5': 8, '10': 'succeeded'},
  ],
};

/// Descriptor for `RemoveAccessResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removeAccessResponseDescriptor = $convert.base64Decode(
    'ChRSZW1vdmVBY2Nlc3NSZXNwb25zZRIcCglzdWNjZWVkZWQYASABKAhSCXN1Y2NlZWRlZA==');

@$core.Deprecated('Use createAccessRoleRequestDescriptor instead')
const CreateAccessRoleRequest$json = {
  '1': 'CreateAccessRoleRequest',
  '2': [
    {'1': 'access_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'accessId'},
    {'1': 'partition_role_id', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'partitionRoleId'},
  ],
};

/// Descriptor for `CreateAccessRoleRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createAccessRoleRequestDescriptor = $convert.base64Decode(
    'ChdDcmVhdGVBY2Nlc3NSb2xlUmVxdWVzdBI4CglhY2Nlc3NfaWQYASABKAlCG7pIGHIWEAMYKD'
    'IQWzAtOWEtel8tXXszLDQwfVIIYWNjZXNzSWQSRwoRcGFydGl0aW9uX3JvbGVfaWQYAiABKAlC'
    'G7pIGHIWEAMYKDIQWzAtOWEtel8tXXszLDQwfVIPcGFydGl0aW9uUm9sZUlk');

@$core.Deprecated('Use createAccessRoleResponseDescriptor instead')
const CreateAccessRoleResponse$json = {
  '1': 'CreateAccessRoleResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.tenancy.v1.AccessRoleObject', '10': 'data'},
  ],
};

/// Descriptor for `CreateAccessRoleResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createAccessRoleResponseDescriptor = $convert.base64Decode(
    'ChhDcmVhdGVBY2Nlc3NSb2xlUmVzcG9uc2USMAoEZGF0YRgBIAEoCzIcLnRlbmFuY3kudjEuQW'
    'NjZXNzUm9sZU9iamVjdFIEZGF0YQ==');

@$core.Deprecated('Use removeAccessRoleRequestDescriptor instead')
const RemoveAccessRoleRequest$json = {
  '1': 'RemoveAccessRoleRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `RemoveAccessRoleRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removeAccessRoleRequestDescriptor = $convert.base64Decode(
    'ChdSZW1vdmVBY2Nlc3NSb2xlUmVxdWVzdBIrCgJpZBgBIAEoCUIbukgYchYQAxgoMhBbMC05YS'
    '16Xy1dezMsNDB9UgJpZA==');

@$core.Deprecated('Use removeAccessRoleResponseDescriptor instead')
const RemoveAccessRoleResponse$json = {
  '1': 'RemoveAccessRoleResponse',
  '2': [
    {'1': 'succeeded', '3': 1, '4': 1, '5': 8, '10': 'succeeded'},
  ],
};

/// Descriptor for `RemoveAccessRoleResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removeAccessRoleResponseDescriptor = $convert.base64Decode(
    'ChhSZW1vdmVBY2Nlc3NSb2xlUmVzcG9uc2USHAoJc3VjY2VlZGVkGAEgASgIUglzdWNjZWVkZW'
    'Q=');

@$core.Deprecated('Use listAccessRoleRequestDescriptor instead')
const ListAccessRoleRequest$json = {
  '1': 'ListAccessRoleRequest',
  '2': [
    {'1': 'access_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'accessId'},
    {'1': 'cursor', '3': 2, '4': 1, '5': 11, '6': '.common.v1.PageCursor', '10': 'cursor'},
  ],
};

/// Descriptor for `ListAccessRoleRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listAccessRoleRequestDescriptor = $convert.base64Decode(
    'ChVMaXN0QWNjZXNzUm9sZVJlcXVlc3QSOAoJYWNjZXNzX2lkGAEgASgJQhu6SBhyFhADGCgyEF'
    'swLTlhLXpfLV17Myw0MH1SCGFjY2Vzc0lkEi0KBmN1cnNvchgCIAEoCzIVLmNvbW1vbi52MS5Q'
    'YWdlQ3Vyc29yUgZjdXJzb3I=');

@$core.Deprecated('Use listAccessRoleResponseDescriptor instead')
const ListAccessRoleResponse$json = {
  '1': 'ListAccessRoleResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.tenancy.v1.AccessRoleObject', '10': 'data'},
  ],
};

/// Descriptor for `ListAccessRoleResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listAccessRoleResponseDescriptor = $convert.base64Decode(
    'ChZMaXN0QWNjZXNzUm9sZVJlc3BvbnNlEjAKBGRhdGEYASADKAsyHC50ZW5hbmN5LnYxLkFjY2'
    'Vzc1JvbGVPYmplY3RSBGRhdGE=');

@$core.Deprecated('Use serviceNamespaceObjectDescriptor instead')
const ServiceNamespaceObject$json = {
  '1': 'ServiceNamespaceObject',
  '2': [
    {'1': 'namespace', '3': 1, '4': 1, '5': 9, '10': 'namespace'},
    {'1': 'permissions', '3': 2, '4': 3, '5': 9, '10': 'permissions'},
    {'1': 'role_bindings', '3': 3, '4': 3, '5': 11, '6': '.tenancy.v1.ServiceNamespaceObject.RoleBindingsEntry', '10': 'roleBindings'},
    {'1': 'registered_at', '3': 4, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'registeredAt'},
  ],
  '3': [ServiceNamespaceObject_RoleBindingsEntry$json],
};

@$core.Deprecated('Use serviceNamespaceObjectDescriptor instead')
const ServiceNamespaceObject_RoleBindingsEntry$json = {
  '1': 'RoleBindingsEntry',
  '2': [
    {'1': 'key', '3': 1, '4': 1, '5': 9, '10': 'key'},
    {'1': 'value', '3': 2, '4': 1, '5': 11, '6': '.tenancy.v1.RolePermissionList', '10': 'value'},
  ],
  '7': {'7': true},
};

/// Descriptor for `ServiceNamespaceObject`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List serviceNamespaceObjectDescriptor = $convert.base64Decode(
    'ChZTZXJ2aWNlTmFtZXNwYWNlT2JqZWN0EhwKCW5hbWVzcGFjZRgBIAEoCVIJbmFtZXNwYWNlEi'
    'AKC3Blcm1pc3Npb25zGAIgAygJUgtwZXJtaXNzaW9ucxJZCg1yb2xlX2JpbmRpbmdzGAMgAygL'
    'MjQudGVuYW5jeS52MS5TZXJ2aWNlTmFtZXNwYWNlT2JqZWN0LlJvbGVCaW5kaW5nc0VudHJ5Ug'
    'xyb2xlQmluZGluZ3MSPwoNcmVnaXN0ZXJlZF9hdBgEIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5U'
    'aW1lc3RhbXBSDHJlZ2lzdGVyZWRBdBpfChFSb2xlQmluZGluZ3NFbnRyeRIQCgNrZXkYASABKA'
    'lSA2tleRI0CgV2YWx1ZRgCIAEoCzIeLnRlbmFuY3kudjEuUm9sZVBlcm1pc3Npb25MaXN0UgV2'
    'YWx1ZToCOAE=');

@$core.Deprecated('Use rolePermissionListDescriptor instead')
const RolePermissionList$json = {
  '1': 'RolePermissionList',
  '2': [
    {'1': 'permissions', '3': 1, '4': 3, '5': 9, '10': 'permissions'},
  ],
};

/// Descriptor for `RolePermissionList`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List rolePermissionListDescriptor = $convert.base64Decode(
    'ChJSb2xlUGVybWlzc2lvbkxpc3QSIAoLcGVybWlzc2lvbnMYASADKAlSC3Blcm1pc3Npb25z');

@$core.Deprecated('Use listServiceNamespacesRequestDescriptor instead')
const ListServiceNamespacesRequest$json = {
  '1': 'ListServiceNamespacesRequest',
};

/// Descriptor for `ListServiceNamespacesRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listServiceNamespacesRequestDescriptor = $convert.base64Decode(
    'ChxMaXN0U2VydmljZU5hbWVzcGFjZXNSZXF1ZXN0');

@$core.Deprecated('Use listServiceNamespacesResponseDescriptor instead')
const ListServiceNamespacesResponse$json = {
  '1': 'ListServiceNamespacesResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.tenancy.v1.ServiceNamespaceObject', '10': 'data'},
  ],
};

/// Descriptor for `ListServiceNamespacesResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listServiceNamespacesResponseDescriptor = $convert.base64Decode(
    'Ch1MaXN0U2VydmljZU5hbWVzcGFjZXNSZXNwb25zZRI2CgRkYXRhGAEgAygLMiIudGVuYW5jeS'
    '52MS5TZXJ2aWNlTmFtZXNwYWNlT2JqZWN0UgRkYXRh');

@$core.Deprecated('Use grantPermissionRequestDescriptor instead')
const GrantPermissionRequest$json = {
  '1': 'GrantPermissionRequest',
  '2': [
    {'1': 'namespace', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'namespace'},
    {'1': 'permission', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'permission'},
    {'1': 'profile_id', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'profileId'},
  ],
};

/// Descriptor for `GrantPermissionRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List grantPermissionRequestDescriptor = $convert.base64Decode(
    'ChZHcmFudFBlcm1pc3Npb25SZXF1ZXN0EicKCW5hbWVzcGFjZRgBIAEoCUIJukgGcgQQAxhkUg'
    'luYW1lc3BhY2USKQoKcGVybWlzc2lvbhgCIAEoCUIJukgGcgQQAxhkUgpwZXJtaXNzaW9uEjoK'
    'CnByb2ZpbGVfaWQYAyABKAlCG7pIGHIWEAMYKDIQWzAtOWEtel8tXXszLDQwfVIJcHJvZmlsZU'
    'lk');

@$core.Deprecated('Use grantPermissionResponseDescriptor instead')
const GrantPermissionResponse$json = {
  '1': 'GrantPermissionResponse',
  '2': [
    {'1': 'succeeded', '3': 1, '4': 1, '5': 8, '10': 'succeeded'},
  ],
};

/// Descriptor for `GrantPermissionResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List grantPermissionResponseDescriptor = $convert.base64Decode(
    'ChdHcmFudFBlcm1pc3Npb25SZXNwb25zZRIcCglzdWNjZWVkZWQYASABKAhSCXN1Y2NlZWRlZA'
    '==');

@$core.Deprecated('Use revokePermissionRequestDescriptor instead')
const RevokePermissionRequest$json = {
  '1': 'RevokePermissionRequest',
  '2': [
    {'1': 'namespace', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'namespace'},
    {'1': 'permission', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'permission'},
    {'1': 'profile_id', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'profileId'},
  ],
};

/// Descriptor for `RevokePermissionRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List revokePermissionRequestDescriptor = $convert.base64Decode(
    'ChdSZXZva2VQZXJtaXNzaW9uUmVxdWVzdBInCgluYW1lc3BhY2UYASABKAlCCbpIBnIEEAMYZF'
    'IJbmFtZXNwYWNlEikKCnBlcm1pc3Npb24YAiABKAlCCbpIBnIEEAMYZFIKcGVybWlzc2lvbhI6'
    'Cgpwcm9maWxlX2lkGAMgASgJQhu6SBhyFhADGCgyEFswLTlhLXpfLV17Myw0MH1SCXByb2ZpbG'
    'VJZA==');

@$core.Deprecated('Use revokePermissionResponseDescriptor instead')
const RevokePermissionResponse$json = {
  '1': 'RevokePermissionResponse',
  '2': [
    {'1': 'succeeded', '3': 1, '4': 1, '5': 8, '10': 'succeeded'},
  ],
};

/// Descriptor for `RevokePermissionResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List revokePermissionResponseDescriptor = $convert.base64Decode(
    'ChhSZXZva2VQZXJtaXNzaW9uUmVzcG9uc2USHAoJc3VjY2VlZGVkGAEgASgIUglzdWNjZWVkZW'
    'Q=');

const $core.Map<$core.String, $core.dynamic> TenancyServiceBase$json = {
  '1': 'TenancyService',
  '2': [
    {
      '1': 'GetTenant',
      '2': '.tenancy.v1.GetTenantRequest',
      '3': '.tenancy.v1.GetTenantResponse',
      '4': {'34': 1},
    },
    {
      '1': 'ListTenant',
      '2': '.tenancy.v1.ListTenantRequest',
      '3': '.tenancy.v1.ListTenantResponse',
      '4': {'34': 1},
      '6': true,
    },
    {'1': 'CreateTenant', '2': '.tenancy.v1.CreateTenantRequest', '3': '.tenancy.v1.CreateTenantResponse', '4': {}},
    {'1': 'UpdateTenant', '2': '.tenancy.v1.UpdateTenantRequest', '3': '.tenancy.v1.UpdateTenantResponse', '4': {}},
    {'1': 'RemoveTenant', '2': '.tenancy.v1.RemoveTenantRequest', '3': '.tenancy.v1.RemoveTenantResponse', '4': {}},
    {
      '1': 'ListPartition',
      '2': '.tenancy.v1.ListPartitionRequest',
      '3': '.tenancy.v1.ListPartitionResponse',
      '4': {'34': 1},
      '6': true,
    },
    {'1': 'CreatePartition', '2': '.tenancy.v1.CreatePartitionRequest', '3': '.tenancy.v1.CreatePartitionResponse', '4': {}},
    {
      '1': 'GetPartition',
      '2': '.tenancy.v1.GetPartitionRequest',
      '3': '.tenancy.v1.GetPartitionResponse',
      '4': {'34': 1},
    },
    {
      '1': 'GetPartitionParents',
      '2': '.tenancy.v1.GetPartitionParentsRequest',
      '3': '.tenancy.v1.GetPartitionParentsResponse',
      '4': {'34': 1},
    },
    {'1': 'RemovePartition', '2': '.tenancy.v1.RemovePartitionRequest', '3': '.tenancy.v1.RemovePartitionResponse', '4': {}},
    {'1': 'UpdatePartition', '2': '.tenancy.v1.UpdatePartitionRequest', '3': '.tenancy.v1.UpdatePartitionResponse', '4': {}},
    {'1': 'CreatePartitionRole', '2': '.tenancy.v1.CreatePartitionRoleRequest', '3': '.tenancy.v1.CreatePartitionRoleResponse', '4': {}},
    {
      '1': 'ListPartitionRole',
      '2': '.tenancy.v1.ListPartitionRoleRequest',
      '3': '.tenancy.v1.ListPartitionRoleResponse',
      '4': {'34': 1},
      '6': true,
    },
    {'1': 'UpdatePartitionRole', '2': '.tenancy.v1.UpdatePartitionRoleRequest', '3': '.tenancy.v1.UpdatePartitionRoleResponse', '4': {}},
    {'1': 'RemovePartitionRole', '2': '.tenancy.v1.RemovePartitionRoleRequest', '3': '.tenancy.v1.RemovePartitionRoleResponse', '4': {}},
    {'1': 'CreatePage', '2': '.tenancy.v1.CreatePageRequest', '3': '.tenancy.v1.CreatePageResponse', '4': {}},
    {
      '1': 'ListPage',
      '2': '.tenancy.v1.ListPageRequest',
      '3': '.tenancy.v1.ListPageResponse',
      '4': {'34': 1},
      '6': true,
    },
    {
      '1': 'GetPage',
      '2': '.tenancy.v1.GetPageRequest',
      '3': '.tenancy.v1.GetPageResponse',
      '4': {'34': 1},
    },
    {'1': 'UpdatePage', '2': '.tenancy.v1.UpdatePageRequest', '3': '.tenancy.v1.UpdatePageResponse', '4': {}},
    {'1': 'RemovePage', '2': '.tenancy.v1.RemovePageRequest', '3': '.tenancy.v1.RemovePageResponse', '4': {}},
    {'1': 'CreateAccess', '2': '.tenancy.v1.CreateAccessRequest', '3': '.tenancy.v1.CreateAccessResponse', '4': {}},
    {
      '1': 'GetAccess',
      '2': '.tenancy.v1.GetAccessRequest',
      '3': '.tenancy.v1.GetAccessResponse',
      '4': {'34': 1},
    },
    {
      '1': 'ListAccess',
      '2': '.tenancy.v1.ListAccessRequest',
      '3': '.tenancy.v1.ListAccessResponse',
      '4': {'34': 1},
      '6': true,
    },
    {'1': 'RemoveAccess', '2': '.tenancy.v1.RemoveAccessRequest', '3': '.tenancy.v1.RemoveAccessResponse', '4': {}},
    {'1': 'CreateAccessRole', '2': '.tenancy.v1.CreateAccessRoleRequest', '3': '.tenancy.v1.CreateAccessRoleResponse', '4': {}},
    {
      '1': 'ListAccessRole',
      '2': '.tenancy.v1.ListAccessRoleRequest',
      '3': '.tenancy.v1.ListAccessRoleResponse',
      '4': {'34': 1},
      '6': true,
    },
    {'1': 'RemoveAccessRole', '2': '.tenancy.v1.RemoveAccessRoleRequest', '3': '.tenancy.v1.RemoveAccessRoleResponse', '4': {}},
    {
      '1': 'ListServiceNamespaces',
      '2': '.tenancy.v1.ListServiceNamespacesRequest',
      '3': '.tenancy.v1.ListServiceNamespacesResponse',
      '4': {'34': 1},
    },
    {'1': 'GrantPermission', '2': '.tenancy.v1.GrantPermissionRequest', '3': '.tenancy.v1.GrantPermissionResponse', '4': {}},
    {'1': 'RevokePermission', '2': '.tenancy.v1.RevokePermissionRequest', '3': '.tenancy.v1.RevokePermissionResponse', '4': {}},
  ],
  '3': {},
};

@$core.Deprecated('Use tenancyServiceDescriptor instead')
const $core.Map<$core.String, $core.Map<$core.String, $core.dynamic>> TenancyServiceBase$messageJson = {
  '.tenancy.v1.GetTenantRequest': GetTenantRequest$json,
  '.tenancy.v1.GetTenantResponse': GetTenantResponse$json,
  '.tenancy.v1.TenantObject': TenantObject$json,
  '.google.protobuf.Struct': $6.Struct$json,
  '.google.protobuf.Struct.FieldsEntry': $6.Struct_FieldsEntry$json,
  '.google.protobuf.Value': $6.Value$json,
  '.google.protobuf.ListValue': $6.ListValue$json,
  '.google.protobuf.Timestamp': $2.Timestamp$json,
  '.tenancy.v1.ListTenantRequest': ListTenantRequest$json,
  '.common.v1.PageCursor': $7.PageCursor$json,
  '.tenancy.v1.ListTenantResponse': ListTenantResponse$json,
  '.tenancy.v1.CreateTenantRequest': CreateTenantRequest$json,
  '.tenancy.v1.CreateTenantResponse': CreateTenantResponse$json,
  '.tenancy.v1.UpdateTenantRequest': UpdateTenantRequest$json,
  '.tenancy.v1.UpdateTenantResponse': UpdateTenantResponse$json,
  '.tenancy.v1.RemoveTenantRequest': RemoveTenantRequest$json,
  '.tenancy.v1.RemoveTenantResponse': RemoveTenantResponse$json,
  '.tenancy.v1.ListPartitionRequest': ListPartitionRequest$json,
  '.tenancy.v1.ListPartitionResponse': ListPartitionResponse$json,
  '.tenancy.v1.PartitionObject': PartitionObject$json,
  '.tenancy.v1.CreatePartitionRequest': CreatePartitionRequest$json,
  '.tenancy.v1.CreatePartitionResponse': CreatePartitionResponse$json,
  '.tenancy.v1.GetPartitionRequest': GetPartitionRequest$json,
  '.tenancy.v1.GetPartitionResponse': GetPartitionResponse$json,
  '.tenancy.v1.GetPartitionParentsRequest': GetPartitionParentsRequest$json,
  '.tenancy.v1.GetPartitionParentsResponse': GetPartitionParentsResponse$json,
  '.tenancy.v1.RemovePartitionRequest': RemovePartitionRequest$json,
  '.tenancy.v1.RemovePartitionResponse': RemovePartitionResponse$json,
  '.tenancy.v1.UpdatePartitionRequest': UpdatePartitionRequest$json,
  '.tenancy.v1.UpdatePartitionResponse': UpdatePartitionResponse$json,
  '.tenancy.v1.CreatePartitionRoleRequest': CreatePartitionRoleRequest$json,
  '.tenancy.v1.CreatePartitionRoleResponse': CreatePartitionRoleResponse$json,
  '.tenancy.v1.PartitionRoleObject': PartitionRoleObject$json,
  '.tenancy.v1.ListPartitionRoleRequest': ListPartitionRoleRequest$json,
  '.tenancy.v1.ListPartitionRoleResponse': ListPartitionRoleResponse$json,
  '.tenancy.v1.UpdatePartitionRoleRequest': UpdatePartitionRoleRequest$json,
  '.tenancy.v1.UpdatePartitionRoleResponse': UpdatePartitionRoleResponse$json,
  '.tenancy.v1.RemovePartitionRoleRequest': RemovePartitionRoleRequest$json,
  '.tenancy.v1.RemovePartitionRoleResponse': RemovePartitionRoleResponse$json,
  '.tenancy.v1.CreatePageRequest': CreatePageRequest$json,
  '.tenancy.v1.CreatePageResponse': CreatePageResponse$json,
  '.tenancy.v1.PageObject': PageObject$json,
  '.tenancy.v1.ListPageRequest': ListPageRequest$json,
  '.tenancy.v1.ListPageResponse': ListPageResponse$json,
  '.tenancy.v1.GetPageRequest': GetPageRequest$json,
  '.tenancy.v1.GetPageResponse': GetPageResponse$json,
  '.tenancy.v1.UpdatePageRequest': UpdatePageRequest$json,
  '.tenancy.v1.UpdatePageResponse': UpdatePageResponse$json,
  '.tenancy.v1.RemovePageRequest': RemovePageRequest$json,
  '.tenancy.v1.RemovePageResponse': RemovePageResponse$json,
  '.tenancy.v1.CreateAccessRequest': CreateAccessRequest$json,
  '.tenancy.v1.CreateAccessResponse': CreateAccessResponse$json,
  '.tenancy.v1.AccessObject': AccessObject$json,
  '.tenancy.v1.GetAccessRequest': GetAccessRequest$json,
  '.tenancy.v1.GetAccessResponse': GetAccessResponse$json,
  '.tenancy.v1.ListAccessRequest': ListAccessRequest$json,
  '.tenancy.v1.ListAccessResponse': ListAccessResponse$json,
  '.tenancy.v1.RemoveAccessRequest': RemoveAccessRequest$json,
  '.tenancy.v1.RemoveAccessResponse': RemoveAccessResponse$json,
  '.tenancy.v1.CreateAccessRoleRequest': CreateAccessRoleRequest$json,
  '.tenancy.v1.CreateAccessRoleResponse': CreateAccessRoleResponse$json,
  '.tenancy.v1.AccessRoleObject': AccessRoleObject$json,
  '.tenancy.v1.ListAccessRoleRequest': ListAccessRoleRequest$json,
  '.tenancy.v1.ListAccessRoleResponse': ListAccessRoleResponse$json,
  '.tenancy.v1.RemoveAccessRoleRequest': RemoveAccessRoleRequest$json,
  '.tenancy.v1.RemoveAccessRoleResponse': RemoveAccessRoleResponse$json,
  '.tenancy.v1.ListServiceNamespacesRequest': ListServiceNamespacesRequest$json,
  '.tenancy.v1.ListServiceNamespacesResponse': ListServiceNamespacesResponse$json,
  '.tenancy.v1.ServiceNamespaceObject': ServiceNamespaceObject$json,
  '.tenancy.v1.ServiceNamespaceObject.RoleBindingsEntry': ServiceNamespaceObject_RoleBindingsEntry$json,
  '.tenancy.v1.RolePermissionList': RolePermissionList$json,
  '.tenancy.v1.GrantPermissionRequest': GrantPermissionRequest$json,
  '.tenancy.v1.GrantPermissionResponse': GrantPermissionResponse$json,
  '.tenancy.v1.RevokePermissionRequest': RevokePermissionRequest$json,
  '.tenancy.v1.RevokePermissionResponse': RevokePermissionResponse$json,
};

/// Descriptor for `TenancyService`. Decode as a `google.protobuf.ServiceDescriptorProto`.
final $typed_data.Uint8List tenancyServiceDescriptor = $convert.base64Decode(
    'Cg5UZW5hbmN5U2VydmljZRLdAQoJR2V0VGVuYW50EhwudGVuYW5jeS52MS5HZXRUZW5hbnRSZX'
    'F1ZXN0Gh0udGVuYW5jeS52MS5HZXRUZW5hbnRSZXNwb25zZSKSAZACAbpHewoHVGVuYW50cxIK'
    'R2V0IHRlbmFudBpZUmV0cmlldmVzIGEgdGVuYW50IGJ5IGl0cyB1bmlxdWUgaWRlbnRpZmllci'
    'BpbmNsdWRpbmcgYWxsIHRlbmFudCBtZXRhZGF0YSBhbmQgcHJvcGVydGllcy4qCWdldFRlbmFu'
    'dIK1GA0KC3RlbmFudF92aWV3EogCCgpMaXN0VGVuYW50Eh0udGVuYW5jeS52MS5MaXN0VGVuYW'
    '50UmVxdWVzdBoeLnRlbmFuY3kudjEuTGlzdFRlbmFudFJlc3BvbnNlIrgBkAIBukegAQoHVGVu'
    'YW50cxIMTGlzdCB0ZW5hbnRzGnpMaXN0cyBhbGwgdGVuYW50cyBpbiB0aGUgc3lzdGVtIHdpdG'
    'ggb3B0aW9uYWwgZmlsdGVyaW5nIGJ5IHF1ZXJ5LCBkYXRlIHJhbmdlLCBhbmQgcHJvcGVydGll'
    'cy4gUmV0dXJucyBhIHN0cmVhbSBvZiB0ZW5hbnRzLioLbGlzdFRlbmFudHOCtRgNCgt0ZW5hbn'
    'RfdmlldzABEvYBCgxDcmVhdGVUZW5hbnQSHy50ZW5hbmN5LnYxLkNyZWF0ZVRlbmFudFJlcXVl'
    'c3QaIC50ZW5hbmN5LnYxLkNyZWF0ZVRlbmFudFJlc3BvbnNlIqIBukeLAQoHVGVuYW50cxINQ3'
    'JlYXRlIHRlbmFudBpjQ3JlYXRlcyBhIG5ldyB0ZW5hbnQgKHRvcC1sZXZlbCBvcmdhbml6YXRp'
    'b25hbCB1bml0KSB3aXRoIG5hbWUsIGRlc2NyaXB0aW9uLCBhbmQgY3VzdG9tIHByb3BlcnRpZX'
    'MuKgxjcmVhdGVUZW5hbnSCtRgPCg10ZW5hbnRfbWFuYWdlEtgBCgxVcGRhdGVUZW5hbnQSHy50'
    'ZW5hbmN5LnYxLlVwZGF0ZVRlbmFudFJlcXVlc3QaIC50ZW5hbmN5LnYxLlVwZGF0ZVRlbmFudF'
    'Jlc3BvbnNlIoQBukduCgdUZW5hbnRzEg1VcGRhdGUgdGVuYW50GkZVcGRhdGVzIGFuIGV4aXN0'
    'aW5nIHRlbmFudCdzIG5hbWUsIGRlc2NyaXB0aW9uLCBzdGF0ZSwgYW5kIHByb3BlcnRpZXMuKg'
    'x1cGRhdGVUZW5hbnSCtRgPCg10ZW5hbnRfbWFuYWdlEoACCgxSZW1vdmVUZW5hbnQSHy50ZW5h'
    'bmN5LnYxLlJlbW92ZVRlbmFudFJlcXVlc3QaIC50ZW5hbmN5LnYxLlJlbW92ZVRlbmFudFJlc3'
    'BvbnNlIqwBukeVAQoHVGVuYW50cxINUmVtb3ZlIHRlbmFudBptU29mdC1kZWxldGVzIGEgdGVu'
    'YW50LiBBbGwgcGFydGl0aW9ucywgYWNjZXNzIGdyYW50cywgYW5kIHJvbGVzIHdpdGhpbiB0aG'
    'UgdGVuYW50IGFyZSBhbHNvIG1hcmtlZCBhcyBkZWxldGVkLioMcmVtb3ZlVGVuYW50grUYDwoN'
    'dGVuYW50X21hbmFnZRKkAgoNTGlzdFBhcnRpdGlvbhIgLnRlbmFuY3kudjEuTGlzdFBhcnRpdG'
    'lvblJlcXVlc3QaIS50ZW5hbmN5LnYxLkxpc3RQYXJ0aXRpb25SZXNwb25zZSLLAZACAbpHsAEK'
    'ClBhcnRpdGlvbnMSD0xpc3QgcGFydGl0aW9ucxqAAUxpc3RzIGFsbCBwYXJ0aXRpb25zIGluIH'
    'RoZSBzeXN0ZW0gd2l0aCBvcHRpb25hbCBmaWx0ZXJpbmcgYnkgcXVlcnksIGRhdGUgcmFuZ2Us'
    'IGFuZCBwcm9wZXJ0aWVzLiBSZXR1cm5zIGEgc3RyZWFtIG9mIHBhcnRpdGlvbnMuKg5saXN0UG'
    'FydGl0aW9uc4K1GBAKDnBhcnRpdGlvbl92aWV3MAESiQIKD0NyZWF0ZVBhcnRpdGlvbhIiLnRl'
    'bmFuY3kudjEuQ3JlYXRlUGFydGl0aW9uUmVxdWVzdBojLnRlbmFuY3kudjEuQ3JlYXRlUGFydG'
    'l0aW9uUmVzcG9uc2UirAG6R5IBCgpQYXJ0aXRpb25zEhBDcmVhdGUgcGFydGl0aW9uGmFDcmVh'
    'dGVzIGEgbmV3IHBhcnRpdGlvbiB3aXRoaW4gYSB0ZW5hbnQuIFN1cHBvcnRzIGhpZXJhcmNoaW'
    'NhbCBzdHJ1Y3R1cmVzIHdpdGggcGFyZW50IHBhcnRpdGlvbnMuKg9jcmVhdGVQYXJ0aXRpb26C'
    'tRgSChBwYXJ0aXRpb25fbWFuYWdlEoQCCgxHZXRQYXJ0aXRpb24SHy50ZW5hbmN5LnYxLkdldF'
    'BhcnRpdGlvblJlcXVlc3QaIC50ZW5hbmN5LnYxLkdldFBhcnRpdGlvblJlc3BvbnNlIrABkAIB'
    'ukeVAQoKUGFydGl0aW9ucxINR2V0IHBhcnRpdGlvbhpqUmV0cmlldmVzIGEgcGFydGl0aW9uIG'
    'J5IGl0cyB1bmlxdWUgaWRlbnRpZmllciBvciBkb21haW4sIGluY2x1ZGluZyBhbGwgcGFydGl0'
    'aW9uIG1ldGFkYXRhIGFuZCBwcm9wZXJ0aWVzLioMZ2V0UGFydGl0aW9ugrUYEAoOcGFydGl0aW'
    '9uX3ZpZXcSoQIKE0dldFBhcnRpdGlvblBhcmVudHMSJi50ZW5hbmN5LnYxLkdldFBhcnRpdGlv'
    'blBhcmVudHNSZXF1ZXN0GicudGVuYW5jeS52MS5HZXRQYXJ0aXRpb25QYXJlbnRzUmVzcG9uc2'
    'UiuAGQAgG6R50BCgpQYXJ0aXRpb25zEhVHZXQgcGFydGl0aW9uIHBhcmVudHMaY1JldHJpZXZl'
    'cyB0aGUgY29tcGxldGUgcGFyZW50IGhpZXJhcmNoeSBmb3IgYSBwYXJ0aXRpb24gZnJvbSB0aG'
    'Ugcm9vdCB0ZW5hbnQgZG93biB0byB0aGUgcGFydGl0aW9uLioTZ2V0UGFydGl0aW9uUGFyZW50'
    'c4K1GBAKDnBhcnRpdGlvbl92aWV3EqkCCg9SZW1vdmVQYXJ0aXRpb24SIi50ZW5hbmN5LnYxLl'
    'JlbW92ZVBhcnRpdGlvblJlcXVlc3QaIy50ZW5hbmN5LnYxLlJlbW92ZVBhcnRpdGlvblJlc3Bv'
    'bnNlIswBukeyAQoKUGFydGl0aW9ucxIQUmVtb3ZlIHBhcnRpdGlvbhqAAVNvZnQtZGVsZXRlcy'
    'BhIHBhcnRpdGlvbi4gQWxsIGFjY2VzcyBncmFudHMsIHJvbGVzLCBwYWdlcywgYW5kIHNlcnZp'
    'Y2UgYWNjb3VudHMgd2l0aGluIHRoZSBwYXJ0aXRpb24gYXJlIGFsc28gbWFya2VkIGFzIGRlbG'
    'V0ZWQuKg9yZW1vdmVQYXJ0aXRpb26CtRgSChBwYXJ0aXRpb25fbWFuYWdlEvkBCg9VcGRhdGVQ'
    'YXJ0aXRpb24SIi50ZW5hbmN5LnYxLlVwZGF0ZVBhcnRpdGlvblJlcXVlc3QaIy50ZW5hbmN5Ln'
    'YxLlVwZGF0ZVBhcnRpdGlvblJlc3BvbnNlIpwBukeCAQoKUGFydGl0aW9ucxIQVXBkYXRlIHBh'
    'cnRpdGlvbhpRVXBkYXRlcyBhbiBleGlzdGluZyBwYXJ0aXRpb24ncyBuYW1lLCBkZXNjcmlwdG'
    'lvbiwgZG9tYWluLCBzdGF0ZSwgYW5kIHByb3BlcnRpZXMuKg91cGRhdGVQYXJ0aXRpb26CtRgS'
    'ChBwYXJ0aXRpb25fbWFuYWdlEooCChNDcmVhdGVQYXJ0aXRpb25Sb2xlEiYudGVuYW5jeS52MS'
    '5DcmVhdGVQYXJ0aXRpb25Sb2xlUmVxdWVzdBonLnRlbmFuY3kudjEuQ3JlYXRlUGFydGl0aW9u'
    'Um9sZVJlc3BvbnNlIqEBukeMAQoFUm9sZXMSFUNyZWF0ZSBwYXJ0aXRpb24gcm9sZRpXQ3JlYX'
    'RlcyBhIG5ldyByb2xlIHdpdGhpbiBhIHBhcnRpdGlvbiBmb3IgYWNjZXNzIGNvbnRyb2wgKGFk'
    'bWluLCBlZGl0b3IsIHZpZXdlciwgZXRjLikuKhNjcmVhdGVQYXJ0aXRpb25Sb2xlgrUYDQoLcm'
    '9sZV9tYW5hZ2USiAIKEUxpc3RQYXJ0aXRpb25Sb2xlEiQudGVuYW5jeS52MS5MaXN0UGFydGl0'
    'aW9uUm9sZVJlcXVlc3QaJS50ZW5hbmN5LnYxLkxpc3RQYXJ0aXRpb25Sb2xlUmVzcG9uc2Uiow'
    'GQAgG6R4sBCgVSb2xlcxIUTGlzdCBwYXJ0aXRpb24gcm9sZXMaWExpc3RzIGFsbCByb2xlcyBh'
    'dmFpbGFibGUgZm9yIGEgc3BlY2lmaWMgcGFydGl0aW9uLiBSZXR1cm5zIGEgc3RyZWFtIG9mIH'
    'BhcnRpdGlvbiByb2xlcy4qEmxpc3RQYXJ0aXRpb25Sb2xlc4K1GA0KC3JvbGVfbWFuYWdlMAES'
    '6QEKE1VwZGF0ZVBhcnRpdGlvblJvbGUSJi50ZW5hbmN5LnYxLlVwZGF0ZVBhcnRpdGlvblJvbG'
    'VSZXF1ZXN0GicudGVuYW5jeS52MS5VcGRhdGVQYXJ0aXRpb25Sb2xlUmVzcG9uc2UigAG6R2wK'
    'BVJvbGVzEhVVcGRhdGUgcGFydGl0aW9uIHJvbGUaN1VwZGF0ZXMgYSBwYXJ0aXRpb24gcm9sZS'
    'dzIG5hbWUsIHByb3BlcnRpZXMsIGFuZCBzdGF0ZS4qE3VwZGF0ZVBhcnRpdGlvblJvbGWCtRgN'
    'Cgtyb2xlX21hbmFnZRKFAgoTUmVtb3ZlUGFydGl0aW9uUm9sZRImLnRlbmFuY3kudjEuUmVtb3'
    'ZlUGFydGl0aW9uUm9sZVJlcXVlc3QaJy50ZW5hbmN5LnYxLlJlbW92ZVBhcnRpdGlvblJvbGVS'
    'ZXNwb25zZSKcAbpHhwEKBVJvbGVzEhVSZW1vdmUgcGFydGl0aW9uIHJvbGUaUlJlbW92ZXMgYS'
    'BwYXJ0aXRpb24gcm9sZS4gQWxsIGFjY2VzcyBncmFudHMgdXNpbmcgdGhpcyByb2xlIG11c3Qg'
    'YmUgcmVtb3ZlZCBmaXJzdC4qE3JlbW92ZVBhcnRpdGlvblJvbGWCtRgNCgtyb2xlX21hbmFnZR'
    'L+AQoKQ3JlYXRlUGFnZRIdLnRlbmFuY3kudjEuQ3JlYXRlUGFnZVJlcXVlc3QaHi50ZW5hbmN5'
    'LnYxLkNyZWF0ZVBhZ2VSZXNwb25zZSKwAbpHmwEKBVBhZ2VzEhJDcmVhdGUgY3VzdG9tIHBhZ2'
    'UackNyZWF0ZXMgYSBjdXN0b20gVUkgcGFnZSBmb3IgYSBwYXJ0aXRpb24gd2l0aCBIVE1MIGNv'
    'bnRlbnQuIEVuYWJsZXMgcGFydGl0aW9uLXNwZWNpZmljIGJyYW5kaW5nIGFuZCBjdXN0b21pem'
    'F0aW9uLioKY3JlYXRlUGFnZYK1GA0KC3BhZ2VfbWFuYWdlEscBCghMaXN0UGFnZRIbLnRlbmFu'
    'Y3kudjEuTGlzdFBhZ2VSZXF1ZXN0GhwudGVuYW5jeS52MS5MaXN0UGFnZVJlc3BvbnNlIn6QAg'
    'G6R2kKBVBhZ2VzEhFMaXN0IGN1c3RvbSBwYWdlcxpCTGlzdHMgYWxsIGN1c3RvbSBwYWdlcyBm'
    'b3IgYSBwYXJ0aXRpb24uIFJldHVybnMgYSBzdHJlYW0gb2YgcGFnZXMuKglsaXN0UGFnZXOCtR'
    'gLCglwYWdlX3ZpZXcwARK7AQoHR2V0UGFnZRIaLnRlbmFuY3kudjEuR2V0UGFnZVJlcXVlc3Qa'
    'Gy50ZW5hbmN5LnYxLkdldFBhZ2VSZXNwb25zZSJ3kAIBukdiCgVQYWdlcxIPR2V0IGN1c3RvbS'
    'BwYWdlGj9SZXRyaWV2ZXMgYSBjdXN0b20gcGFnZSBieSBwYWdlIElELCBwYXJ0aXRpb24gSUQs'
    'IG9yIHBhZ2UgbmFtZS4qB2dldFBhZ2WCtRgLCglwYWdlX3ZpZXcSzAEKClVwZGF0ZVBhZ2USHS'
    '50ZW5hbmN5LnYxLlVwZGF0ZVBhZ2VSZXF1ZXN0Gh4udGVuYW5jeS52MS5VcGRhdGVQYWdlUmVz'
    'cG9uc2Uif7pHawoFUGFnZXMSElVwZGF0ZSBjdXN0b20gcGFnZRpCVXBkYXRlcyBhIGN1c3RvbS'
    'BwYWdlJ3MgbmFtZSwgSFRNTCBjb250ZW50LCBzdGF0ZSwgYW5kIHByb3BlcnRpZXMuKgp1cGRh'
    'dGVQYWdlgrUYDQoLcGFnZV9tYW5hZ2USsQEKClJlbW92ZVBhZ2USHS50ZW5hbmN5LnYxLlJlbW'
    '92ZVBhZ2VSZXF1ZXN0Gh4udGVuYW5jeS52MS5SZW1vdmVQYWdlUmVzcG9uc2UiZLpHUAoFUGFn'
    'ZXMSElJlbW92ZSBjdXN0b20gcGFnZRonUmVtb3ZlcyBhIGN1c3RvbSBwYWdlIGZyb20gYSBwYX'
    'J0aXRpb24uKgpyZW1vdmVQYWdlgrUYDQoLcGFnZV9tYW5hZ2US/AEKDENyZWF0ZUFjY2VzcxIf'
    'LnRlbmFuY3kudjEuQ3JlYXRlQWNjZXNzUmVxdWVzdBogLnRlbmFuY3kudjEuQ3JlYXRlQWNjZX'
    'NzUmVzcG9uc2UiqAG6R5EBCgZBY2Nlc3MSE0NyZWF0ZSBhY2Nlc3MgZ3JhbnQaZEdyYW50cyBh'
    'IHByb2ZpbGUgYWNjZXNzIHRvIGEgcGFydGl0aW9uLiBUaGUgcHJvZmlsZSBjYW4gdGhlbiBiZS'
    'Bhc3NpZ25lZCByb2xlcyB2aWEgQ3JlYXRlQWNjZXNzUm9sZS4qDGNyZWF0ZUFjY2Vzc4K1GA8K'
    'DWFjY2Vzc19tYW5hZ2US2wEKCUdldEFjY2VzcxIcLnRlbmFuY3kudjEuR2V0QWNjZXNzUmVxdW'
    'VzdBodLnRlbmFuY3kudjEuR2V0QWNjZXNzUmVzcG9uc2UikAGQAgG6R3kKBkFjY2VzcxIQR2V0'
    'IGFjY2VzcyBncmFudBpSUmV0cmlldmVzIGFuIGFjY2VzcyBncmFudCBieSBhY2Nlc3MgSUQgb3'
    'IgYnkgcGFydGl0aW9uIGFuZCBwcm9maWxlIElEIGNvbWJpbmF0aW9uLioJZ2V0QWNjZXNzgrUY'
    'DQoLYWNjZXNzX3ZpZXcS8wEKCkxpc3RBY2Nlc3MSHS50ZW5hbmN5LnYxLkxpc3RBY2Nlc3NSZX'
    'F1ZXN0Gh4udGVuYW5jeS52MS5MaXN0QWNjZXNzUmVzcG9uc2UiowGQAgG6R4sBCgZBY2Nlc3MS'
    'Ekxpc3QgYWNjZXNzIGdyYW50cxphTGlzdHMgYWxsIGFjY2VzcyBncmFudHMgZm9yIGEgcGFydG'
    'l0aW9uICh3aG8gaGFzIGFjY2Vzcykgb3IgZm9yIGEgcHJvZmlsZSAod2hhdCB0aGV5IGNhbiBh'
    'Y2Nlc3MpLioKbGlzdEFjY2Vzc4K1GA0KC2FjY2Vzc192aWV3MAES8AEKDFJlbW92ZUFjY2Vzcx'
    'IfLnRlbmFuY3kudjEuUmVtb3ZlQWNjZXNzUmVxdWVzdBogLnRlbmFuY3kudjEuUmVtb3ZlQWNj'
    'ZXNzUmVzcG9uc2UinAG6R4UBCgZBY2Nlc3MSE1JlbW92ZSBhY2Nlc3MgZ3JhbnQaWFJldm9rZX'
    'MgYSBwcm9maWxlJ3MgYWNjZXNzIHRvIGEgcGFydGl0aW9uLiBBbGwgYXNzb2NpYXRlZCBhY2Nl'
    'c3Mgcm9sZXMgYXJlIGFsc28gcmVtb3ZlZC4qDHJlbW92ZUFjY2Vzc4K1GA8KDWFjY2Vzc19tYW'
    '5hZ2USmQIKEENyZWF0ZUFjY2Vzc1JvbGUSIy50ZW5hbmN5LnYxLkNyZWF0ZUFjY2Vzc1JvbGVS'
    'ZXF1ZXN0GiQudGVuYW5jeS52MS5DcmVhdGVBY2Nlc3NSb2xlUmVzcG9uc2UiuQG6R58BCgZBY2'
    'Nlc3MSFUFzc2lnbiByb2xlIHRvIGFjY2VzcxpsQXNzaWducyBhIHBhcnRpdGlvbiByb2xlIHRv'
    'IGFuIGFjY2VzcyBncmFudCwgZ3JhbnRpbmcgdGhlIHByb2ZpbGUgc3BlY2lmaWMgcGVybWlzc2'
    'lvbnMgd2l0aGluIHRoZSBwYXJ0aXRpb24uKhBjcmVhdGVBY2Nlc3NSb2xlgrUYEgoQcGVybWlz'
    'c2lvbl9ncmFudBLvAQoOTGlzdEFjY2Vzc1JvbGUSIS50ZW5hbmN5LnYxLkxpc3RBY2Nlc3NSb2'
    'xlUmVxdWVzdBoiLnRlbmFuY3kudjEuTGlzdEFjY2Vzc1JvbGVSZXNwb25zZSKTAZACAbpHfAoG'
    'QWNjZXNzEhFMaXN0IGFjY2VzcyByb2xlcxpOTGlzdHMgYWxsIHJvbGVzIGFzc2lnbmVkIHRvIG'
    'FuIGFjY2VzcyBncmFudC4gUmV0dXJucyBhIHN0cmVhbSBvZiBhY2Nlc3Mgcm9sZXMuKg9saXN0'
    'QWNjZXNzUm9sZXOCtRgNCgthY2Nlc3NfdmlldzABEpoCChBSZW1vdmVBY2Nlc3NSb2xlEiMudG'
    'VuYW5jeS52MS5SZW1vdmVBY2Nlc3NSb2xlUmVxdWVzdBokLnRlbmFuY3kudjEuUmVtb3ZlQWNj'
    'ZXNzUm9sZVJlc3BvbnNlIroBukegAQoGQWNjZXNzEhJSZW1vdmUgYWNjZXNzIHJvbGUacFJlbW'
    '92ZXMgYSBzcGVjaWZpYyByb2xlIGZyb20gYW4gYWNjZXNzIGdyYW50LiBUaGUgcHJvZmlsZSBy'
    'ZXRhaW5zIGFjY2VzcyBidXQgbG9zZXMgdGhlIHBlcm1pc3Npb25zIG9mIHRoaXMgcm9sZS4qEH'
    'JlbW92ZUFjY2Vzc1JvbGWCtRgSChBwZXJtaXNzaW9uX2dyYW50ErMCChVMaXN0U2VydmljZU5h'
    'bWVzcGFjZXMSKC50ZW5hbmN5LnYxLkxpc3RTZXJ2aWNlTmFtZXNwYWNlc1JlcXVlc3QaKS50ZW'
    '5hbmN5LnYxLkxpc3RTZXJ2aWNlTmFtZXNwYWNlc1Jlc3BvbnNlIsQBkAIBukenAQoLUGVybWlz'
    'c2lvbnMSF0xpc3Qgc2VydmljZSBuYW1lc3BhY2VzGmhSZXR1cm5zIGFsbCByZWdpc3RlcmVkIH'
    'NlcnZpY2UgcGVybWlzc2lvbiBuYW1lc3BhY2VzIHdpdGggdGhlaXIgYXZhaWxhYmxlIHBlcm1p'
    'c3Npb25zIGFuZCByb2xlIGJpbmRpbmdzLioVbGlzdFNlcnZpY2VOYW1lc3BhY2VzgrUYEgoQcG'
    'VybWlzc2lvbl9ncmFudBKaAgoPR3JhbnRQZXJtaXNzaW9uEiIudGVuYW5jeS52MS5HcmFudFBl'
    'cm1pc3Npb25SZXF1ZXN0GiMudGVuYW5jeS52MS5HcmFudFBlcm1pc3Npb25SZXNwb25zZSK9Ab'
    'pHowEKC1Blcm1pc3Npb25zEhBHcmFudCBwZXJtaXNzaW9uGnFDcmVhdGVzIGEgZ3JhbnRlZF8q'
    'IEtldG8gdHVwbGUgZ2l2aW5nIHRoZSBzcGVjaWZpZWQgcHJvZmlsZSBhIHNwZWNpZmljIHBlcm'
    '1pc3Npb24gaW4gdGhlIGdpdmVuIHNlcnZpY2UgbmFtZXNwYWNlLioPZ3JhbnRQZXJtaXNzaW9u'
    'grUYEgoQcGVybWlzc2lvbl9ncmFudBKcAgoQUmV2b2tlUGVybWlzc2lvbhIjLnRlbmFuY3kudj'
    'EuUmV2b2tlUGVybWlzc2lvblJlcXVlc3QaJC50ZW5hbmN5LnYxLlJldm9rZVBlcm1pc3Npb25S'
    'ZXNwb25zZSK8AbpHogEKC1Blcm1pc3Npb25zEhFSZXZva2UgcGVybWlzc2lvbhpuRGVsZXRlcy'
    'B0aGUgZ3JhbnRlZF8qIEtldG8gdHVwbGUgcmVtb3ZpbmcgYSBzcGVjaWZpYyBwZXJtaXNzaW9u'
    'IGZyb20gYSBwcm9maWxlIGluIHRoZSBnaXZlbiBzZXJ2aWNlIG5hbWVzcGFjZS4qEHJldm9rZV'
    'Blcm1pc3Npb26CtRgSChBwZXJtaXNzaW9uX2dyYW50GrYIgrUYsQgKD3NlcnZpY2VfdGVuYW5j'
    'eRILdGVuYW50X3ZpZXcSDXRlbmFudF9tYW5hZ2USDnBhcnRpdGlvbl92aWV3EhBwYXJ0aXRpb2'
    '5fbWFuYWdlEgthY2Nlc3NfdmlldxINYWNjZXNzX21hbmFnZRILcm9sZV9tYW5hZ2USCXBhZ2Vf'
    'dmlldxILcGFnZV9tYW5hZ2USEHBlcm1pc3Npb25fZ3JhbnQSFHNlcnZpY2VfYWNjb3VudF92aW'
    'V3EhZzZXJ2aWNlX2FjY291bnRfbWFuYWdlEgtjbGllbnRfdmlldxINY2xpZW50X21hbmFnZRrd'
    'AQgBEgt0ZW5hbnRfdmlldxINdGVuYW50X21hbmFnZRIOcGFydGl0aW9uX3ZpZXcSEHBhcnRpdG'
    'lvbl9tYW5hZ2USC2FjY2Vzc192aWV3Eg1hY2Nlc3NfbWFuYWdlEgtyb2xlX21hbmFnZRIJcGFn'
    'ZV92aWV3EgtwYWdlX21hbmFnZRIQcGVybWlzc2lvbl9ncmFudBIUc2VydmljZV9hY2NvdW50X3'
    'ZpZXcSFnNlcnZpY2VfYWNjb3VudF9tYW5hZ2USC2NsaWVudF92aWV3Eg1jbGllbnRfbWFuYWdl'
    'Gs4BCAISC3RlbmFudF92aWV3Eg5wYXJ0aXRpb25fdmlldxIQcGFydGl0aW9uX21hbmFnZRILYW'
    'NjZXNzX3ZpZXcSDWFjY2Vzc19tYW5hZ2USC3JvbGVfbWFuYWdlEglwYWdlX3ZpZXcSC3BhZ2Vf'
    'bWFuYWdlEhBwZXJtaXNzaW9uX2dyYW50EhRzZXJ2aWNlX2FjY291bnRfdmlldxIWc2VydmljZV'
    '9hY2NvdW50X21hbmFnZRILY2xpZW50X3ZpZXcSDWNsaWVudF9tYW5hZ2UaWggDEgt0ZW5hbnRf'
    'dmlldxIOcGFydGl0aW9uX3ZpZXcSC2FjY2Vzc192aWV3EglwYWdlX3ZpZXcSFHNlcnZpY2VfYW'
    'Njb3VudF92aWV3EgtjbGllbnRfdmlldxoqCAQSC3RlbmFudF92aWV3Eg5wYXJ0aXRpb25fdmll'
    'dxIJcGFnZV92aWV3GioIBRILdGVuYW50X3ZpZXcSDnBhcnRpdGlvbl92aWV3EglwYWdlX3ZpZX'
    'ca3QEIBhILdGVuYW50X3ZpZXcSDXRlbmFudF9tYW5hZ2USDnBhcnRpdGlvbl92aWV3EhBwYXJ0'
    'aXRpb25fbWFuYWdlEgthY2Nlc3NfdmlldxINYWNjZXNzX21hbmFnZRILcm9sZV9tYW5hZ2USCX'
    'BhZ2VfdmlldxILcGFnZV9tYW5hZ2USEHBlcm1pc3Npb25fZ3JhbnQSFHNlcnZpY2VfYWNjb3Vu'
    'dF92aWV3EhZzZXJ2aWNlX2FjY291bnRfbWFuYWdlEgtjbGllbnRfdmlldxINY2xpZW50X21hbm'
    'FnZQ==');

