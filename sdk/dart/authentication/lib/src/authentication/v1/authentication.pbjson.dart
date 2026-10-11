//
//  Generated code. Do not modify.
//  source: authentication/v1/authentication.proto
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

@$core.Deprecated('Use loginSourceDescriptor instead')
const LoginSource$json = {
  '1': 'LoginSource',
  '2': [
    {'1': 'LOGIN_SOURCE_UNSPECIFIED', '2': 0},
    {'1': 'LOGIN_SOURCE_DIRECT', '2': 1},
    {'1': 'LOGIN_SOURCE_GOOGLE', '2': 2},
    {'1': 'LOGIN_SOURCE_FACEBOOK', '2': 3},
    {'1': 'LOGIN_SOURCE_SERVICE_ACCOUNT', '2': 4},
    {'1': 'LOGIN_SOURCE_SESSION_REFRESH', '2': 5},
  ],
};

/// Descriptor for `LoginSource`. Decode as a `google.protobuf.EnumDescriptorProto`.
final $typed_data.Uint8List loginSourceDescriptor = $convert.base64Decode(
    'CgtMb2dpblNvdXJjZRIcChhMT0dJTl9TT1VSQ0VfVU5TUEVDSUZJRUQQABIXChNMT0dJTl9TT1'
    'VSQ0VfRElSRUNUEAESFwoTTE9HSU5fU09VUkNFX0dPT0dMRRACEhkKFUxPR0lOX1NPVVJDRV9G'
    'QUNFQk9PSxADEiAKHExPR0lOX1NPVVJDRV9TRVJWSUNFX0FDQ09VTlQQBBIgChxMT0dJTl9TT1'
    'VSQ0VfU0VTU0lPTl9SRUZSRVNIEAU=');

@$core.Deprecated('Use loginEventObjectDescriptor instead')
const LoginEventObject$json = {
  '1': 'LoginEventObject',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '10': 'id'},
    {'1': 'tenant_id', '3': 2, '4': 1, '5': 9, '10': 'tenantId'},
    {'1': 'partition_id', '3': 3, '4': 1, '5': 9, '10': 'partitionId'},
    {'1': 'profile_id', '3': 4, '4': 1, '5': 9, '10': 'profileId'},
    {'1': 'client_id', '3': 5, '4': 1, '5': 9, '10': 'clientId'},
    {'1': 'source', '3': 6, '4': 1, '5': 9, '10': 'source'},
    {'1': 'contact_id', '3': 7, '4': 1, '5': 9, '10': 'contactId'},
    {'1': 'device_id', '3': 8, '4': 1, '5': 9, '10': 'deviceId'},
    {'1': 'ip_address', '3': 9, '4': 1, '5': 9, '10': 'ipAddress'},
    {'1': 'user_agent', '3': 10, '4': 1, '5': 9, '10': 'userAgent'},
    {'1': 'status', '3': 11, '4': 1, '5': 5, '10': 'status'},
    {'1': 'properties', '3': 12, '4': 1, '5': 11, '6': '.google.protobuf.Struct', '10': 'properties'},
    {'1': 'created_at', '3': 13, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'createdAt'},
  ],
};

/// Descriptor for `LoginEventObject`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List loginEventObjectDescriptor = $convert.base64Decode(
    'ChBMb2dpbkV2ZW50T2JqZWN0Eg4KAmlkGAEgASgJUgJpZBIbCgl0ZW5hbnRfaWQYAiABKAlSCH'
    'RlbmFudElkEiEKDHBhcnRpdGlvbl9pZBgDIAEoCVILcGFydGl0aW9uSWQSHQoKcHJvZmlsZV9p'
    'ZBgEIAEoCVIJcHJvZmlsZUlkEhsKCWNsaWVudF9pZBgFIAEoCVIIY2xpZW50SWQSFgoGc291cm'
    'NlGAYgASgJUgZzb3VyY2USHQoKY29udGFjdF9pZBgHIAEoCVIJY29udGFjdElkEhsKCWRldmlj'
    'ZV9pZBgIIAEoCVIIZGV2aWNlSWQSHQoKaXBfYWRkcmVzcxgJIAEoCVIJaXBBZGRyZXNzEh0KCn'
    'VzZXJfYWdlbnQYCiABKAlSCXVzZXJBZ2VudBIWCgZzdGF0dXMYCyABKAVSBnN0YXR1cxI3Cgpw'
    'cm9wZXJ0aWVzGAwgASgLMhcuZ29vZ2xlLnByb3RvYnVmLlN0cnVjdFIKcHJvcGVydGllcxI5Cg'
    'pjcmVhdGVkX2F0GA0gASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcFIJY3JlYXRlZEF0');

@$core.Deprecated('Use getLoginEventRequestDescriptor instead')
const GetLoginEventRequest$json = {
  '1': 'GetLoginEventRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `GetLoginEventRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getLoginEventRequestDescriptor = $convert.base64Decode(
    'ChRHZXRMb2dpbkV2ZW50UmVxdWVzdBIXCgJpZBgBIAEoCUIHukgEcgIQAVICaWQ=');

@$core.Deprecated('Use getLoginEventResponseDescriptor instead')
const GetLoginEventResponse$json = {
  '1': 'GetLoginEventResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 1, '5': 11, '6': '.authentication.v1.LoginEventObject', '10': 'data'},
  ],
};

/// Descriptor for `GetLoginEventResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getLoginEventResponseDescriptor = $convert.base64Decode(
    'ChVHZXRMb2dpbkV2ZW50UmVzcG9uc2USNwoEZGF0YRgBIAEoCzIjLmF1dGhlbnRpY2F0aW9uLn'
    'YxLkxvZ2luRXZlbnRPYmplY3RSBGRhdGE=');

@$core.Deprecated('Use listLoginEventsRequestDescriptor instead')
const ListLoginEventsRequest$json = {
  '1': 'ListLoginEventsRequest',
  '2': [
    {'1': 'profile_id', '3': 1, '4': 1, '5': 9, '10': 'profileId'},
    {'1': 'client_id', '3': 2, '4': 1, '5': 9, '10': 'clientId'},
    {'1': 'source', '3': 3, '4': 1, '5': 9, '10': 'source'},
    {'1': 'device_id', '3': 4, '4': 1, '5': 9, '10': 'deviceId'},
    {'1': 'start_date', '3': 5, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'startDate'},
    {'1': 'end_date', '3': 6, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'endDate'},
    {'1': 'count', '3': 7, '4': 1, '5': 5, '10': 'count'},
    {'1': 'page', '3': 8, '4': 1, '5': 9, '10': 'page'},
  ],
};

/// Descriptor for `ListLoginEventsRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listLoginEventsRequestDescriptor = $convert.base64Decode(
    'ChZMaXN0TG9naW5FdmVudHNSZXF1ZXN0Eh0KCnByb2ZpbGVfaWQYASABKAlSCXByb2ZpbGVJZB'
    'IbCgljbGllbnRfaWQYAiABKAlSCGNsaWVudElkEhYKBnNvdXJjZRgDIAEoCVIGc291cmNlEhsK'
    'CWRldmljZV9pZBgEIAEoCVIIZGV2aWNlSWQSOQoKc3RhcnRfZGF0ZRgFIAEoCzIaLmdvb2dsZS'
    '5wcm90b2J1Zi5UaW1lc3RhbXBSCXN0YXJ0RGF0ZRI1CghlbmRfZGF0ZRgGIAEoCzIaLmdvb2ds'
    'ZS5wcm90b2J1Zi5UaW1lc3RhbXBSB2VuZERhdGUSFAoFY291bnQYByABKAVSBWNvdW50EhIKBH'
    'BhZ2UYCCABKAlSBHBhZ2U=');

@$core.Deprecated('Use listLoginEventsResponseDescriptor instead')
const ListLoginEventsResponse$json = {
  '1': 'ListLoginEventsResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.authentication.v1.LoginEventObject', '10': 'data'},
  ],
};

/// Descriptor for `ListLoginEventsResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listLoginEventsResponseDescriptor = $convert.base64Decode(
    'ChdMaXN0TG9naW5FdmVudHNSZXNwb25zZRI3CgRkYXRhGAEgAygLMiMuYXV0aGVudGljYXRpb2'
    '4udjEuTG9naW5FdmVudE9iamVjdFIEZGF0YQ==');

@$core.Deprecated('Use genesisSessionProofClaimsDescriptor instead')
const GenesisSessionProofClaims$json = {
  '1': 'GenesisSessionProofClaims',
  '2': [
    {'1': 'version', '3': 1, '4': 1, '5': 9, '10': 'version'},
    {'1': 'key_id', '3': 2, '4': 1, '5': 9, '10': 'keyId'},
    {'1': 'algorithm', '3': 3, '4': 1, '5': 9, '10': 'algorithm'},
    {'1': 'profile_id', '3': 4, '4': 1, '5': 9, '10': 'profileId'},
    {'1': 'device_id', '3': 5, '4': 1, '5': 9, '10': 'deviceId'},
    {'1': 'pubkey_hash', '3': 6, '4': 1, '5': 9, '10': 'pubkeyHash'},
    {'1': 'device_key_id', '3': 7, '4': 1, '5': 9, '10': 'deviceKeyId'},
    {'1': 'nonce', '3': 8, '4': 1, '5': 9, '10': 'nonce'},
    {'1': 'issued_at', '3': 9, '4': 1, '5': 9, '10': 'issuedAt'},
    {'1': 'expires_at', '3': 10, '4': 1, '5': 9, '10': 'expiresAt'},
    {'1': 'session_id', '3': 11, '4': 1, '5': 9, '10': 'sessionId'},
    {'1': 'tenant_id', '3': 12, '4': 1, '5': 9, '10': 'tenantId'},
    {'1': 'partition_id', '3': 13, '4': 1, '5': 9, '10': 'partitionId'},
    {'1': 'audience', '3': 14, '4': 1, '5': 9, '10': 'audience'},
  ],
};

/// Descriptor for `GenesisSessionProofClaims`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List genesisSessionProofClaimsDescriptor = $convert.base64Decode(
    'ChlHZW5lc2lzU2Vzc2lvblByb29mQ2xhaW1zEhgKB3ZlcnNpb24YASABKAlSB3ZlcnNpb24SFQ'
    'oGa2V5X2lkGAIgASgJUgVrZXlJZBIcCglhbGdvcml0aG0YAyABKAlSCWFsZ29yaXRobRIdCgpw'
    'cm9maWxlX2lkGAQgASgJUglwcm9maWxlSWQSGwoJZGV2aWNlX2lkGAUgASgJUghkZXZpY2VJZB'
    'IfCgtwdWJrZXlfaGFzaBgGIAEoCVIKcHVia2V5SGFzaBIiCg1kZXZpY2Vfa2V5X2lkGAcgASgJ'
    'UgtkZXZpY2VLZXlJZBIUCgVub25jZRgIIAEoCVIFbm9uY2USGwoJaXNzdWVkX2F0GAkgASgJUg'
    'hpc3N1ZWRBdBIdCgpleHBpcmVzX2F0GAogASgJUglleHBpcmVzQXQSHQoKc2Vzc2lvbl9pZBgL'
    'IAEoCVIJc2Vzc2lvbklkEhsKCXRlbmFudF9pZBgMIAEoCVIIdGVuYW50SWQSIQoMcGFydGl0aW'
    '9uX2lkGA0gASgJUgtwYXJ0aXRpb25JZBIaCghhdWRpZW5jZRgOIAEoCVIIYXVkaWVuY2U=');

@$core.Deprecated('Use issueGenesisSessionProofRequestDescriptor instead')
const IssueGenesisSessionProofRequest$json = {
  '1': 'IssueGenesisSessionProofRequest',
  '2': [
    {'1': 'pubkey_hash', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'pubkeyHash'},
    {'1': 'device_key_id', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'deviceKeyId'},
    {'1': 'device_id', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'deviceId'},
  ],
};

/// Descriptor for `IssueGenesisSessionProofRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List issueGenesisSessionProofRequestDescriptor = $convert.base64Decode(
    'Ch9Jc3N1ZUdlbmVzaXNTZXNzaW9uUHJvb2ZSZXF1ZXN0EjkKC3B1YmtleV9oYXNoGAEgASgJQh'
    'i6SBVyEzIRXlswLTlhLWZBLUZdezY0fSRSCnB1YmtleUhhc2gSLAoNZGV2aWNlX2tleV9pZBgC'
    'IAEoCUIIukgFcgMY/wFSC2RldmljZUtleUlkEiUKCWRldmljZV9pZBgDIAEoCUIIukgFcgMY/w'
    'FSCGRldmljZUlk');

@$core.Deprecated('Use issueGenesisSessionProofResponseDescriptor instead')
const IssueGenesisSessionProofResponse$json = {
  '1': 'IssueGenesisSessionProofResponse',
  '2': [
    {'1': 'token', '3': 1, '4': 1, '5': 9, '10': 'token'},
    {'1': 'key_id', '3': 2, '4': 1, '5': 9, '10': 'keyId'},
    {'1': 'algorithm', '3': 3, '4': 1, '5': 9, '10': 'algorithm'},
    {'1': 'nonce', '3': 4, '4': 1, '5': 9, '10': 'nonce'},
    {'1': 'issued_at', '3': 5, '4': 1, '5': 9, '10': 'issuedAt'},
    {'1': 'expires_at', '3': 6, '4': 1, '5': 9, '10': 'expiresAt'},
    {'1': 'binding_hash', '3': 7, '4': 1, '5': 9, '10': 'bindingHash'},
    {'1': 'audience', '3': 8, '4': 1, '5': 9, '10': 'audience'},
  ],
};

/// Descriptor for `IssueGenesisSessionProofResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List issueGenesisSessionProofResponseDescriptor = $convert.base64Decode(
    'CiBJc3N1ZUdlbmVzaXNTZXNzaW9uUHJvb2ZSZXNwb25zZRIUCgV0b2tlbhgBIAEoCVIFdG9rZW'
    '4SFQoGa2V5X2lkGAIgASgJUgVrZXlJZBIcCglhbGdvcml0aG0YAyABKAlSCWFsZ29yaXRobRIU'
    'CgVub25jZRgEIAEoCVIFbm9uY2USGwoJaXNzdWVkX2F0GAUgASgJUghpc3N1ZWRBdBIdCgpleH'
    'BpcmVzX2F0GAYgASgJUglleHBpcmVzQXQSIQoMYmluZGluZ19oYXNoGAcgASgJUgtiaW5kaW5n'
    'SGFzaBIaCghhdWRpZW5jZRgIIAEoCVIIYXVkaWVuY2U=');

@$core.Deprecated('Use verifyGenesisSessionProofRequestDescriptor instead')
const VerifyGenesisSessionProofRequest$json = {
  '1': 'VerifyGenesisSessionProofRequest',
  '2': [
    {'1': 'token', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'token'},
    {'1': 'profile_id', '3': 2, '4': 1, '5': 9, '10': 'profileId'},
    {'1': 'device_id', '3': 3, '4': 1, '5': 9, '10': 'deviceId'},
    {'1': 'pubkey_hash', '3': 4, '4': 1, '5': 9, '10': 'pubkeyHash'},
    {'1': 'device_key_id', '3': 5, '4': 1, '5': 9, '10': 'deviceKeyId'},
    {'1': 'consume', '3': 6, '4': 1, '5': 8, '10': 'consume'},
  ],
};

/// Descriptor for `VerifyGenesisSessionProofRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List verifyGenesisSessionProofRequestDescriptor = $convert.base64Decode(
    'CiBWZXJpZnlHZW5lc2lzU2Vzc2lvblByb29mUmVxdWVzdBIdCgV0b2tlbhgBIAEoCUIHukgEcg'
    'IQAVIFdG9rZW4SHQoKcHJvZmlsZV9pZBgCIAEoCVIJcHJvZmlsZUlkEhsKCWRldmljZV9pZBgD'
    'IAEoCVIIZGV2aWNlSWQSHwoLcHVia2V5X2hhc2gYBCABKAlSCnB1YmtleUhhc2gSIgoNZGV2aW'
    'NlX2tleV9pZBgFIAEoCVILZGV2aWNlS2V5SWQSGAoHY29uc3VtZRgGIAEoCFIHY29uc3VtZQ==');

@$core.Deprecated('Use verifyGenesisSessionProofResponseDescriptor instead')
const VerifyGenesisSessionProofResponse$json = {
  '1': 'VerifyGenesisSessionProofResponse',
  '2': [
    {'1': 'valid', '3': 1, '4': 1, '5': 8, '10': 'valid'},
    {'1': 'reason', '3': 2, '4': 1, '5': 9, '10': 'reason'},
    {'1': 'claims', '3': 3, '4': 1, '5': 11, '6': '.authentication.v1.GenesisSessionProofClaims', '10': 'claims'},
    {'1': 'binding_hash', '3': 4, '4': 1, '5': 9, '10': 'bindingHash'},
  ],
};

/// Descriptor for `VerifyGenesisSessionProofResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List verifyGenesisSessionProofResponseDescriptor = $convert.base64Decode(
    'CiFWZXJpZnlHZW5lc2lzU2Vzc2lvblByb29mUmVzcG9uc2USFAoFdmFsaWQYASABKAhSBXZhbG'
    'lkEhYKBnJlYXNvbhgCIAEoCVIGcmVhc29uEkQKBmNsYWltcxgDIAEoCzIsLmF1dGhlbnRpY2F0'
    'aW9uLnYxLkdlbmVzaXNTZXNzaW9uUHJvb2ZDbGFpbXNSBmNsYWltcxIhCgxiaW5kaW5nX2hhc2'
    'gYBCABKAlSC2JpbmRpbmdIYXNo');

const $core.Map<$core.String, $core.dynamic> AuthenticationServiceBase$json = {
  '1': 'AuthenticationService',
  '2': [
    {
      '1': 'GetLoginEvent',
      '2': '.authentication.v1.GetLoginEventRequest',
      '3': '.authentication.v1.GetLoginEventResponse',
      '4': {'34': 1},
    },
    {
      '1': 'ListLoginEvents',
      '2': '.authentication.v1.ListLoginEventsRequest',
      '3': '.authentication.v1.ListLoginEventsResponse',
      '4': {'34': 1},
      '6': true,
    },
    {'1': 'IssueGenesisSessionProof', '2': '.authentication.v1.IssueGenesisSessionProofRequest', '3': '.authentication.v1.IssueGenesisSessionProofResponse', '4': {}},
    {'1': 'VerifyGenesisSessionProof', '2': '.authentication.v1.VerifyGenesisSessionProofRequest', '3': '.authentication.v1.VerifyGenesisSessionProofResponse', '4': {}},
  ],
  '3': {},
};

@$core.Deprecated('Use authenticationServiceDescriptor instead')
const $core.Map<$core.String, $core.Map<$core.String, $core.dynamic>> AuthenticationServiceBase$messageJson = {
  '.authentication.v1.GetLoginEventRequest': GetLoginEventRequest$json,
  '.authentication.v1.GetLoginEventResponse': GetLoginEventResponse$json,
  '.authentication.v1.LoginEventObject': LoginEventObject$json,
  '.google.protobuf.Struct': $6.Struct$json,
  '.google.protobuf.Struct.FieldsEntry': $6.Struct_FieldsEntry$json,
  '.google.protobuf.Value': $6.Value$json,
  '.google.protobuf.ListValue': $6.ListValue$json,
  '.google.protobuf.Timestamp': $2.Timestamp$json,
  '.authentication.v1.ListLoginEventsRequest': ListLoginEventsRequest$json,
  '.authentication.v1.ListLoginEventsResponse': ListLoginEventsResponse$json,
  '.authentication.v1.IssueGenesisSessionProofRequest': IssueGenesisSessionProofRequest$json,
  '.authentication.v1.IssueGenesisSessionProofResponse': IssueGenesisSessionProofResponse$json,
  '.authentication.v1.VerifyGenesisSessionProofRequest': VerifyGenesisSessionProofRequest$json,
  '.authentication.v1.VerifyGenesisSessionProofResponse': VerifyGenesisSessionProofResponse$json,
  '.authentication.v1.GenesisSessionProofClaims': GenesisSessionProofClaims$json,
};

/// Descriptor for `AuthenticationService`. Decode as a `google.protobuf.ServiceDescriptorProto`.
final $typed_data.Uint8List authenticationServiceDescriptor = $convert.base64Decode(
    'ChVBdXRoZW50aWNhdGlvblNlcnZpY2USuQIKDUdldExvZ2luRXZlbnQSJy5hdXRoZW50aWNhdG'
    'lvbi52MS5HZXRMb2dpbkV2ZW50UmVxdWVzdBooLmF1dGhlbnRpY2F0aW9uLnYxLkdldExvZ2lu'
    'RXZlbnRSZXNwb25zZSLUAZACAbpHugEKDkF1dGhlbnRpY2F0aW9uEg9HZXQgbG9naW4gZXZlbn'
    'QahwFSZXRyaWV2ZXMgYSBzaW5nbGUgbG9naW4gZXZlbnQgYnkgaXRzIHVuaXF1ZSBpZGVudGlm'
    'aWVyLiBVc2VycyBjYW4gb25seSB2aWV3IHRoZWlyIG93biBsb2dpbiBldmVudHMgdW5sZXNzIH'
    'RoZXkgaGF2ZSBhZG1pbiBwZXJtaXNzaW9ucy4qDWdldExvZ2luRXZlbnSCtRgPCg1hdXRoX3Zp'
    'ZXdfb3duEtwCCg9MaXN0TG9naW5FdmVudHMSKS5hdXRoZW50aWNhdGlvbi52MS5MaXN0TG9naW'
    '5FdmVudHNSZXF1ZXN0GiouYXV0aGVudGljYXRpb24udjEuTGlzdExvZ2luRXZlbnRzUmVzcG9u'
    'c2Ui7wGQAgG6R9UBCg5BdXRoZW50aWNhdGlvbhIRTGlzdCBsb2dpbiBldmVudHMangFMaXN0cy'
    'Bsb2dpbiBldmVudHMgd2l0aCBmaWx0ZXJpbmcgYnkgcHJvZmlsZSwgY2xpZW50LCBzb3VyY2Us'
    'IGRldmljZSwgYW5kIHRpbWUgcmFuZ2UuIFVzZXJzIGNhbiBvbmx5IGxpc3QgdGhlaXIgb3duIG'
    'V2ZW50cyB1bmxlc3MgdGhleSBoYXZlIGFkbWluIHBlcm1pc3Npb25zLioPbGlzdExvZ2luRXZl'
    'bnRzgrUYDwoNYXV0aF92aWV3X293bjABEsUCChhJc3N1ZUdlbmVzaXNTZXNzaW9uUHJvb2YSMi'
    '5hdXRoZW50aWNhdGlvbi52MS5Jc3N1ZUdlbmVzaXNTZXNzaW9uUHJvb2ZSZXF1ZXN0GjMuYXV0'
    'aGVudGljYXRpb24udjEuSXNzdWVHZW5lc2lzU2Vzc2lvblByb29mUmVzcG9uc2UivwG6R7sBCh'
    'NHZW5lc2lzU2Vzc2lvblByb29mEhtJc3N1ZSBnZW5lc2lzIHNlc3Npb24gcHJvb2YabU1pbnRz'
    'IGEgZ2VuZXNpcyBzZXNzaW9uIHByb29mIGJvdW5kIHRvIHRoZSBjYWxsZXIncyBsaXZlIHNlc3'
    'Npb24sIGRldmljZSBhbmQgdGhlIGRldmljZSBrZXkgYmVpbmcgcmVnaXN0ZXJlZC4qGGlzc3Vl'
    'R2VuZXNpc1Nlc3Npb25Qcm9vZhLjAgoZVmVyaWZ5R2VuZXNpc1Nlc3Npb25Qcm9vZhIzLmF1dG'
    'hlbnRpY2F0aW9uLnYxLlZlcmlmeUdlbmVzaXNTZXNzaW9uUHJvb2ZSZXF1ZXN0GjQuYXV0aGVu'
    'dGljYXRpb24udjEuVmVyaWZ5R2VuZXNpc1Nlc3Npb25Qcm9vZlJlc3BvbnNlItoBuke9AQoTR2'
    'VuZXNpc1Nlc3Npb25Qcm9vZhIcVmVyaWZ5IGdlbmVzaXMgc2Vzc2lvbiBwcm9vZhptVmVyaWZp'
    'ZXMgYSBnZW5lc2lzIHNlc3Npb24gcHJvb2YgYWdhaW5zdCB0aGUgZXhwZWN0ZWQgcHJvZmlsZS'
    'wgZGV2aWNlIGFuZCBrZXksIG9wdGlvbmFsbHkgc3BlbmRpbmcgaXRzIG5vbmNlLioZdmVyaWZ5'
    'R2VuZXNpc1Nlc3Npb25Qcm9vZoK1GBUKE2F1dGhfZ2VuZXNpc192ZXJpZnka7wGCtRjqAQoWc2'
    'VydmljZV9hdXRoZW50aWNhdGlvbhINYXV0aF92aWV3X293bhINYXV0aF92aWV3X2FsbBITYXV0'
    'aF9nZW5lc2lzX3ZlcmlmeRogCAESDWF1dGhfdmlld19vd24SDWF1dGhfdmlld19hbGwaIAgCEg'
    '1hdXRoX3ZpZXdfb3duEg1hdXRoX3ZpZXdfYWxsGhEIAxINYXV0aF92aWV3X293bhoRCAQSDWF1'
    'dGhfdmlld19vd24aEQgFEg1hdXRoX3ZpZXdfb3duGiAIBhINYXV0aF92aWV3X293bhINYXV0aF'
    '92aWV3X2FsbA==');

