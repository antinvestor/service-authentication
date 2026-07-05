//
//  Generated code. Do not modify.
//  source: tenancy/v2/auth_contract.proto
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
import '../../google/protobuf/field_mask.pbjson.dart' as $1;
import '../../google/protobuf/struct.pbjson.dart' as $6;
import '../../google/protobuf/timestamp.pbjson.dart' as $2;

@$core.Deprecated('Use authorizationScopeDescriptor instead')
const AuthorizationScope$json = {
  '1': 'AuthorizationScope',
  '2': [
    {'1': 'AUTHORIZATION_SCOPE_UNSPECIFIED', '2': 0},
    {'1': 'AUTHORIZATION_SCOPE_PARTITION_ONLY', '2': 1},
    {'1': 'AUTHORIZATION_SCOPE_PARTITION_TREE', '2': 2},
  ],
};

/// Descriptor for `AuthorizationScope`. Decode as a `google.protobuf.EnumDescriptorProto`.
final $typed_data.Uint8List authorizationScopeDescriptor = $convert.base64Decode(
    'ChJBdXRob3JpemF0aW9uU2NvcGUSIwofQVVUSE9SSVpBVElPTl9TQ09QRV9VTlNQRUNJRklFRB'
    'AAEiYKIkFVVEhPUklaQVRJT05fU0NPUEVfUEFSVElUSU9OX09OTFkQARImCiJBVVRIT1JJWkFU'
    'SU9OX1NDT1BFX1BBUlRJVElPTl9UUkVFEAI=');

@$core.Deprecated('Use authorizationPolicyStatusDescriptor instead')
const AuthorizationPolicyStatus$json = {
  '1': 'AuthorizationPolicyStatus',
  '2': [
    {'1': 'AUTHORIZATION_POLICY_STATUS_UNSPECIFIED', '2': 0},
    {'1': 'AUTHORIZATION_POLICY_STATUS_PENDING', '2': 1},
    {'1': 'AUTHORIZATION_POLICY_STATUS_APPLIED', '2': 2},
    {'1': 'AUTHORIZATION_POLICY_STATUS_FAILED', '2': 3},
  ],
};

/// Descriptor for `AuthorizationPolicyStatus`. Decode as a `google.protobuf.EnumDescriptorProto`.
final $typed_data.Uint8List authorizationPolicyStatusDescriptor = $convert.base64Decode(
    'ChlBdXRob3JpemF0aW9uUG9saWN5U3RhdHVzEisKJ0FVVEhPUklaQVRJT05fUE9MSUNZX1NUQV'
    'RVU19VTlNQRUNJRklFRBAAEicKI0FVVEhPUklaQVRJT05fUE9MSUNZX1NUQVRVU19QRU5ESU5H'
    'EAESJwojQVVUSE9SSVpBVElPTl9QT0xJQ1lfU1RBVFVTX0FQUExJRUQQAhImCiJBVVRIT1JJWk'
    'FUSU9OX1BPTElDWV9TVEFUVVNfRkFJTEVEEAM=');

@$core.Deprecated('Use oAuthClientConfigurationDescriptor instead')
const OAuthClientConfiguration$json = {
  '1': 'OAuthClientConfiguration',
  '2': [
    {'1': 'grant_types', '3': 1, '4': 3, '5': 9, '8': {}, '10': 'grantTypes'},
    {
      '1': 'response_types',
      '3': 2,
      '4': 3,
      '5': 9,
      '8': {},
      '10': 'responseTypes'
    },
    {'1': 'redirect_uris', '3': 3, '4': 3, '5': 9, '10': 'redirectUris'},
    {'1': 'scopes', '3': 4, '4': 1, '5': 9, '10': 'scopes'},
    {
      '1': 'resource_recipients',
      '3': 5,
      '4': 3,
      '5': 9,
      '8': {},
      '10': 'resourceRecipients'
    },
    {
      '1': 'token_endpoint_auth_method',
      '3': 6,
      '4': 1,
      '5': 9,
      '8': {},
      '10': 'tokenEndpointAuthMethod'
    },
    {
      '1': 'properties',
      '3': 7,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Struct',
      '10': 'properties'
    },
  ],
};

/// Descriptor for `OAuthClientConfiguration`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List oAuthClientConfigurationDescriptor = $convert.base64Decode(
    'ChhPQXV0aENsaWVudENvbmZpZ3VyYXRpb24SZAoLZ3JhbnRfdHlwZXMYASADKAlCQ7pIQJIBPR'
    'gBIjlyN1ISYXV0aG9yaXphdGlvbl9jb2RlUhJjbGllbnRfY3JlZGVudGlhbHNSDXJlZnJlc2hf'
    'dG9rZW5SCmdyYW50VHlwZXMSQAoOcmVzcG9uc2VfdHlwZXMYAiADKAlCGbpIFpIBExgBIg9yDV'
    'IEY29kZVIFdG9rZW5SDXJlc3BvbnNlVHlwZXMSIwoNcmVkaXJlY3RfdXJpcxgDIAMoCVIMcmVk'
    'aXJlY3RVcmlzEhYKBnNjb3BlcxgEIAEoCVIGc2NvcGVzElwKE3Jlc291cmNlX3JlY2lwaWVudH'
    'MYBSADKAlCK7pIKJIBJQgBGAEiH3IdMhheaHR0cHM6Ly9bXi8/I10rL1tePyNdKySIAQFSEnJl'
    'c291cmNlUmVjaXBpZW50cxKFAQoadG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2QYBiABKAlCSL'
    'pIRdgBAXJAUgRub25lUhNjbGllbnRfc2VjcmV0X2Jhc2ljUhJjbGllbnRfc2VjcmV0X3Bvc3RS'
    'D3ByaXZhdGVfa2V5X2p3dFIXdG9rZW5FbmRwb2ludEF1dGhNZXRob2QSNwoKcHJvcGVydGllcx'
    'gHIAEoCzIXLmdvb2dsZS5wcm90b2J1Zi5TdHJ1Y3RSCnByb3BlcnRpZXM=');

@$core.Deprecated('Use oAuthClientDescriptor instead')
const OAuthClient$json = {
  '1': 'OAuthClient',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'client_id', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'clientId'},
    {'1': 'type', '3': 4, '4': 1, '5': 9, '8': {}, '10': 'type'},
    {
      '1': 'configuration',
      '3': 5,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.OAuthClientConfiguration',
      '10': 'configuration'
    },
    {
      '1': 'state',
      '3': 6,
      '4': 1,
      '5': 14,
      '6': '.common.v1.STATE',
      '10': 'state'
    },
    {
      '1': 'created_at',
      '3': 7,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Timestamp',
      '10': 'createdAt'
    },
    {
      '1': 'partition_id',
      '3': 8,
      '4': 1,
      '5': 9,
      '8': {},
      '9': 0,
      '10': 'partitionId'
    },
    {
      '1': 'service_account_id',
      '3': 9,
      '4': 1,
      '5': 9,
      '8': {},
      '9': 0,
      '10': 'serviceAccountId'
    },
  ],
  '8': [
    {'1': 'owner'},
  ],
};

/// Descriptor for `OAuthClient`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List oAuthClientDescriptor = $convert.base64Decode(
    'CgtPQXV0aENsaWVudBInCgJpZBgBIAEoCUIXukgUchIyEFswLTlhLXpfLV17Myw1MH1SAmlkEh'
    '0KBG5hbWUYAiABKAlCCbpIBnIEEAMYZFIEbmFtZRImCgljbGllbnRfaWQYAyABKAlCCbpIBnIE'
    'EAMYZFIIY2xpZW50SWQSQwoEdHlwZRgEIAEoCUIvukgscipSBnB1YmxpY1IMY29uZmlkZW50aW'
    'FsUghpbnRlcm5hbFIIZXh0ZXJuYWxSBHR5cGUSSgoNY29uZmlndXJhdGlvbhgFIAEoCzIkLnRl'
    'bmFuY3kudjIuT0F1dGhDbGllbnRDb25maWd1cmF0aW9uUg1jb25maWd1cmF0aW9uEiYKBXN0YX'
    'RlGAYgASgOMhAuY29tbW9uLnYxLlNUQVRFUgVzdGF0ZRI5CgpjcmVhdGVkX2F0GAcgASgLMhou'
    'Z29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcFIJY3JlYXRlZEF0EjwKDHBhcnRpdGlvbl9pZBgIIA'
    'EoCUIXukgUchIyEFswLTlhLXpfLV17Myw1MH1IAFILcGFydGl0aW9uSWQSRwoSc2VydmljZV9h'
    'Y2NvdW50X2lkGAkgASgJQhe6SBRyEjIQWzAtOWEtel8tXXszLDUwfUgAUhBzZXJ2aWNlQWNjb3'
    'VudElkQgcKBW93bmVy');

@$core.Deprecated('Use serviceAuthorizationGrantDescriptor instead')
const ServiceAuthorizationGrant$json = {
  '1': 'ServiceAuthorizationGrant',
  '2': [
    {'1': 'namespace', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'namespace'},
    {'1': 'permissions', '3': 2, '4': 3, '5': 9, '8': {}, '10': 'permissions'},
    {
      '1': 'scope',
      '3': 3,
      '4': 1,
      '5': 14,
      '6': '.tenancy.v2.AuthorizationScope',
      '8': {},
      '10': 'scope'
    },
  ],
};

/// Descriptor for `ServiceAuthorizationGrant`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List serviceAuthorizationGrantDescriptor = $convert.base64Decode(
    'ChlTZXJ2aWNlQXV0aG9yaXphdGlvbkdyYW50EjkKCW5hbWVzcGFjZRgBIAEoCUIbukgYchYyFF'
    'thLXpdW2EtejAtOV9dezIsOTl9UgluYW1lc3BhY2USRgoLcGVybWlzc2lvbnMYAiADKAlCJLpI'
    'IZIBHggBGAEiGHIWMhRbYS16XVthLXowLTlfXXsxLDk5fVILcGVybWlzc2lvbnMSQAoFc2NvcG'
    'UYAyABKA4yHi50ZW5hbmN5LnYyLkF1dGhvcml6YXRpb25TY29wZUIKukgHggEEEAEgAFIFc2Nv'
    'cGU=');

@$core.Deprecated('Use serviceAuthorizationPolicyInputDescriptor instead')
const ServiceAuthorizationPolicyInput$json = {
  '1': 'ServiceAuthorizationPolicyInput',
  '2': [
    {
      '1': 'schema_version',
      '3': 1,
      '4': 1,
      '5': 5,
      '8': {},
      '10': 'schemaVersion'
    },
    {
      '1': 'grants',
      '3': 2,
      '4': 3,
      '5': 11,
      '6': '.tenancy.v2.ServiceAuthorizationGrant',
      '8': {},
      '10': 'grants'
    },
  ],
};

/// Descriptor for `ServiceAuthorizationPolicyInput`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List serviceAuthorizationPolicyInputDescriptor =
    $convert.base64Decode(
        'Ch9TZXJ2aWNlQXV0aG9yaXphdGlvblBvbGljeUlucHV0Ei4KDnNjaGVtYV92ZXJzaW9uGAEgAS'
        'gFQge6SAQaAggBUg1zY2hlbWFWZXJzaW9uEkcKBmdyYW50cxgCIAMoCzIlLnRlbmFuY3kudjIu'
        'U2VydmljZUF1dGhvcml6YXRpb25HcmFudEIIukgFkgECCAFSBmdyYW50cw==');

@$core.Deprecated('Use serviceAuthorizationPolicyDescriptor instead')
const ServiceAuthorizationPolicy$json = {
  '1': 'ServiceAuthorizationPolicy',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'schema_version', '3': 2, '4': 1, '5': 5, '10': 'schemaVersion'},
    {'1': 'generation', '3': 3, '4': 1, '5': 3, '10': 'generation'},
    {
      '1': 'applied_generation',
      '3': 4,
      '4': 1,
      '5': 3,
      '10': 'appliedGeneration'
    },
    {
      '1': 'status',
      '3': 5,
      '4': 1,
      '5': 14,
      '6': '.tenancy.v2.AuthorizationPolicyStatus',
      '10': 'status'
    },
    {
      '1': 'grants',
      '3': 6,
      '4': 3,
      '5': 11,
      '6': '.tenancy.v2.ServiceAuthorizationGrant',
      '10': 'grants'
    },
    {'1': 'last_error_code', '3': 7, '4': 1, '5': 9, '10': 'lastErrorCode'},
    {
      '1': 'next_attempt_at',
      '3': 8,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Timestamp',
      '10': 'nextAttemptAt'
    },
    {
      '1': 'synced_at',
      '3': 9,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Timestamp',
      '10': 'syncedAt'
    },
  ],
};

/// Descriptor for `ServiceAuthorizationPolicy`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List serviceAuthorizationPolicyDescriptor = $convert.base64Decode(
    'ChpTZXJ2aWNlQXV0aG9yaXphdGlvblBvbGljeRInCgJpZBgBIAEoCUIXukgUchIyEFswLTlhLX'
    'pfLV17Myw1MH1SAmlkEiUKDnNjaGVtYV92ZXJzaW9uGAIgASgFUg1zY2hlbWFWZXJzaW9uEh4K'
    'CmdlbmVyYXRpb24YAyABKANSCmdlbmVyYXRpb24SLQoSYXBwbGllZF9nZW5lcmF0aW9uGAQgAS'
    'gDUhFhcHBsaWVkR2VuZXJhdGlvbhI9CgZzdGF0dXMYBSABKA4yJS50ZW5hbmN5LnYyLkF1dGhv'
    'cml6YXRpb25Qb2xpY3lTdGF0dXNSBnN0YXR1cxI9CgZncmFudHMYBiADKAsyJS50ZW5hbmN5Ln'
    'YyLlNlcnZpY2VBdXRob3JpemF0aW9uR3JhbnRSBmdyYW50cxImCg9sYXN0X2Vycm9yX2NvZGUY'
    'ByABKAlSDWxhc3RFcnJvckNvZGUSQgoPbmV4dF9hdHRlbXB0X2F0GAggASgLMhouZ29vZ2xlLn'
    'Byb3RvYnVmLlRpbWVzdGFtcFINbmV4dEF0dGVtcHRBdBI3CglzeW5jZWRfYXQYCSABKAsyGi5n'
    'b29nbGUucHJvdG9idWYuVGltZXN0YW1wUghzeW5jZWRBdA==');

@$core.Deprecated('Use serviceAccountDescriptor instead')
const ServiceAccount$json = {
  '1': 'ServiceAccount',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'tenant_id', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'tenantId'},
    {'1': 'partition_id', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
    {'1': 'profile_id', '3': 4, '4': 1, '5': 9, '8': {}, '10': 'profileId'},
    {'1': 'name', '3': 5, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'type', '3': 6, '4': 1, '5': 9, '8': {}, '10': 'type'},
    {
      '1': 'oauth_client',
      '3': 7,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.OAuthClient',
      '10': 'oauthClient'
    },
    {
      '1': 'authorization_policy',
      '3': 8,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.ServiceAuthorizationPolicy',
      '10': 'authorizationPolicy'
    },
    {
      '1': 'public_keys',
      '3': 9,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Struct',
      '10': 'publicKeys'
    },
    {
      '1': 'properties',
      '3': 10,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Struct',
      '10': 'properties'
    },
    {
      '1': 'state',
      '3': 11,
      '4': 1,
      '5': 14,
      '6': '.common.v1.STATE',
      '10': 'state'
    },
    {
      '1': 'created_at',
      '3': 12,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Timestamp',
      '10': 'createdAt'
    },
  ],
};

/// Descriptor for `ServiceAccount`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List serviceAccountDescriptor = $convert.base64Decode(
    'Cg5TZXJ2aWNlQWNjb3VudBInCgJpZBgBIAEoCUIXukgUchIyEFswLTlhLXpfLV17Myw1MH1SAm'
    'lkEjQKCXRlbmFudF9pZBgCIAEoCUIXukgUchIyEFswLTlhLXpfLV17Myw1MH1SCHRlbmFudElk'
    'EjoKDHBhcnRpdGlvbl9pZBgDIAEoCUIXukgUchIyEFswLTlhLXpfLV17Myw1MH1SC3BhcnRpdG'
    'lvbklkEjYKCnByb2ZpbGVfaWQYBCABKAlCF7pIFHISMhBbMC05YS16Xy1dezMsNTB9Uglwcm9m'
    'aWxlSWQSHQoEbmFtZRgFIAEoCUIJukgGcgQQAxhkUgRuYW1lEi0KBHR5cGUYBiABKAlCGbpIFn'
    'IUUghpbnRlcm5hbFIIZXh0ZXJuYWxSBHR5cGUSOgoMb2F1dGhfY2xpZW50GAcgASgLMhcudGVu'
    'YW5jeS52Mi5PQXV0aENsaWVudFILb2F1dGhDbGllbnQSWQoUYXV0aG9yaXphdGlvbl9wb2xpY3'
    'kYCCABKAsyJi50ZW5hbmN5LnYyLlNlcnZpY2VBdXRob3JpemF0aW9uUG9saWN5UhNhdXRob3Jp'
    'emF0aW9uUG9saWN5EjgKC3B1YmxpY19rZXlzGAkgASgLMhcuZ29vZ2xlLnByb3RvYnVmLlN0cn'
    'VjdFIKcHVibGljS2V5cxI3Cgpwcm9wZXJ0aWVzGAogASgLMhcuZ29vZ2xlLnByb3RvYnVmLlN0'
    'cnVjdFIKcHJvcGVydGllcxImCgVzdGF0ZRgLIAEoDjIQLmNvbW1vbi52MS5TVEFURVIFc3RhdG'
    'USOQoKY3JlYXRlZF9hdBgMIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXBSCWNyZWF0'
    'ZWRBdA==');

@$core.Deprecated('Use createOAuthClientRequestDescriptor instead')
const CreateOAuthClientRequest$json = {
  '1': 'CreateOAuthClientRequest',
  '2': [
    {'1': 'partition_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'type', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'type'},
    {
      '1': 'configuration',
      '3': 4,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.OAuthClientConfiguration',
      '8': {},
      '10': 'configuration'
    },
  ],
};

/// Descriptor for `CreateOAuthClientRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createOAuthClientRequestDescriptor = $convert.base64Decode(
    'ChhDcmVhdGVPQXV0aENsaWVudFJlcXVlc3QSOgoMcGFydGl0aW9uX2lkGAEgASgJQhe6SBRyEj'
    'IQWzAtOWEtel8tXXszLDUwfVILcGFydGl0aW9uSWQSHQoEbmFtZRgCIAEoCUIJukgGcgQQAxhk'
    'UgRuYW1lEi8KBHR5cGUYAyABKAlCG7pIGHIWUgZwdWJsaWNSDGNvbmZpZGVudGlhbFIEdHlwZR'
    'JSCg1jb25maWd1cmF0aW9uGAQgASgLMiQudGVuYW5jeS52Mi5PQXV0aENsaWVudENvbmZpZ3Vy'
    'YXRpb25CBrpIA8gBAVINY29uZmlndXJhdGlvbg==');

@$core.Deprecated('Use createOAuthClientResponseDescriptor instead')
const CreateOAuthClientResponse$json = {
  '1': 'CreateOAuthClientResponse',
  '2': [
    {
      '1': 'data',
      '3': 1,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.OAuthClient',
      '10': 'data'
    },
    {'1': 'client_secret', '3': 2, '4': 1, '5': 9, '10': 'clientSecret'},
  ],
};

/// Descriptor for `CreateOAuthClientResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createOAuthClientResponseDescriptor = $convert.base64Decode(
    'ChlDcmVhdGVPQXV0aENsaWVudFJlc3BvbnNlEisKBGRhdGEYASABKAsyFy50ZW5hbmN5LnYyLk'
    '9BdXRoQ2xpZW50UgRkYXRhEiMKDWNsaWVudF9zZWNyZXQYAiABKAlSDGNsaWVudFNlY3JldA==');

@$core.Deprecated('Use getOAuthClientRequestDescriptor instead')
const GetOAuthClientRequest$json = {
  '1': 'GetOAuthClientRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '9': 0, '10': 'id'},
    {
      '1': 'client_id',
      '3': 2,
      '4': 1,
      '5': 9,
      '8': {},
      '9': 0,
      '10': 'clientId'
    },
  ],
  '8': [
    {'1': 'selector', '2': {}},
  ],
};

/// Descriptor for `GetOAuthClientRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getOAuthClientRequestDescriptor = $convert.base64Decode(
    'ChVHZXRPQXV0aENsaWVudFJlcXVlc3QSKQoCaWQYASABKAlCF7pIFHISMhBbMC05YS16Xy1dez'
    'MsNTB9SABSAmlkEigKCWNsaWVudF9pZBgCIAEoCUIJukgGcgQQAxhkSABSCGNsaWVudElkQhEK'
    'CHNlbGVjdG9yEgW6SAIIAQ==');

@$core.Deprecated('Use getOAuthClientResponseDescriptor instead')
const GetOAuthClientResponse$json = {
  '1': 'GetOAuthClientResponse',
  '2': [
    {
      '1': 'data',
      '3': 1,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.OAuthClient',
      '10': 'data'
    },
  ],
};

/// Descriptor for `GetOAuthClientResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getOAuthClientResponseDescriptor =
    $convert.base64Decode(
        'ChZHZXRPQXV0aENsaWVudFJlc3BvbnNlEisKBGRhdGEYASABKAsyFy50ZW5hbmN5LnYyLk9BdX'
        'RoQ2xpZW50UgRkYXRh');

@$core.Deprecated('Use listOAuthClientsRequestDescriptor instead')
const ListOAuthClientsRequest$json = {
  '1': 'ListOAuthClientsRequest',
  '2': [
    {
      '1': 'partition_id',
      '3': 1,
      '4': 1,
      '5': 9,
      '8': {},
      '9': 0,
      '10': 'partitionId'
    },
    {
      '1': 'service_account_id',
      '3': 2,
      '4': 1,
      '5': 9,
      '8': {},
      '9': 0,
      '10': 'serviceAccountId'
    },
    {
      '1': 'cursor',
      '3': 3,
      '4': 1,
      '5': 11,
      '6': '.common.v1.PageCursor',
      '10': 'cursor'
    },
  ],
  '8': [
    {'1': 'owner', '2': {}},
  ],
};

/// Descriptor for `ListOAuthClientsRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listOAuthClientsRequestDescriptor = $convert.base64Decode(
    'ChdMaXN0T0F1dGhDbGllbnRzUmVxdWVzdBI8CgxwYXJ0aXRpb25faWQYASABKAlCF7pIFHISMh'
    'BbMC05YS16Xy1dezMsNTB9SABSC3BhcnRpdGlvbklkEkcKEnNlcnZpY2VfYWNjb3VudF9pZBgC'
    'IAEoCUIXukgUchIyEFswLTlhLXpfLV17Myw1MH1IAFIQc2VydmljZUFjY291bnRJZBItCgZjdX'
    'Jzb3IYAyABKAsyFS5jb21tb24udjEuUGFnZUN1cnNvclIGY3Vyc29yQg4KBW93bmVyEgW6SAII'
    'AQ==');

@$core.Deprecated('Use listOAuthClientsResponseDescriptor instead')
const ListOAuthClientsResponse$json = {
  '1': 'ListOAuthClientsResponse',
  '2': [
    {
      '1': 'data',
      '3': 1,
      '4': 3,
      '5': 11,
      '6': '.tenancy.v2.OAuthClient',
      '10': 'data'
    },
  ],
};

/// Descriptor for `ListOAuthClientsResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listOAuthClientsResponseDescriptor =
    $convert.base64Decode(
        'ChhMaXN0T0F1dGhDbGllbnRzUmVzcG9uc2USKwoEZGF0YRgBIAMoCzIXLnRlbmFuY3kudjIuT0'
        'F1dGhDbGllbnRSBGRhdGE=');

@$core.Deprecated('Use updateOAuthClientRequestDescriptor instead')
const UpdateOAuthClientRequest$json = {
  '1': 'UpdateOAuthClientRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {
      '1': 'configuration',
      '3': 3,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.OAuthClientConfiguration',
      '10': 'configuration'
    },
    {
      '1': 'update_mask',
      '3': 4,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.FieldMask',
      '8': {},
      '10': 'updateMask'
    },
  ],
};

/// Descriptor for `UpdateOAuthClientRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List updateOAuthClientRequestDescriptor = $convert.base64Decode(
    'ChhVcGRhdGVPQXV0aENsaWVudFJlcXVlc3QSJwoCaWQYASABKAlCF7pIFHISMhBbMC05YS16Xy'
    '1dezMsNTB9UgJpZBIgCgRuYW1lGAIgASgJQgy6SAnYAQFyBBADGGRSBG5hbWUSSgoNY29uZmln'
    'dXJhdGlvbhgDIAEoCzIkLnRlbmFuY3kudjIuT0F1dGhDbGllbnRDb25maWd1cmF0aW9uUg1jb2'
    '5maWd1cmF0aW9uEkMKC3VwZGF0ZV9tYXNrGAQgASgLMhouZ29vZ2xlLnByb3RvYnVmLkZpZWxk'
    'TWFza0IGukgDyAEBUgp1cGRhdGVNYXNr');

@$core.Deprecated('Use updateOAuthClientResponseDescriptor instead')
const UpdateOAuthClientResponse$json = {
  '1': 'UpdateOAuthClientResponse',
  '2': [
    {
      '1': 'data',
      '3': 1,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.OAuthClient',
      '10': 'data'
    },
  ],
};

/// Descriptor for `UpdateOAuthClientResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List updateOAuthClientResponseDescriptor =
    $convert.base64Decode(
        'ChlVcGRhdGVPQXV0aENsaWVudFJlc3BvbnNlEisKBGRhdGEYASABKAsyFy50ZW5hbmN5LnYyLk'
        '9BdXRoQ2xpZW50UgRkYXRh');

@$core.Deprecated('Use removeOAuthClientRequestDescriptor instead')
const RemoveOAuthClientRequest$json = {
  '1': 'RemoveOAuthClientRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `RemoveOAuthClientRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removeOAuthClientRequestDescriptor =
    $convert.base64Decode(
        'ChhSZW1vdmVPQXV0aENsaWVudFJlcXVlc3QSJwoCaWQYASABKAlCF7pIFHISMhBbMC05YS16Xy'
        '1dezMsNTB9UgJpZA==');

@$core.Deprecated('Use removeOAuthClientResponseDescriptor instead')
const RemoveOAuthClientResponse$json = {
  '1': 'RemoveOAuthClientResponse',
  '2': [
    {'1': 'succeeded', '3': 1, '4': 1, '5': 8, '10': 'succeeded'},
  ],
};

/// Descriptor for `RemoveOAuthClientResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removeOAuthClientResponseDescriptor =
    $convert.base64Decode(
        'ChlSZW1vdmVPQXV0aENsaWVudFJlc3BvbnNlEhwKCXN1Y2NlZWRlZBgBIAEoCFIJc3VjY2VlZG'
        'Vk');

@$core.Deprecated('Use createServiceAccountRequestDescriptor instead')
const CreateServiceAccountRequest$json = {
  '1': 'CreateServiceAccountRequest',
  '2': [
    {'1': 'partition_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
    {'1': 'profile_id', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'profileId'},
    {'1': 'name', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'type', '3': 4, '4': 1, '5': 9, '8': {}, '10': 'type'},
    {
      '1': 'oauth_client',
      '3': 5,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.OAuthClientConfiguration',
      '8': {},
      '10': 'oauthClient'
    },
    {
      '1': 'authorization_policy',
      '3': 6,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.ServiceAuthorizationPolicyInput',
      '8': {},
      '10': 'authorizationPolicy'
    },
    {
      '1': 'public_keys',
      '3': 7,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Struct',
      '10': 'publicKeys'
    },
    {
      '1': 'properties',
      '3': 8,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Struct',
      '10': 'properties'
    },
  ],
};

/// Descriptor for `CreateServiceAccountRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createServiceAccountRequestDescriptor = $convert.base64Decode(
    'ChtDcmVhdGVTZXJ2aWNlQWNjb3VudFJlcXVlc3QSOgoMcGFydGl0aW9uX2lkGAEgASgJQhe6SB'
    'RyEjIQWzAtOWEtel8tXXszLDUwfVILcGFydGl0aW9uSWQSNgoKcHJvZmlsZV9pZBgCIAEoCUIX'
    'ukgUchIyEFswLTlhLXpfLV17Myw1MH1SCXByb2ZpbGVJZBIdCgRuYW1lGAMgASgJQgm6SAZyBB'
    'ADGGRSBG5hbWUSLQoEdHlwZRgEIAEoCUIZukgWchRSCGludGVybmFsUghleHRlcm5hbFIEdHlw'
    'ZRJPCgxvYXV0aF9jbGllbnQYBSABKAsyJC50ZW5hbmN5LnYyLk9BdXRoQ2xpZW50Q29uZmlndX'
    'JhdGlvbkIGukgDyAEBUgtvYXV0aENsaWVudBJmChRhdXRob3JpemF0aW9uX3BvbGljeRgGIAEo'
    'CzIrLnRlbmFuY3kudjIuU2VydmljZUF1dGhvcml6YXRpb25Qb2xpY3lJbnB1dEIGukgDyAEBUh'
    'NhdXRob3JpemF0aW9uUG9saWN5EjgKC3B1YmxpY19rZXlzGAcgASgLMhcuZ29vZ2xlLnByb3Rv'
    'YnVmLlN0cnVjdFIKcHVibGljS2V5cxI3Cgpwcm9wZXJ0aWVzGAggASgLMhcuZ29vZ2xlLnByb3'
    'RvYnVmLlN0cnVjdFIKcHJvcGVydGllcw==');

@$core.Deprecated('Use createServiceAccountResponseDescriptor instead')
const CreateServiceAccountResponse$json = {
  '1': 'CreateServiceAccountResponse',
  '2': [
    {
      '1': 'data',
      '3': 1,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.ServiceAccount',
      '10': 'data'
    },
    {'1': 'client_secret', '3': 2, '4': 1, '5': 9, '10': 'clientSecret'},
  ],
};

/// Descriptor for `CreateServiceAccountResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createServiceAccountResponseDescriptor =
    $convert.base64Decode(
        'ChxDcmVhdGVTZXJ2aWNlQWNjb3VudFJlc3BvbnNlEi4KBGRhdGEYASABKAsyGi50ZW5hbmN5Ln'
        'YyLlNlcnZpY2VBY2NvdW50UgRkYXRhEiMKDWNsaWVudF9zZWNyZXQYAiABKAlSDGNsaWVudFNl'
        'Y3JldA==');

@$core.Deprecated('Use getServiceAccountRequestDescriptor instead')
const GetServiceAccountRequest$json = {
  '1': 'GetServiceAccountRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '9': 0, '10': 'id'},
    {
      '1': 'client_id',
      '3': 2,
      '4': 1,
      '5': 9,
      '8': {},
      '9': 0,
      '10': 'clientId'
    },
  ],
  '8': [
    {'1': 'selector', '2': {}},
  ],
};

/// Descriptor for `GetServiceAccountRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getServiceAccountRequestDescriptor = $convert.base64Decode(
    'ChhHZXRTZXJ2aWNlQWNjb3VudFJlcXVlc3QSKQoCaWQYASABKAlCF7pIFHISMhBbMC05YS16Xy'
    '1dezMsNTB9SABSAmlkEigKCWNsaWVudF9pZBgCIAEoCUIJukgGcgQQAxhkSABSCGNsaWVudElk'
    'QhEKCHNlbGVjdG9yEgW6SAIIAQ==');

@$core.Deprecated('Use getServiceAccountResponseDescriptor instead')
const GetServiceAccountResponse$json = {
  '1': 'GetServiceAccountResponse',
  '2': [
    {
      '1': 'data',
      '3': 1,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.ServiceAccount',
      '10': 'data'
    },
  ],
};

/// Descriptor for `GetServiceAccountResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getServiceAccountResponseDescriptor =
    $convert.base64Decode(
        'ChlHZXRTZXJ2aWNlQWNjb3VudFJlc3BvbnNlEi4KBGRhdGEYASABKAsyGi50ZW5hbmN5LnYyLl'
        'NlcnZpY2VBY2NvdW50UgRkYXRh');

@$core.Deprecated('Use listServiceAccountsRequestDescriptor instead')
const ListServiceAccountsRequest$json = {
  '1': 'ListServiceAccountsRequest',
  '2': [
    {'1': 'partition_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'partitionId'},
    {
      '1': 'cursor',
      '3': 2,
      '4': 1,
      '5': 11,
      '6': '.common.v1.PageCursor',
      '10': 'cursor'
    },
  ],
};

/// Descriptor for `ListServiceAccountsRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listServiceAccountsRequestDescriptor =
    $convert.base64Decode(
        'ChpMaXN0U2VydmljZUFjY291bnRzUmVxdWVzdBI6CgxwYXJ0aXRpb25faWQYASABKAlCF7pIFH'
        'ISMhBbMC05YS16Xy1dezMsNTB9UgtwYXJ0aXRpb25JZBItCgZjdXJzb3IYAiABKAsyFS5jb21t'
        'b24udjEuUGFnZUN1cnNvclIGY3Vyc29y');

@$core.Deprecated('Use listServiceAccountsResponseDescriptor instead')
const ListServiceAccountsResponse$json = {
  '1': 'ListServiceAccountsResponse',
  '2': [
    {
      '1': 'data',
      '3': 1,
      '4': 3,
      '5': 11,
      '6': '.tenancy.v2.ServiceAccount',
      '10': 'data'
    },
  ],
};

/// Descriptor for `ListServiceAccountsResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listServiceAccountsResponseDescriptor =
    $convert.base64Decode(
        'ChtMaXN0U2VydmljZUFjY291bnRzUmVzcG9uc2USLgoEZGF0YRgBIAMoCzIaLnRlbmFuY3kudj'
        'IuU2VydmljZUFjY291bnRSBGRhdGE=');

@$core.Deprecated('Use updateServiceAccountRequestDescriptor instead')
const UpdateServiceAccountRequest$json = {
  '1': 'UpdateServiceAccountRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
    {'1': 'name', '3': 2, '4': 1, '5': 9, '8': {}, '10': 'name'},
    {'1': 'type', '3': 3, '4': 1, '5': 9, '8': {}, '10': 'type'},
    {
      '1': 'oauth_client',
      '3': 4,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.OAuthClientConfiguration',
      '10': 'oauthClient'
    },
    {
      '1': 'authorization_policy',
      '3': 5,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.ServiceAuthorizationPolicyInput',
      '10': 'authorizationPolicy'
    },
    {
      '1': 'public_keys',
      '3': 6,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Struct',
      '10': 'publicKeys'
    },
    {
      '1': 'properties',
      '3': 7,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Struct',
      '10': 'properties'
    },
    {
      '1': 'update_mask',
      '3': 8,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.FieldMask',
      '8': {},
      '10': 'updateMask'
    },
  ],
};

/// Descriptor for `UpdateServiceAccountRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List updateServiceAccountRequestDescriptor = $convert.base64Decode(
    'ChtVcGRhdGVTZXJ2aWNlQWNjb3VudFJlcXVlc3QSJwoCaWQYASABKAlCF7pIFHISMhBbMC05YS'
    '16Xy1dezMsNTB9UgJpZBIgCgRuYW1lGAIgASgJQgy6SAnYAQFyBBADGGRSBG5hbWUSMAoEdHlw'
    'ZRgDIAEoCUIcukgZ2AEBchRSCGludGVybmFsUghleHRlcm5hbFIEdHlwZRJHCgxvYXV0aF9jbG'
    'llbnQYBCABKAsyJC50ZW5hbmN5LnYyLk9BdXRoQ2xpZW50Q29uZmlndXJhdGlvblILb2F1dGhD'
    'bGllbnQSXgoUYXV0aG9yaXphdGlvbl9wb2xpY3kYBSABKAsyKy50ZW5hbmN5LnYyLlNlcnZpY2'
    'VBdXRob3JpemF0aW9uUG9saWN5SW5wdXRSE2F1dGhvcml6YXRpb25Qb2xpY3kSOAoLcHVibGlj'
    'X2tleXMYBiABKAsyFy5nb29nbGUucHJvdG9idWYuU3RydWN0UgpwdWJsaWNLZXlzEjcKCnByb3'
    'BlcnRpZXMYByABKAsyFy5nb29nbGUucHJvdG9idWYuU3RydWN0Ugpwcm9wZXJ0aWVzEkMKC3Vw'
    'ZGF0ZV9tYXNrGAggASgLMhouZ29vZ2xlLnByb3RvYnVmLkZpZWxkTWFza0IGukgDyAEBUgp1cG'
    'RhdGVNYXNr');

@$core.Deprecated('Use updateServiceAccountResponseDescriptor instead')
const UpdateServiceAccountResponse$json = {
  '1': 'UpdateServiceAccountResponse',
  '2': [
    {
      '1': 'data',
      '3': 1,
      '4': 1,
      '5': 11,
      '6': '.tenancy.v2.ServiceAccount',
      '10': 'data'
    },
  ],
};

/// Descriptor for `UpdateServiceAccountResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List updateServiceAccountResponseDescriptor =
    $convert.base64Decode(
        'ChxVcGRhdGVTZXJ2aWNlQWNjb3VudFJlc3BvbnNlEi4KBGRhdGEYASABKAsyGi50ZW5hbmN5Ln'
        'YyLlNlcnZpY2VBY2NvdW50UgRkYXRh');

@$core.Deprecated('Use removeServiceAccountRequestDescriptor instead')
const RemoveServiceAccountRequest$json = {
  '1': 'RemoveServiceAccountRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `RemoveServiceAccountRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removeServiceAccountRequestDescriptor =
    $convert.base64Decode(
        'ChtSZW1vdmVTZXJ2aWNlQWNjb3VudFJlcXVlc3QSJwoCaWQYASABKAlCF7pIFHISMhBbMC05YS'
        '16Xy1dezMsNTB9UgJpZA==');

@$core.Deprecated('Use removeServiceAccountResponseDescriptor instead')
const RemoveServiceAccountResponse$json = {
  '1': 'RemoveServiceAccountResponse',
  '2': [
    {'1': 'succeeded', '3': 1, '4': 1, '5': 8, '10': 'succeeded'},
  ],
};

/// Descriptor for `RemoveServiceAccountResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removeServiceAccountResponseDescriptor =
    $convert.base64Decode(
        'ChxSZW1vdmVTZXJ2aWNlQWNjb3VudFJlc3BvbnNlEhwKCXN1Y2NlZWRlZBgBIAEoCFIJc3VjY2'
        'VlZGVk');

@$core.Deprecated(
    'Use reconcileServiceAccountAuthorizationRequestDescriptor instead')
const ReconcileServiceAccountAuthorizationRequest$json = {
  '1': 'ReconcileServiceAccountAuthorizationRequest',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'id'},
  ],
};

/// Descriptor for `ReconcileServiceAccountAuthorizationRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List
    reconcileServiceAccountAuthorizationRequestDescriptor =
    $convert.base64Decode(
        'CitSZWNvbmNpbGVTZXJ2aWNlQWNjb3VudEF1dGhvcml6YXRpb25SZXF1ZXN0EicKAmlkGAEgAS'
        'gJQhe6SBRyEjIQWzAtOWEtel8tXXszLDUwfVICaWQ=');

@$core.Deprecated(
    'Use reconcileServiceAccountAuthorizationResponseDescriptor instead')
const ReconcileServiceAccountAuthorizationResponse$json = {
  '1': 'ReconcileServiceAccountAuthorizationResponse',
  '2': [
    {'1': 'generation', '3': 1, '4': 1, '5': 3, '10': 'generation'},
  ],
};

/// Descriptor for `ReconcileServiceAccountAuthorizationResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List
    reconcileServiceAccountAuthorizationResponseDescriptor =
    $convert.base64Decode(
        'CixSZWNvbmNpbGVTZXJ2aWNlQWNjb3VudEF1dGhvcml6YXRpb25SZXNwb25zZRIeCgpnZW5lcm'
        'F0aW9uGAEgASgDUgpnZW5lcmF0aW9u');

const $core.Map<$core.String, $core.dynamic> AuthContractServiceBase$json = {
  '1': 'AuthContractService',
  '2': [
    {
      '1': 'CreateOAuthClient',
      '2': '.tenancy.v2.CreateOAuthClientRequest',
      '3': '.tenancy.v2.CreateOAuthClientResponse',
      '4': {}
    },
    {
      '1': 'GetOAuthClient',
      '2': '.tenancy.v2.GetOAuthClientRequest',
      '3': '.tenancy.v2.GetOAuthClientResponse',
      '4': {'34': 1},
    },
    {
      '1': 'ListOAuthClients',
      '2': '.tenancy.v2.ListOAuthClientsRequest',
      '3': '.tenancy.v2.ListOAuthClientsResponse',
      '4': {'34': 1},
    },
    {
      '1': 'UpdateOAuthClient',
      '2': '.tenancy.v2.UpdateOAuthClientRequest',
      '3': '.tenancy.v2.UpdateOAuthClientResponse',
      '4': {}
    },
    {
      '1': 'RemoveOAuthClient',
      '2': '.tenancy.v2.RemoveOAuthClientRequest',
      '3': '.tenancy.v2.RemoveOAuthClientResponse',
      '4': {}
    },
    {
      '1': 'CreateServiceAccount',
      '2': '.tenancy.v2.CreateServiceAccountRequest',
      '3': '.tenancy.v2.CreateServiceAccountResponse',
      '4': {}
    },
    {
      '1': 'GetServiceAccount',
      '2': '.tenancy.v2.GetServiceAccountRequest',
      '3': '.tenancy.v2.GetServiceAccountResponse',
      '4': {'34': 1},
    },
    {
      '1': 'ListServiceAccounts',
      '2': '.tenancy.v2.ListServiceAccountsRequest',
      '3': '.tenancy.v2.ListServiceAccountsResponse',
      '4': {'34': 1},
    },
    {
      '1': 'UpdateServiceAccount',
      '2': '.tenancy.v2.UpdateServiceAccountRequest',
      '3': '.tenancy.v2.UpdateServiceAccountResponse',
      '4': {}
    },
    {
      '1': 'RemoveServiceAccount',
      '2': '.tenancy.v2.RemoveServiceAccountRequest',
      '3': '.tenancy.v2.RemoveServiceAccountResponse',
      '4': {}
    },
    {
      '1': 'ReconcileServiceAccountAuthorization',
      '2': '.tenancy.v2.ReconcileServiceAccountAuthorizationRequest',
      '3': '.tenancy.v2.ReconcileServiceAccountAuthorizationResponse',
      '4': {}
    },
  ],
  '3': {},
};

@$core.Deprecated('Use authContractServiceDescriptor instead')
const $core.Map<$core.String, $core.Map<$core.String, $core.dynamic>>
    AuthContractServiceBase$messageJson = {
  '.tenancy.v2.CreateOAuthClientRequest': CreateOAuthClientRequest$json,
  '.tenancy.v2.OAuthClientConfiguration': OAuthClientConfiguration$json,
  '.google.protobuf.Struct': $6.Struct$json,
  '.google.protobuf.Struct.FieldsEntry': $6.Struct_FieldsEntry$json,
  '.google.protobuf.Value': $6.Value$json,
  '.google.protobuf.ListValue': $6.ListValue$json,
  '.tenancy.v2.CreateOAuthClientResponse': CreateOAuthClientResponse$json,
  '.tenancy.v2.OAuthClient': OAuthClient$json,
  '.google.protobuf.Timestamp': $2.Timestamp$json,
  '.tenancy.v2.GetOAuthClientRequest': GetOAuthClientRequest$json,
  '.tenancy.v2.GetOAuthClientResponse': GetOAuthClientResponse$json,
  '.tenancy.v2.ListOAuthClientsRequest': ListOAuthClientsRequest$json,
  '.common.v1.PageCursor': $7.PageCursor$json,
  '.tenancy.v2.ListOAuthClientsResponse': ListOAuthClientsResponse$json,
  '.tenancy.v2.UpdateOAuthClientRequest': UpdateOAuthClientRequest$json,
  '.google.protobuf.FieldMask': $1.FieldMask$json,
  '.tenancy.v2.UpdateOAuthClientResponse': UpdateOAuthClientResponse$json,
  '.tenancy.v2.RemoveOAuthClientRequest': RemoveOAuthClientRequest$json,
  '.tenancy.v2.RemoveOAuthClientResponse': RemoveOAuthClientResponse$json,
  '.tenancy.v2.CreateServiceAccountRequest': CreateServiceAccountRequest$json,
  '.tenancy.v2.ServiceAuthorizationPolicyInput':
      ServiceAuthorizationPolicyInput$json,
  '.tenancy.v2.ServiceAuthorizationGrant': ServiceAuthorizationGrant$json,
  '.tenancy.v2.CreateServiceAccountResponse': CreateServiceAccountResponse$json,
  '.tenancy.v2.ServiceAccount': ServiceAccount$json,
  '.tenancy.v2.ServiceAuthorizationPolicy': ServiceAuthorizationPolicy$json,
  '.tenancy.v2.GetServiceAccountRequest': GetServiceAccountRequest$json,
  '.tenancy.v2.GetServiceAccountResponse': GetServiceAccountResponse$json,
  '.tenancy.v2.ListServiceAccountsRequest': ListServiceAccountsRequest$json,
  '.tenancy.v2.ListServiceAccountsResponse': ListServiceAccountsResponse$json,
  '.tenancy.v2.UpdateServiceAccountRequest': UpdateServiceAccountRequest$json,
  '.tenancy.v2.UpdateServiceAccountResponse': UpdateServiceAccountResponse$json,
  '.tenancy.v2.RemoveServiceAccountRequest': RemoveServiceAccountRequest$json,
  '.tenancy.v2.RemoveServiceAccountResponse': RemoveServiceAccountResponse$json,
  '.tenancy.v2.ReconcileServiceAccountAuthorizationRequest':
      ReconcileServiceAccountAuthorizationRequest$json,
  '.tenancy.v2.ReconcileServiceAccountAuthorizationResponse':
      ReconcileServiceAccountAuthorizationResponse$json,
};

/// Descriptor for `AuthContractService`. Decode as a `google.protobuf.ServiceDescriptorProto`.
final $typed_data.Uint8List authContractServiceDescriptor = $convert.base64Decode(
    'ChNBdXRoQ29udHJhY3RTZXJ2aWNlEnUKEUNyZWF0ZU9BdXRoQ2xpZW50EiQudGVuYW5jeS52Mi'
    '5DcmVhdGVPQXV0aENsaWVudFJlcXVlc3QaJS50ZW5hbmN5LnYyLkNyZWF0ZU9BdXRoQ2xpZW50'
    'UmVzcG9uc2UiE4K1GA8KDWNsaWVudF9tYW5hZ2USbQoOR2V0T0F1dGhDbGllbnQSIS50ZW5hbm'
    'N5LnYyLkdldE9BdXRoQ2xpZW50UmVxdWVzdBoiLnRlbmFuY3kudjIuR2V0T0F1dGhDbGllbnRS'
    'ZXNwb25zZSIUkAIBgrUYDQoLY2xpZW50X3ZpZXcScwoQTGlzdE9BdXRoQ2xpZW50cxIjLnRlbm'
    'FuY3kudjIuTGlzdE9BdXRoQ2xpZW50c1JlcXVlc3QaJC50ZW5hbmN5LnYyLkxpc3RPQXV0aENs'
    'aWVudHNSZXNwb25zZSIUkAIBgrUYDQoLY2xpZW50X3ZpZXcSdQoRVXBkYXRlT0F1dGhDbGllbn'
    'QSJC50ZW5hbmN5LnYyLlVwZGF0ZU9BdXRoQ2xpZW50UmVxdWVzdBolLnRlbmFuY3kudjIuVXBk'
    'YXRlT0F1dGhDbGllbnRSZXNwb25zZSITgrUYDwoNY2xpZW50X21hbmFnZRJ1ChFSZW1vdmVPQX'
    'V0aENsaWVudBIkLnRlbmFuY3kudjIuUmVtb3ZlT0F1dGhDbGllbnRSZXF1ZXN0GiUudGVuYW5j'
    'eS52Mi5SZW1vdmVPQXV0aENsaWVudFJlc3BvbnNlIhOCtRgPCg1jbGllbnRfbWFuYWdlEocBCh'
    'RDcmVhdGVTZXJ2aWNlQWNjb3VudBInLnRlbmFuY3kudjIuQ3JlYXRlU2VydmljZUFjY291bnRS'
    'ZXF1ZXN0GigudGVuYW5jeS52Mi5DcmVhdGVTZXJ2aWNlQWNjb3VudFJlc3BvbnNlIhyCtRgYCh'
    'ZzZXJ2aWNlX2FjY291bnRfbWFuYWdlEn8KEUdldFNlcnZpY2VBY2NvdW50EiQudGVuYW5jeS52'
    'Mi5HZXRTZXJ2aWNlQWNjb3VudFJlcXVlc3QaJS50ZW5hbmN5LnYyLkdldFNlcnZpY2VBY2NvdW'
    '50UmVzcG9uc2UiHZACAYK1GBYKFHNlcnZpY2VfYWNjb3VudF92aWV3EoUBChNMaXN0U2Vydmlj'
    'ZUFjY291bnRzEiYudGVuYW5jeS52Mi5MaXN0U2VydmljZUFjY291bnRzUmVxdWVzdBonLnRlbm'
    'FuY3kudjIuTGlzdFNlcnZpY2VBY2NvdW50c1Jlc3BvbnNlIh2QAgGCtRgWChRzZXJ2aWNlX2Fj'
    'Y291bnRfdmlldxKHAQoUVXBkYXRlU2VydmljZUFjY291bnQSJy50ZW5hbmN5LnYyLlVwZGF0ZV'
    'NlcnZpY2VBY2NvdW50UmVxdWVzdBooLnRlbmFuY3kudjIuVXBkYXRlU2VydmljZUFjY291bnRS'
    'ZXNwb25zZSIcgrUYGAoWc2VydmljZV9hY2NvdW50X21hbmFnZRKHAQoUUmVtb3ZlU2VydmljZU'
    'FjY291bnQSJy50ZW5hbmN5LnYyLlJlbW92ZVNlcnZpY2VBY2NvdW50UmVxdWVzdBooLnRlbmFu'
    'Y3kudjIuUmVtb3ZlU2VydmljZUFjY291bnRSZXNwb25zZSIcgrUYGAoWc2VydmljZV9hY2NvdW'
    '50X21hbmFnZRK3AQokUmVjb25jaWxlU2VydmljZUFjY291bnRBdXRob3JpemF0aW9uEjcudGVu'
    'YW5jeS52Mi5SZWNvbmNpbGVTZXJ2aWNlQWNjb3VudEF1dGhvcml6YXRpb25SZXF1ZXN0GjgudG'
    'VuYW5jeS52Mi5SZWNvbmNpbGVTZXJ2aWNlQWNjb3VudEF1dGhvcml6YXRpb25SZXNwb25zZSIc'
    'grUYGAoWc2VydmljZV9hY2NvdW50X21hbmFnZRpfgrUYWwoPc2VydmljZV90ZW5hbmN5EhRzZX'
    'J2aWNlX2FjY291bnRfdmlldxIWc2VydmljZV9hY2NvdW50X21hbmFnZRILY2xpZW50X3ZpZXcS'
    'DWNsaWVudF9tYW5hZ2U=');
