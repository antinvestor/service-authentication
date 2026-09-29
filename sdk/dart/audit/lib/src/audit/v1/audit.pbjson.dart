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

@$core.Deprecated('Use auditPhaseDescriptor instead')
const AuditPhase$json = {
  '1': 'AuditPhase',
  '2': [
    {'1': 'AUDIT_PHASE_UNSPECIFIED', '2': 0},
    {'1': 'AUDIT_PHASE_REQUESTED', '2': 1},
    {'1': 'AUDIT_PHASE_COMPLETED', '2': 2},
    {'1': 'AUDIT_PHASE_FAILED', '2': 3},
  ],
};

/// Descriptor for `AuditPhase`. Decode as a `google.protobuf.EnumDescriptorProto`.
final $typed_data.Uint8List auditPhaseDescriptor = $convert.base64Decode(
    'CgpBdWRpdFBoYXNlEhsKF0FVRElUX1BIQVNFX1VOU1BFQ0lGSUVEEAASGQoVQVVESVRfUEhBU0'
    'VfUkVRVUVTVEVEEAESGQoVQVVESVRfUEhBU0VfQ09NUExFVEVEEAISFgoSQVVESVRfUEhBU0Vf'
    'RkFJTEVEEAM=');

@$core.Deprecated('Use intakeStateDescriptor instead')
const IntakeState$json = {
  '1': 'IntakeState',
  '2': [
    {'1': 'INTAKE_STATE_UNSPECIFIED', '2': 0},
    {'1': 'INTAKE_STATE_ACCEPTED', '2': 1},
    {'1': 'INTAKE_STATE_COMMITTED', '2': 2},
    {'1': 'INTAKE_STATE_FAILED', '2': 3},
  ],
};

/// Descriptor for `IntakeState`. Decode as a `google.protobuf.EnumDescriptorProto`.
final $typed_data.Uint8List intakeStateDescriptor = $convert.base64Decode(
    'CgtJbnRha2VTdGF0ZRIcChhJTlRBS0VfU1RBVEVfVU5TUEVDSUZJRUQQABIZChVJTlRBS0VfU1'
    'RBVEVfQUNDRVBURUQQARIaChZJTlRBS0VfU1RBVEVfQ09NTUlUVEVEEAISFwoTSU5UQUtFX1NU'
    'QVRFX0ZBSUxFRBAD');

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
    {'1': 'seq', '3': 19, '4': 1, '5': 3, '10': 'seq'},
    {'1': 'key_id', '3': 20, '4': 1, '5': 9, '10': 'keyId'},
    {'1': 'canon_version', '3': 21, '4': 1, '5': 5, '10': 'canonVersion'},
    {'1': 'entry_id', '3': 22, '4': 1, '5': 9, '10': 'entryId'},
    {'1': 'actor_service_account_id', '3': 23, '4': 1, '5': 9, '10': 'actorServiceAccountId'},
    {'1': 'on_behalf_of', '3': 24, '4': 1, '5': 9, '10': 'onBehalfOf'},
    {'1': 'occurred_at', '3': 25, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'occurredAt'},
    {'1': 'received_at', '3': 26, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'receivedAt'},
    {'1': 'correlation_id', '3': 27, '4': 1, '5': 9, '10': 'correlationId'},
    {'1': 'event_id', '3': 28, '4': 1, '5': 9, '10': 'eventId'},
    {'1': 'intent_id', '3': 29, '4': 1, '5': 9, '10': 'intentId'},
    {'1': 'instance_id', '3': 30, '4': 1, '5': 9, '10': 'instanceId'},
    {'1': 'payload_hash', '3': 31, '4': 1, '5': 9, '10': 'payloadHash'},
    {'1': 'authorization_hash', '3': 32, '4': 1, '5': 9, '10': 'authorizationHash'},
    {'1': 'policy_hash', '3': 33, '4': 1, '5': 9, '10': 'policyHash'},
    {'1': 'device_key_id', '3': 34, '4': 1, '5': 9, '10': 'deviceKeyId'},
    {'1': 'state_from', '3': 35, '4': 1, '5': 9, '10': 'stateFrom'},
    {'1': 'state_to', '3': 36, '4': 1, '5': 9, '10': 'stateTo'},
    {'1': 'resource_version', '3': 37, '4': 1, '5': 3, '10': 'resourceVersion'},
    {'1': 'relations', '3': 38, '4': 3, '5': 11, '6': '.audit.v1.AuditRelation', '10': 'relations'},
    {'1': 'manifest_version', '3': 39, '4': 1, '5': 5, '10': 'manifestVersion'},
    {'1': 'unmanifested', '3': 40, '4': 1, '5': 8, '10': 'unmanifested'},
    {'1': 'state', '3': 41, '4': 1, '5': 14, '6': '.audit.v1.IntakeState', '10': 'state'},
    {'1': 'phase', '3': 42, '4': 1, '5': 14, '6': '.audit.v1.AuditPhase', '10': 'phase'},
    {'1': 'outcome_of_entry_id', '3': 43, '4': 1, '5': 9, '10': 'outcomeOfEntryId'},
    {'1': 'audit_class', '3': 44, '4': 1, '5': 9, '10': 'auditClass'},
    {'1': 'written_during_degradation', '3': 45, '4': 1, '5': 8, '10': 'writtenDuringDegradation'},
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
    'NpZ25hdHVyZRIQCgNzZXEYEyABKANSA3NlcRIVCgZrZXlfaWQYFCABKAlSBWtleUlkEiMKDWNh'
    'bm9uX3ZlcnNpb24YFSABKAVSDGNhbm9uVmVyc2lvbhIZCghlbnRyeV9pZBgWIAEoCVIHZW50cn'
    'lJZBI3ChhhY3Rvcl9zZXJ2aWNlX2FjY291bnRfaWQYFyABKAlSFWFjdG9yU2VydmljZUFjY291'
    'bnRJZBIgCgxvbl9iZWhhbGZfb2YYGCABKAlSCm9uQmVoYWxmT2YSOwoLb2NjdXJyZWRfYXQYGS'
    'ABKAsyGi5nb29nbGUucHJvdG9idWYuVGltZXN0YW1wUgpvY2N1cnJlZEF0EjsKC3JlY2VpdmVk'
    'X2F0GBogASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcFIKcmVjZWl2ZWRBdBIlCg5jb3'
    'JyZWxhdGlvbl9pZBgbIAEoCVINY29ycmVsYXRpb25JZBIZCghldmVudF9pZBgcIAEoCVIHZXZl'
    'bnRJZBIbCglpbnRlbnRfaWQYHSABKAlSCGludGVudElkEh8KC2luc3RhbmNlX2lkGB4gASgJUg'
    'ppbnN0YW5jZUlkEiEKDHBheWxvYWRfaGFzaBgfIAEoCVILcGF5bG9hZEhhc2gSLQoSYXV0aG9y'
    'aXphdGlvbl9oYXNoGCAgASgJUhFhdXRob3JpemF0aW9uSGFzaBIfCgtwb2xpY3lfaGFzaBghIA'
    'EoCVIKcG9saWN5SGFzaBIiCg1kZXZpY2Vfa2V5X2lkGCIgASgJUgtkZXZpY2VLZXlJZBIdCgpz'
    'dGF0ZV9mcm9tGCMgASgJUglzdGF0ZUZyb20SGQoIc3RhdGVfdG8YJCABKAlSB3N0YXRlVG8SKQ'
    'oQcmVzb3VyY2VfdmVyc2lvbhglIAEoA1IPcmVzb3VyY2VWZXJzaW9uEjUKCXJlbGF0aW9ucxgm'
    'IAMoCzIXLmF1ZGl0LnYxLkF1ZGl0UmVsYXRpb25SCXJlbGF0aW9ucxIpChBtYW5pZmVzdF92ZX'
    'JzaW9uGCcgASgFUg9tYW5pZmVzdFZlcnNpb24SIgoMdW5tYW5pZmVzdGVkGCggASgIUgx1bm1h'
    'bmlmZXN0ZWQSKwoFc3RhdGUYKSABKA4yFS5hdWRpdC52MS5JbnRha2VTdGF0ZVIFc3RhdGUSKg'
    'oFcGhhc2UYKiABKA4yFC5hdWRpdC52MS5BdWRpdFBoYXNlUgVwaGFzZRItChNvdXRjb21lX29m'
    'X2VudHJ5X2lkGCsgASgJUhBvdXRjb21lT2ZFbnRyeUlkEh8KC2F1ZGl0X2NsYXNzGCwgASgJUg'
    'phdWRpdENsYXNzEjwKGndyaXR0ZW5fZHVyaW5nX2RlZ3JhZGF0aW9uGC0gASgIUhh3cml0dGVu'
    'RHVyaW5nRGVncmFkYXRpb24=');

@$core.Deprecated('Use auditRelationDescriptor instead')
const AuditRelation$json = {
  '1': 'AuditRelation',
  '2': [
    {'1': 'parent_type', '3': 1, '4': 1, '5': 9, '10': 'parentType'},
    {'1': 'parent_id', '3': 2, '4': 1, '5': 9, '10': 'parentId'},
    {'1': 'child_type', '3': 3, '4': 1, '5': 9, '10': 'childType'},
    {'1': 'child_id', '3': 4, '4': 1, '5': 9, '10': 'childId'},
    {'1': 'action', '3': 5, '4': 1, '5': 9, '10': 'action'},
  ],
};

/// Descriptor for `AuditRelation`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List auditRelationDescriptor = $convert.base64Decode(
    'Cg1BdWRpdFJlbGF0aW9uEh8KC3BhcmVudF90eXBlGAEgASgJUgpwYXJlbnRUeXBlEhsKCXBhcm'
    'VudF9pZBgCIAEoCVIIcGFyZW50SWQSHQoKY2hpbGRfdHlwZRgDIAEoCVIJY2hpbGRUeXBlEhkK'
    'CGNoaWxkX2lkGAQgASgJUgdjaGlsZElkEhYKBmFjdGlvbhgFIAEoCVIGYWN0aW9u');

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
    {'1': 'entry_id', '3': 12, '4': 1, '5': 9, '8': {}, '10': 'entryId'},
    {'1': 'on_behalf_of', '3': 13, '4': 1, '5': 9, '8': {}, '10': 'onBehalfOf'},
    {'1': 'occurred_at', '3': 14, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'occurredAt'},
    {'1': 'correlation_id', '3': 15, '4': 1, '5': 9, '8': {}, '10': 'correlationId'},
    {'1': 'event_id', '3': 16, '4': 1, '5': 9, '8': {}, '10': 'eventId'},
    {'1': 'intent_id', '3': 17, '4': 1, '5': 9, '8': {}, '10': 'intentId'},
    {'1': 'instance_id', '3': 18, '4': 1, '5': 9, '8': {}, '10': 'instanceId'},
    {'1': 'payload_hash', '3': 19, '4': 1, '5': 9, '8': {}, '10': 'payloadHash'},
    {'1': 'authorization_hash', '3': 20, '4': 1, '5': 9, '8': {}, '10': 'authorizationHash'},
    {'1': 'policy_hash', '3': 21, '4': 1, '5': 9, '8': {}, '10': 'policyHash'},
    {'1': 'device_key_id', '3': 22, '4': 1, '5': 9, '8': {}, '10': 'deviceKeyId'},
    {'1': 'state_from', '3': 23, '4': 1, '5': 9, '8': {}, '10': 'stateFrom'},
    {'1': 'state_to', '3': 24, '4': 1, '5': 9, '8': {}, '10': 'stateTo'},
    {'1': 'resource_version', '3': 25, '4': 1, '5': 3, '10': 'resourceVersion'},
    {'1': 'relations', '3': 26, '4': 3, '5': 11, '6': '.audit.v1.AuditRelation', '8': {}, '10': 'relations'},
    {'1': 'phase', '3': 27, '4': 1, '5': 14, '6': '.audit.v1.AuditPhase', '10': 'phase'},
    {'1': 'outcome_of_entry_id', '3': 28, '4': 1, '5': 9, '8': {}, '10': 'outcomeOfEntryId'},
    {'1': 'audit_class', '3': 29, '4': 1, '5': 9, '8': {}, '10': 'auditClass'},
    {'1': 'written_during_degradation', '3': 30, '4': 1, '5': 8, '10': 'writtenDuringDegradation'},
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
    'RQcm9maWxlSWQSGQoIdHJhY2VfaWQYCyABKAlSB3RyYWNlSWQSIgoIZW50cnlfaWQYDCABKAlC'
    'B7pIBHICGEBSB2VudHJ5SWQSKQoMb25fYmVoYWxmX29mGA0gASgJQge6SARyAhgyUgpvbkJlaG'
    'FsZk9mEjsKC29jY3VycmVkX2F0GA4gASgLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcFIK'
    'b2NjdXJyZWRBdBIuCg5jb3JyZWxhdGlvbl9pZBgPIAEoCUIHukgEcgIYQFINY29ycmVsYXRpb2'
    '5JZBIiCghldmVudF9pZBgQIAEoCUIHukgEcgIYQFIHZXZlbnRJZBIkCglpbnRlbnRfaWQYESAB'
    'KAlCB7pIBHICGEBSCGludGVudElkEigKC2luc3RhbmNlX2lkGBIgASgJQge6SARyAhhAUgppbn'
    'N0YW5jZUlkEjsKDHBheWxvYWRfaGFzaBgTIAEoCUIYukgVchMyEV4oWzAtOWEtZl17NjR9KT8k'
    'UgtwYXlsb2FkSGFzaBJHChJhdXRob3JpemF0aW9uX2hhc2gYFCABKAlCGLpIFXITMhFeKFswLT'
    'lhLWZdezY0fSk/JFIRYXV0aG9yaXphdGlvbkhhc2gSOQoLcG9saWN5X2hhc2gYFSABKAlCGLpI'
    'FXITMhFeKFswLTlhLWZdezY0fSk/JFIKcG9saWN5SGFzaBIrCg1kZXZpY2Vfa2V5X2lkGBYgAS'
    'gJQge6SARyAhhAUgtkZXZpY2VLZXlJZBImCgpzdGF0ZV9mcm9tGBcgASgJQge6SARyAhhAUglz'
    'dGF0ZUZyb20SIgoIc3RhdGVfdG8YGCABKAlCB7pIBHICGEBSB3N0YXRlVG8SKQoQcmVzb3VyY2'
    'VfdmVyc2lvbhgZIAEoA1IPcmVzb3VyY2VWZXJzaW9uEj8KCXJlbGF0aW9ucxgaIAMoCzIXLmF1'
    'ZGl0LnYxLkF1ZGl0UmVsYXRpb25CCLpIBZIBAhAyUglyZWxhdGlvbnMSKgoFcGhhc2UYGyABKA'
    '4yFC5hdWRpdC52MS5BdWRpdFBoYXNlUgVwaGFzZRI2ChNvdXRjb21lX29mX2VudHJ5X2lkGBwg'
    'ASgJQge6SARyAhhAUhBvdXRjb21lT2ZFbnRyeUlkEigKC2F1ZGl0X2NsYXNzGB0gASgJQge6SA'
    'RyAhggUgphdWRpdENsYXNzEjwKGndyaXR0ZW5fZHVyaW5nX2RlZ3JhZGF0aW9uGB4gASgIUhh3'
    'cml0dGVuRHVyaW5nRGVncmFkYXRpb24=');

@$core.Deprecated('Use createAuditEntryResponseDescriptor instead')
const CreateAuditEntryResponse$json = {
  '1': 'CreateAuditEntryResponse',
  '2': [
    {
      '1': 'data',
      '3': 1,
      '4': 1,
      '5': 11,
      '6': '.audit.v1.AuditEntryObject',
      '8': {'3': true},
      '10': 'data',
    },
    {'1': 'intake_id', '3': 2, '4': 1, '5': 9, '10': 'intakeId'},
    {'1': 'entry_id', '3': 3, '4': 1, '5': 9, '10': 'entryId'},
    {'1': 'state', '3': 4, '4': 1, '5': 14, '6': '.audit.v1.IntakeState', '10': 'state'},
  ],
};

/// Descriptor for `CreateAuditEntryResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List createAuditEntryResponseDescriptor = $convert.base64Decode(
    'ChhDcmVhdGVBdWRpdEVudHJ5UmVzcG9uc2USMgoEZGF0YRgBIAEoCzIaLmF1ZGl0LnYxLkF1ZG'
    'l0RW50cnlPYmplY3RCAhgBUgRkYXRhEhsKCWludGFrZV9pZBgCIAEoCVIIaW50YWtlSWQSGQoI'
    'ZW50cnlfaWQYAyABKAlSB2VudHJ5SWQSKwoFc3RhdGUYBCABKA4yFS5hdWRpdC52MS5JbnRha2'
    'VTdGF0ZVIFc3RhdGU=');

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
    {
      '1': 'data',
      '3': 1,
      '4': 3,
      '5': 11,
      '6': '.audit.v1.AuditEntryObject',
      '8': {'3': true},
      '10': 'data',
    },
    {'1': 'receipts', '3': 2, '4': 3, '5': 11, '6': '.audit.v1.CreateAuditEntryResponse', '10': 'receipts'},
  ],
};

/// Descriptor for `BatchCreateAuditEntriesResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List batchCreateAuditEntriesResponseDescriptor = $convert.base64Decode(
    'Ch9CYXRjaENyZWF0ZUF1ZGl0RW50cmllc1Jlc3BvbnNlEjIKBGRhdGEYASADKAsyGi5hdWRpdC'
    '52MS5BdWRpdEVudHJ5T2JqZWN0QgIYAVIEZGF0YRI+CghyZWNlaXB0cxgCIAMoCzIiLmF1ZGl0'
    'LnYxLkNyZWF0ZUF1ZGl0RW50cnlSZXNwb25zZVIIcmVjZWlwdHM=');

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
    {'1': 'intent_id', '3': 12, '4': 1, '5': 9, '10': 'intentId'},
    {'1': 'event_id', '3': 13, '4': 1, '5': 9, '10': 'eventId'},
    {'1': 'correlation_id', '3': 14, '4': 1, '5': 9, '10': 'correlationId'},
    {'1': 'on_behalf_of', '3': 15, '4': 1, '5': 9, '10': 'onBehalfOf'},
    {'1': 'seq_from', '3': 16, '4': 1, '5': 3, '10': 'seqFrom'},
    {'1': 'seq_to', '3': 17, '4': 1, '5': 3, '10': 'seqTo'},
    {'1': 'phase', '3': 18, '4': 1, '5': 14, '6': '.audit.v1.AuditPhase', '10': 'phase'},
    {'1': 'without_outcome', '3': 19, '4': 1, '5': 8, '10': 'withoutOutcome'},
    {'1': 'written_during_degradation_only', '3': 20, '4': 1, '5': 8, '10': 'writtenDuringDegradationOnly'},
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
    'RwYWdlGAsgASgJUgRwYWdlEhsKCWludGVudF9pZBgMIAEoCVIIaW50ZW50SWQSGQoIZXZlbnRf'
    'aWQYDSABKAlSB2V2ZW50SWQSJQoOY29ycmVsYXRpb25faWQYDiABKAlSDWNvcnJlbGF0aW9uSW'
    'QSIAoMb25fYmVoYWxmX29mGA8gASgJUgpvbkJlaGFsZk9mEhkKCHNlcV9mcm9tGBAgASgDUgdz'
    'ZXFGcm9tEhUKBnNlcV90bxgRIAEoA1IFc2VxVG8SKgoFcGhhc2UYEiABKA4yFC5hdWRpdC52MS'
    '5BdWRpdFBoYXNlUgVwaGFzZRInCg93aXRob3V0X291dGNvbWUYEyABKAhSDndpdGhvdXRPdXRj'
    'b21lEkUKH3dyaXR0ZW5fZHVyaW5nX2RlZ3JhZGF0aW9uX29ubHkYFCABKAhSHHdyaXR0ZW5EdX'
    'JpbmdEZWdyYWRhdGlvbk9ubHk=');

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
    {'1': 'start_seq', '3': 3, '4': 1, '5': 3, '10': 'startSeq'},
    {'1': 'end_seq', '3': 4, '4': 1, '5': 3, '10': 'endSeq'},
  ],
};

/// Descriptor for `VerifyIntegrityRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List verifyIntegrityRequestDescriptor = $convert.base64Decode(
    'ChZWZXJpZnlJbnRlZ3JpdHlSZXF1ZXN0EjkKCnN0YXJ0X2RhdGUYASABKAsyGi5nb29nbGUucH'
    'JvdG9idWYuVGltZXN0YW1wUglzdGFydERhdGUSNQoIZW5kX2RhdGUYAiABKAsyGi5nb29nbGUu'
    'cHJvdG9idWYuVGltZXN0YW1wUgdlbmREYXRlEhsKCXN0YXJ0X3NlcRgDIAEoA1IIc3RhcnRTZX'
    'ESFwoHZW5kX3NlcRgEIAEoA1IGZW5kU2Vx');

@$core.Deprecated('Use verifyIntegrityResponseDescriptor instead')
const VerifyIntegrityResponse$json = {
  '1': 'VerifyIntegrityResponse',
  '2': [
    {'1': 'valid', '3': 1, '4': 1, '5': 8, '10': 'valid'},
    {'1': 'entries_verified', '3': 2, '4': 1, '5': 3, '10': 'entriesVerified'},
    {'1': 'first_invalid_entry_id', '3': 3, '4': 1, '5': 9, '10': 'firstInvalidEntryId'},
    {'1': 'message', '3': 4, '4': 1, '5': 9, '10': 'message'},
    {'1': 'start_checkpoint_seq', '3': 5, '4': 1, '5': 3, '10': 'startCheckpointSeq'},
    {'1': 'end_seq', '3': 6, '4': 1, '5': 3, '10': 'endSeq'},
    {'1': 'end_hash', '3': 7, '4': 1, '5': 9, '10': 'endHash'},
    {'1': 'key_ids_used', '3': 8, '4': 3, '5': 9, '10': 'keyIdsUsed'},
    {'1': 'partial', '3': 9, '4': 1, '5': 8, '10': 'partial'},
    {'1': 'first_invalid_seq', '3': 10, '4': 1, '5': 3, '10': 'firstInvalidSeq'},
  ],
};

/// Descriptor for `VerifyIntegrityResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List verifyIntegrityResponseDescriptor = $convert.base64Decode(
    'ChdWZXJpZnlJbnRlZ3JpdHlSZXNwb25zZRIUCgV2YWxpZBgBIAEoCFIFdmFsaWQSKQoQZW50cm'
    'llc192ZXJpZmllZBgCIAEoA1IPZW50cmllc1ZlcmlmaWVkEjMKFmZpcnN0X2ludmFsaWRfZW50'
    'cnlfaWQYAyABKAlSE2ZpcnN0SW52YWxpZEVudHJ5SWQSGAoHbWVzc2FnZRgEIAEoCVIHbWVzc2'
    'FnZRIwChRzdGFydF9jaGVja3BvaW50X3NlcRgFIAEoA1ISc3RhcnRDaGVja3BvaW50U2VxEhcK'
    'B2VuZF9zZXEYBiABKANSBmVuZFNlcRIZCghlbmRfaGFzaBgHIAEoCVIHZW5kSGFzaBIgCgxrZX'
    'lfaWRzX3VzZWQYCCADKAlSCmtleUlkc1VzZWQSGAoHcGFydGlhbBgJIAEoCFIHcGFydGlhbBIq'
    'ChFmaXJzdF9pbnZhbGlkX3NlcRgKIAEoA1IPZmlyc3RJbnZhbGlkU2Vx');

@$core.Deprecated('Use auditCheckpointDescriptor instead')
const AuditCheckpoint$json = {
  '1': 'AuditCheckpoint',
  '2': [
    {'1': 'tenant_id', '3': 1, '4': 1, '5': 9, '10': 'tenantId'},
    {'1': 'seq', '3': 2, '4': 1, '5': 3, '10': 'seq'},
    {'1': 'entry_hash', '3': 3, '4': 1, '5': 9, '10': 'entryHash'},
    {'1': 'key_id', '3': 4, '4': 1, '5': 9, '10': 'keyId'},
    {'1': 'signature', '3': 5, '4': 1, '5': 9, '10': 'signature'},
    {'1': 'created_at', '3': 6, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'createdAt'},
  ],
};

/// Descriptor for `AuditCheckpoint`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List auditCheckpointDescriptor = $convert.base64Decode(
    'Cg9BdWRpdENoZWNrcG9pbnQSGwoJdGVuYW50X2lkGAEgASgJUgh0ZW5hbnRJZBIQCgNzZXEYAi'
    'ABKANSA3NlcRIdCgplbnRyeV9oYXNoGAMgASgJUgllbnRyeUhhc2gSFQoGa2V5X2lkGAQgASgJ'
    'UgVrZXlJZBIcCglzaWduYXR1cmUYBSABKAlSCXNpZ25hdHVyZRI5CgpjcmVhdGVkX2F0GAYgAS'
    'gLMhouZ29vZ2xlLnByb3RvYnVmLlRpbWVzdGFtcFIJY3JlYXRlZEF0');

@$core.Deprecated('Use signingKeyDescriptor instead')
const SigningKey$json = {
  '1': 'SigningKey',
  '2': [
    {'1': 'key_id', '3': 1, '4': 1, '5': 9, '10': 'keyId'},
    {'1': 'algorithm', '3': 2, '4': 1, '5': 9, '10': 'algorithm'},
    {'1': 'public_key', '3': 3, '4': 1, '5': 9, '10': 'publicKey'},
    {'1': 'valid_from', '3': 4, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'validFrom'},
    {'1': 'retired_at', '3': 5, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'retiredAt'},
  ],
};

/// Descriptor for `SigningKey`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List signingKeyDescriptor = $convert.base64Decode(
    'CgpTaWduaW5nS2V5EhUKBmtleV9pZBgBIAEoCVIFa2V5SWQSHAoJYWxnb3JpdGhtGAIgASgJUg'
    'lhbGdvcml0aG0SHQoKcHVibGljX2tleRgDIAEoCVIJcHVibGljS2V5EjkKCnZhbGlkX2Zyb20Y'
    'BCABKAsyGi5nb29nbGUucHJvdG9idWYuVGltZXN0YW1wUgl2YWxpZEZyb20SOQoKcmV0aXJlZF'
    '9hdBgFIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXBSCXJldGlyZWRBdA==');

@$core.Deprecated('Use listCheckpointsRequestDescriptor instead')
const ListCheckpointsRequest$json = {
  '1': 'ListCheckpointsRequest',
  '2': [
    {'1': 'seq_from', '3': 1, '4': 1, '5': 3, '10': 'seqFrom'},
    {'1': 'seq_to', '3': 2, '4': 1, '5': 3, '10': 'seqTo'},
    {'1': 'count', '3': 3, '4': 1, '5': 5, '10': 'count'},
  ],
};

/// Descriptor for `ListCheckpointsRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listCheckpointsRequestDescriptor = $convert.base64Decode(
    'ChZMaXN0Q2hlY2twb2ludHNSZXF1ZXN0EhkKCHNlcV9mcm9tGAEgASgDUgdzZXFGcm9tEhUKBn'
    'NlcV90bxgCIAEoA1IFc2VxVG8SFAoFY291bnQYAyABKAVSBWNvdW50');

@$core.Deprecated('Use listCheckpointsResponseDescriptor instead')
const ListCheckpointsResponse$json = {
  '1': 'ListCheckpointsResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.audit.v1.AuditCheckpoint', '10': 'data'},
  ],
};

/// Descriptor for `ListCheckpointsResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listCheckpointsResponseDescriptor = $convert.base64Decode(
    'ChdMaXN0Q2hlY2twb2ludHNSZXNwb25zZRItCgRkYXRhGAEgAygLMhkuYXVkaXQudjEuQXVkaX'
    'RDaGVja3BvaW50UgRkYXRh');

@$core.Deprecated('Use getSigningKeysRequestDescriptor instead')
const GetSigningKeysRequest$json = {
  '1': 'GetSigningKeysRequest',
};

/// Descriptor for `GetSigningKeysRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getSigningKeysRequestDescriptor = $convert.base64Decode(
    'ChVHZXRTaWduaW5nS2V5c1JlcXVlc3Q=');

@$core.Deprecated('Use getSigningKeysResponseDescriptor instead')
const GetSigningKeysResponse$json = {
  '1': 'GetSigningKeysResponse',
  '2': [
    {'1': 'data', '3': 1, '4': 3, '5': 11, '6': '.audit.v1.SigningKey', '10': 'data'},
  ],
};

/// Descriptor for `GetSigningKeysResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getSigningKeysResponseDescriptor = $convert.base64Decode(
    'ChZHZXRTaWduaW5nS2V5c1Jlc3BvbnNlEigKBGRhdGEYASADKAsyFC5hdWRpdC52MS5TaWduaW'
    '5nS2V5UgRkYXRh');

@$core.Deprecated('Use exportAuditEntriesRequestDescriptor instead')
const ExportAuditEntriesRequest$json = {
  '1': 'ExportAuditEntriesRequest',
  '2': [
    {'1': 'start_seq', '3': 1, '4': 1, '5': 3, '8': {}, '10': 'startSeq'},
    {'1': 'end_seq', '3': 2, '4': 1, '5': 3, '8': {}, '10': 'endSeq'},
  ],
};

/// Descriptor for `ExportAuditEntriesRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List exportAuditEntriesRequestDescriptor = $convert.base64Decode(
    'ChlFeHBvcnRBdWRpdEVudHJpZXNSZXF1ZXN0EiQKCXN0YXJ0X3NlcRgBIAEoA0IHukgEIgIoAF'
    'IIc3RhcnRTZXESIAoHZW5kX3NlcRgCIAEoA0IHukgEIgIoAFIGZW5kU2Vx');

@$core.Deprecated('Use exportAuditEntriesResponseDescriptor instead')
const ExportAuditEntriesResponse$json = {
  '1': 'ExportAuditEntriesResponse',
  '2': [
    {'1': 'header', '3': 1, '4': 1, '5': 11, '6': '.audit.v1.ExportAuditEntriesResponse.Header', '9': 0, '10': 'header'},
    {'1': 'entry', '3': 2, '4': 1, '5': 11, '6': '.audit.v1.AuditEntryObject', '9': 0, '10': 'entry'},
  ],
  '3': [ExportAuditEntriesResponse_Header$json],
  '8': [
    {'1': 'payload'},
  ],
};

@$core.Deprecated('Use exportAuditEntriesResponseDescriptor instead')
const ExportAuditEntriesResponse_Header$json = {
  '1': 'Header',
  '2': [
    {'1': 'tenant_id', '3': 1, '4': 1, '5': 9, '10': 'tenantId'},
    {'1': 'start_seq', '3': 2, '4': 1, '5': 3, '10': 'startSeq'},
    {'1': 'end_seq', '3': 3, '4': 1, '5': 3, '10': 'endSeq'},
    {'1': 'start_checkpoint', '3': 4, '4': 1, '5': 11, '6': '.audit.v1.AuditCheckpoint', '10': 'startCheckpoint'},
    {'1': 'end_checkpoint', '3': 5, '4': 1, '5': 11, '6': '.audit.v1.AuditCheckpoint', '10': 'endCheckpoint'},
    {'1': 'keys', '3': 6, '4': 3, '5': 11, '6': '.audit.v1.SigningKey', '10': 'keys'},
  ],
};

/// Descriptor for `ExportAuditEntriesResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List exportAuditEntriesResponseDescriptor = $convert.base64Decode(
    'ChpFeHBvcnRBdWRpdEVudHJpZXNSZXNwb25zZRJFCgZoZWFkZXIYASABKAsyKy5hdWRpdC52MS'
    '5FeHBvcnRBdWRpdEVudHJpZXNSZXNwb25zZS5IZWFkZXJIAFIGaGVhZGVyEjIKBWVudHJ5GAIg'
    'ASgLMhouYXVkaXQudjEuQXVkaXRFbnRyeU9iamVjdEgAUgVlbnRyeRqNAgoGSGVhZGVyEhsKCX'
    'RlbmFudF9pZBgBIAEoCVIIdGVuYW50SWQSGwoJc3RhcnRfc2VxGAIgASgDUghzdGFydFNlcRIX'
    'CgdlbmRfc2VxGAMgASgDUgZlbmRTZXESRAoQc3RhcnRfY2hlY2twb2ludBgEIAEoCzIZLmF1ZG'
    'l0LnYxLkF1ZGl0Q2hlY2twb2ludFIPc3RhcnRDaGVja3BvaW50EkAKDmVuZF9jaGVja3BvaW50'
    'GAUgASgLMhkuYXVkaXQudjEuQXVkaXRDaGVja3BvaW50Ug1lbmRDaGVja3BvaW50EigKBGtleX'
    'MYBiADKAsyFC5hdWRpdC52MS5TaWduaW5nS2V5UgRrZXlzQgkKB3BheWxvYWQ=');

@$core.Deprecated('Use auditManifestDescriptor instead')
const AuditManifest$json = {
  '1': 'AuditManifest',
  '2': [
    {'1': 'service', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'service'},
    {'1': 'actions', '3': 2, '4': 3, '5': 9, '8': {}, '10': 'actions'},
    {'1': 'resource_types', '3': 3, '4': 3, '5': 9, '8': {}, '10': 'resourceTypes'},
    {'1': 'open_vocabulary', '3': 4, '4': 1, '5': 8, '10': 'openVocabulary'},
    {'1': 'allow_backdating', '3': 5, '4': 1, '5': 8, '10': 'allowBackdating'},
    {'1': 'extra_forbidden_keys', '3': 6, '4': 3, '5': 9, '8': {}, '10': 'extraForbiddenKeys'},
  ],
};

/// Descriptor for `AuditManifest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List auditManifestDescriptor = $convert.base64Decode(
    'Cg1BdWRpdE1hbmlmZXN0EiMKB3NlcnZpY2UYASABKAlCCbpIBnIEEAEYZFIHc2VydmljZRIjCg'
    'dhY3Rpb25zGAIgAygJQgm6SAaSAQMQ9ANSB2FjdGlvbnMSMAoOcmVzb3VyY2VfdHlwZXMYAyAD'
    'KAlCCbpIBpIBAxD0A1INcmVzb3VyY2VUeXBlcxInCg9vcGVuX3ZvY2FidWxhcnkYBCABKAhSDm'
    '9wZW5Wb2NhYnVsYXJ5EikKEGFsbG93X2JhY2tkYXRpbmcYBSABKAhSD2FsbG93QmFja2RhdGlu'
    'ZxI6ChRleHRyYV9mb3JiaWRkZW5fa2V5cxgGIAMoCUIIukgFkgECEGRSEmV4dHJhRm9yYmlkZG'
    'VuS2V5cw==');

@$core.Deprecated('Use registerAuditManifestRequestDescriptor instead')
const RegisterAuditManifestRequest$json = {
  '1': 'RegisterAuditManifestRequest',
  '2': [
    {'1': 'manifest', '3': 1, '4': 1, '5': 11, '6': '.audit.v1.AuditManifest', '8': {}, '10': 'manifest'},
  ],
};

/// Descriptor for `RegisterAuditManifestRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List registerAuditManifestRequestDescriptor = $convert.base64Decode(
    'ChxSZWdpc3RlckF1ZGl0TWFuaWZlc3RSZXF1ZXN0EjsKCG1hbmlmZXN0GAEgASgLMhcuYXVkaX'
    'QudjEuQXVkaXRNYW5pZmVzdEIGukgDyAEBUghtYW5pZmVzdA==');

@$core.Deprecated('Use registerAuditManifestResponseDescriptor instead')
const RegisterAuditManifestResponse$json = {
  '1': 'RegisterAuditManifestResponse',
  '2': [
    {'1': 'service', '3': 1, '4': 1, '5': 9, '10': 'service'},
    {'1': 'version', '3': 2, '4': 1, '5': 5, '10': 'version'},
    {'1': 'unchanged', '3': 3, '4': 1, '5': 8, '10': 'unchanged'},
  ],
};

/// Descriptor for `RegisterAuditManifestResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List registerAuditManifestResponseDescriptor = $convert.base64Decode(
    'Ch1SZWdpc3RlckF1ZGl0TWFuaWZlc3RSZXNwb25zZRIYCgdzZXJ2aWNlGAEgASgJUgdzZXJ2aW'
    'NlEhgKB3ZlcnNpb24YAiABKAVSB3ZlcnNpb24SHAoJdW5jaGFuZ2VkGAMgASgIUgl1bmNoYW5n'
    'ZWQ=');

@$core.Deprecated('Use getAuditManifestRequestDescriptor instead')
const GetAuditManifestRequest$json = {
  '1': 'GetAuditManifestRequest',
  '2': [
    {'1': 'service', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'service'},
  ],
};

/// Descriptor for `GetAuditManifestRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getAuditManifestRequestDescriptor = $convert.base64Decode(
    'ChdHZXRBdWRpdE1hbmlmZXN0UmVxdWVzdBIhCgdzZXJ2aWNlGAEgASgJQge6SARyAhABUgdzZX'
    'J2aWNl');

@$core.Deprecated('Use getAuditManifestResponseDescriptor instead')
const GetAuditManifestResponse$json = {
  '1': 'GetAuditManifestResponse',
  '2': [
    {'1': 'manifest', '3': 1, '4': 1, '5': 11, '6': '.audit.v1.AuditManifest', '10': 'manifest'},
    {'1': 'version', '3': 2, '4': 1, '5': 5, '10': 'version'},
    {'1': 'created_at', '3': 3, '4': 1, '5': 11, '6': '.google.protobuf.Timestamp', '10': 'createdAt'},
  ],
};

/// Descriptor for `GetAuditManifestResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getAuditManifestResponseDescriptor = $convert.base64Decode(
    'ChhHZXRBdWRpdE1hbmlmZXN0UmVzcG9uc2USMwoIbWFuaWZlc3QYASABKAsyFy5hdWRpdC52MS'
    '5BdWRpdE1hbmlmZXN0UghtYW5pZmVzdBIYCgd2ZXJzaW9uGAIgASgFUgd2ZXJzaW9uEjkKCmNy'
    'ZWF0ZWRfYXQYAyABKAsyGi5nb29nbGUucHJvdG9idWYuVGltZXN0YW1wUgljcmVhdGVkQXQ=');

@$core.Deprecated('Use requeueIntakeRequestDescriptor instead')
const RequeueIntakeRequest$json = {
  '1': 'RequeueIntakeRequest',
  '2': [
    {'1': 'intake_ids', '3': 1, '4': 3, '5': 9, '8': {}, '10': 'intakeIds'},
  ],
};

/// Descriptor for `RequeueIntakeRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List requeueIntakeRequestDescriptor = $convert.base64Decode(
    'ChRSZXF1ZXVlSW50YWtlUmVxdWVzdBIqCgppbnRha2VfaWRzGAEgAygJQgu6SAiSAQUIARD0A1'
    'IJaW50YWtlSWRz');

@$core.Deprecated('Use requeueIntakeResponseDescriptor instead')
const RequeueIntakeResponse$json = {
  '1': 'RequeueIntakeResponse',
  '2': [
    {'1': 'requeued', '3': 1, '4': 1, '5': 3, '10': 'requeued'},
  ],
};

/// Descriptor for `RequeueIntakeResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List requeueIntakeResponseDescriptor = $convert.base64Decode(
    'ChVSZXF1ZXVlSW50YWtlUmVzcG9uc2USGgoIcmVxdWV1ZWQYASABKANSCHJlcXVldWVk');

@$core.Deprecated('Use retireSigningKeyRequestDescriptor instead')
const RetireSigningKeyRequest$json = {
  '1': 'RetireSigningKeyRequest',
  '2': [
    {'1': 'key_id', '3': 1, '4': 1, '5': 9, '8': {}, '10': 'keyId'},
  ],
};

/// Descriptor for `RetireSigningKeyRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List retireSigningKeyRequestDescriptor = $convert.base64Decode(
    'ChdSZXRpcmVTaWduaW5nS2V5UmVxdWVzdBIeCgZrZXlfaWQYASABKAlCB7pIBHICEAFSBWtleU'
    'lk');

@$core.Deprecated('Use retireSigningKeyResponseDescriptor instead')
const RetireSigningKeyResponse$json = {
  '1': 'RetireSigningKeyResponse',
  '2': [
    {'1': 'key', '3': 1, '4': 1, '5': 11, '6': '.audit.v1.SigningKey', '10': 'key'},
  ],
};

/// Descriptor for `RetireSigningKeyResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List retireSigningKeyResponseDescriptor = $convert.base64Decode(
    'ChhSZXRpcmVTaWduaW5nS2V5UmVzcG9uc2USJgoDa2V5GAEgASgLMhQuYXVkaXQudjEuU2lnbm'
    'luZ0tleVIDa2V5');

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
    {
      '1': 'ExportAuditEntries',
      '2': '.audit.v1.ExportAuditEntriesRequest',
      '3': '.audit.v1.ExportAuditEntriesResponse',
      '4': {'34': 1},
      '6': true,
    },
    {
      '1': 'ListCheckpoints',
      '2': '.audit.v1.ListCheckpointsRequest',
      '3': '.audit.v1.ListCheckpointsResponse',
      '4': {'34': 1},
    },
    {
      '1': 'GetSigningKeys',
      '2': '.audit.v1.GetSigningKeysRequest',
      '3': '.audit.v1.GetSigningKeysResponse',
      '4': {'34': 1},
    },
    {'1': 'RegisterAuditManifest', '2': '.audit.v1.RegisterAuditManifestRequest', '3': '.audit.v1.RegisterAuditManifestResponse', '4': {}},
    {
      '1': 'GetAuditManifest',
      '2': '.audit.v1.GetAuditManifestRequest',
      '3': '.audit.v1.GetAuditManifestResponse',
      '4': {'34': 1},
    },
    {'1': 'RequeueIntake', '2': '.audit.v1.RequeueIntakeRequest', '3': '.audit.v1.RequeueIntakeResponse', '4': {}},
    {'1': 'RetireSigningKey', '2': '.audit.v1.RetireSigningKeyRequest', '3': '.audit.v1.RetireSigningKeyResponse', '4': {}},
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
  '.google.protobuf.Timestamp': $2.Timestamp$json,
  '.audit.v1.AuditRelation': AuditRelation$json,
  '.audit.v1.CreateAuditEntryResponse': CreateAuditEntryResponse$json,
  '.audit.v1.AuditEntryObject': AuditEntryObject$json,
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
  '.audit.v1.ExportAuditEntriesRequest': ExportAuditEntriesRequest$json,
  '.audit.v1.ExportAuditEntriesResponse': ExportAuditEntriesResponse$json,
  '.audit.v1.ExportAuditEntriesResponse.Header': ExportAuditEntriesResponse_Header$json,
  '.audit.v1.AuditCheckpoint': AuditCheckpoint$json,
  '.audit.v1.SigningKey': SigningKey$json,
  '.audit.v1.ListCheckpointsRequest': ListCheckpointsRequest$json,
  '.audit.v1.ListCheckpointsResponse': ListCheckpointsResponse$json,
  '.audit.v1.GetSigningKeysRequest': GetSigningKeysRequest$json,
  '.audit.v1.GetSigningKeysResponse': GetSigningKeysResponse$json,
  '.audit.v1.RegisterAuditManifestRequest': RegisterAuditManifestRequest$json,
  '.audit.v1.AuditManifest': AuditManifest$json,
  '.audit.v1.RegisterAuditManifestResponse': RegisterAuditManifestResponse$json,
  '.audit.v1.GetAuditManifestRequest': GetAuditManifestRequest$json,
  '.audit.v1.GetAuditManifestResponse': GetAuditManifestResponse$json,
  '.audit.v1.RequeueIntakeRequest': RequeueIntakeRequest$json,
  '.audit.v1.RequeueIntakeResponse': RequeueIntakeResponse$json,
  '.audit.v1.RetireSigningKeyRequest': RetireSigningKeyRequest$json,
  '.audit.v1.RetireSigningKeyResponse': RetireSigningKeyResponse$json,
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
    'F1ZGl0RW50cmllc4K1GAwKCmF1ZGl0X3ZpZXcwARLbAgoPVmVyaWZ5SW50ZWdyaXR5EiAuYXVk'
    'aXQudjEuVmVyaWZ5SW50ZWdyaXR5UmVxdWVzdBohLmF1ZGl0LnYxLlZlcmlmeUludGVncml0eV'
    'Jlc3BvbnNlIoICkAIBukfpAQoFQXVkaXQSFlZlcmlmeSBhdWRpdCBpbnRlZ3JpdHkatgFWZXJp'
    'ZmllcyB0aGUgaGFzaCBjaGFpbiBhbmQgZGlnaXRhbCBzaWduYXR1cmVzIG9mIGF1ZGl0IGVudH'
    'JpZXMgb3ZlciBhIHNlcXVlbmNlIHJhbmdlLCBzdGFydGluZyBmcm9tIHRoZSBuZWFyZXN0IGNo'
    'ZWNrcG9pbnQuIFJldHVybnMgdGhlIGZpcnN0IGludmFsaWQgZW50cnkgaWYgdGFtcGVyaW5nIG'
    'lzIGRldGVjdGVkLioPdmVyaWZ5SW50ZWdyaXR5grUYDgoMYXVkaXRfdmVyaWZ5Eo8CChJFeHBv'
    'cnRBdWRpdEVudHJpZXMSIy5hdWRpdC52MS5FeHBvcnRBdWRpdEVudHJpZXNSZXF1ZXN0GiQuYX'
    'VkaXQudjEuRXhwb3J0QXVkaXRFbnRyaWVzUmVzcG9uc2UiqwGQAgG6R5IBCgVBdWRpdBIURXhw'
    'b3J0IGF1ZGl0IGVudHJpZXMaX1N0cmVhbXMgYSB2ZXJpZmlhYmxlIGJ1bmRsZTogYm91bmRpbm'
    'cgY2hlY2twb2ludHMsIHB1YmxpYyBrZXlzLCB0aGVuIGVudHJpZXMgaW4gc2VxdWVuY2Ugb3Jk'
    'ZXIuKhJleHBvcnRBdWRpdEVudHJpZXOCtRgOCgxhdWRpdF9leHBvcnQwARLcAQoPTGlzdENoZW'
    'NrcG9pbnRzEiAuYXVkaXQudjEuTGlzdENoZWNrcG9pbnRzUmVxdWVzdBohLmF1ZGl0LnYxLkxp'
    'c3RDaGVja3BvaW50c1Jlc3BvbnNlIoMBkAIBukdtCgVBdWRpdBIQTGlzdCBjaGVja3BvaW50cx'
    'pBTGlzdHMgc2lnbmVkIGNoYWluIGNoZWNrcG9pbnRzLCB0aGUgdW5pdCBleHRlcm5hbCBzeXN0'
    'ZW1zIGFuY2hvci4qD2xpc3RDaGVja3BvaW50c4K1GAwKCmF1ZGl0X3ZpZXcS+AEKDkdldFNpZ2'
    '5pbmdLZXlzEh8uYXVkaXQudjEuR2V0U2lnbmluZ0tleXNSZXF1ZXN0GiAuYXVkaXQudjEuR2V0'
    'U2lnbmluZ0tleXNSZXNwb25zZSKiAZACAbpHiwEKBUF1ZGl0EhBHZXQgc2lnbmluZyBrZXlzGm'
    'BSZXR1cm5zIHB1YmxpYyBzaWduaW5nIGtleXMgd2l0aCB2YWxpZGl0eSB3aW5kb3dzIHNvIGFu'
    'eSBlbnRyeSBjYW4gYmUgdmVyaWZpZWQgdW5kZXIgaXRzIGtleV9pZC4qDmdldFNpZ25pbmdLZX'
    'lzgrUYDAoKYXVkaXRfdmlldxKjAgoVUmVnaXN0ZXJBdWRpdE1hbmlmZXN0EiYuYXVkaXQudjEu'
    'UmVnaXN0ZXJBdWRpdE1hbmlmZXN0UmVxdWVzdBonLmF1ZGl0LnYxLlJlZ2lzdGVyQXVkaXRNYW'
    '5pZmVzdFJlc3BvbnNlIrgBukeZAQoFQXVkaXQSF1JlZ2lzdGVyIGF1ZGl0IG1hbmlmZXN0GmBS'
    'ZWdpc3RlcnMgYSB2ZXJzaW9uZWQgdm9jYWJ1bGFyeSBtYW5pZmVzdCBmb3IgdGhlIGNhbGxpbm'
    'cgc2VydmljZS4gVW5jaGFuZ2VkIGNvbnRlbnQgaXMgYSBuby1vcC4qFXJlZ2lzdGVyQXVkaXRN'
    'YW5pZmVzdIK1GBcKFWF1ZGl0X21hbmlmZXN0X21hbmFnZRLcAQoQR2V0QXVkaXRNYW5pZmVzdB'
    'IhLmF1ZGl0LnYxLkdldEF1ZGl0TWFuaWZlc3RSZXF1ZXN0GiIuYXVkaXQudjEuR2V0QXVkaXRN'
    'YW5pZmVzdFJlc3BvbnNlIoABkAIBukdqCgVBdWRpdBISR2V0IGF1ZGl0IG1hbmlmZXN0GjtSZX'
    'R1cm5zIHRoZSBsYXRlc3QgcmVnaXN0ZXJlZCBhdWRpdCBtYW5pZmVzdCBmb3IgYSBzZXJ2aWNl'
    'LioQZ2V0QXVkaXRNYW5pZmVzdIK1GAwKCmF1ZGl0X3ZpZXcShQIKDVJlcXVldWVJbnRha2USHi'
    '5hdWRpdC52MS5SZXF1ZXVlSW50YWtlUmVxdWVzdBofLmF1ZGl0LnYxLlJlcXVldWVJbnRha2VS'
    'ZXNwb25zZSKyAbpHmwEKBUF1ZGl0EhVSZXF1ZXVlIGZhaWxlZCBpbnRha2UabE1vdmVzIGZhaW'
    'xlZCBpbnRha2Ugcm93cyBiYWNrIHRvIGFjY2VwdGVkIHNvIHRoZSBjaGFpbiB3cml0ZXIgcmV0'
    'cmllcyB0aGVtLiBUaGUgb3BlcmF0aW9uIGlzIGl0c2VsZiBhdWRpdGVkLioNcmVxdWV1ZUludG'
    'FrZYK1GA8KDWF1ZGl0X29wZXJhdGUSiQIKEFJldGlyZVNpZ25pbmdLZXkSIS5hdWRpdC52MS5S'
    'ZXRpcmVTaWduaW5nS2V5UmVxdWVzdBoiLmF1ZGl0LnYxLlJldGlyZVNpZ25pbmdLZXlSZXNwb2'
    '5zZSKtAbpHlgEKBUF1ZGl0EhJSZXRpcmUgc2lnbmluZyBrZXkaZ1JldGlyZXMgYSBzaWduaW5n'
    'IGtleS4gRXhpc3RpbmcgZW50cmllcyBzdGF5IHZlcmlmaWFibGU7IHRoZSB3cml0ZXIgcmVmdX'
    'NlcyB0byBzaWduIHdpdGggYSByZXRpcmVkIGtleS4qEHJldGlyZVNpZ25pbmdLZXmCtRgPCg1h'
    'dWRpdF9vcGVyYXRlGuoCgrUY5QIKDXNlcnZpY2VfYXVkaXQSCmF1ZGl0X3ZpZXcSDGF1ZGl0X2'
    'NyZWF0ZRIMYXVkaXRfdmVyaWZ5EgxhdWRpdF9leHBvcnQSFWF1ZGl0X21hbmlmZXN0X21hbmFn'
    'ZRIQYXVkaXRfY3JlYXRlX2FueRINYXVkaXRfb3BlcmF0ZRpHCAESCmF1ZGl0X3ZpZXcSDGF1ZG'
    'l0X2NyZWF0ZRIMYXVkaXRfdmVyaWZ5EgxhdWRpdF9leHBvcnQSDWF1ZGl0X29wZXJhdGUaKggC'
    'EgphdWRpdF92aWV3EgxhdWRpdF92ZXJpZnkSDGF1ZGl0X2V4cG9ydBoOCAMSCmF1ZGl0X3ZpZX'
    'caDggEEgphdWRpdF92aWV3Gg4IBRIKYXVkaXRfdmlldxpBCAYSCmF1ZGl0X3ZpZXcSDGF1ZGl0'
    'X2NyZWF0ZRIMYXVkaXRfdmVyaWZ5EhVhdWRpdF9tYW5pZmVzdF9tYW5hZ2U=');

