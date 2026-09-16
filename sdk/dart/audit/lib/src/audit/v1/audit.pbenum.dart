//
//  Generated code. Do not modify.
//  source: audit/v1/audit.proto
//
// @dart = 2.12

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_final_fields
// ignore_for_file: unnecessary_import, unnecessary_this, unused_import

import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;

/// AuditPhase links a human command to its outcome (GFOS §10.4, K11).
/// A producer records REQUESTED before its own transaction and a linked
/// COMPLETED or FAILED afterwards, so a REQUESTED entry with no outcome
/// reads as "asked, not done". The service never infers completion.
class AuditPhase extends $pb.ProtobufEnum {
  static const AuditPhase AUDIT_PHASE_UNSPECIFIED = AuditPhase._(0, _omitEnumNames ? '' : 'AUDIT_PHASE_UNSPECIFIED');
  static const AuditPhase AUDIT_PHASE_REQUESTED = AuditPhase._(1, _omitEnumNames ? '' : 'AUDIT_PHASE_REQUESTED');
  static const AuditPhase AUDIT_PHASE_COMPLETED = AuditPhase._(2, _omitEnumNames ? '' : 'AUDIT_PHASE_COMPLETED');
  static const AuditPhase AUDIT_PHASE_FAILED = AuditPhase._(3, _omitEnumNames ? '' : 'AUDIT_PHASE_FAILED');

  static const $core.List<AuditPhase> values = <AuditPhase> [
    AUDIT_PHASE_UNSPECIFIED,
    AUDIT_PHASE_REQUESTED,
    AUDIT_PHASE_COMPLETED,
    AUDIT_PHASE_FAILED,
  ];

  static final $core.Map<$core.int, AuditPhase> _byValue = $pb.ProtobufEnum.initByValue(values);
  static AuditPhase? valueOf($core.int value) => _byValue[value];

  const AuditPhase._($core.int v, $core.String n) : super(v, n);
}

/// IntakeState is the lifecycle of an accepted entry.
class IntakeState extends $pb.ProtobufEnum {
  static const IntakeState INTAKE_STATE_UNSPECIFIED = IntakeState._(0, _omitEnumNames ? '' : 'INTAKE_STATE_UNSPECIFIED');
  static const IntakeState INTAKE_STATE_ACCEPTED = IntakeState._(1, _omitEnumNames ? '' : 'INTAKE_STATE_ACCEPTED');
  static const IntakeState INTAKE_STATE_COMMITTED = IntakeState._(2, _omitEnumNames ? '' : 'INTAKE_STATE_COMMITTED');
  static const IntakeState INTAKE_STATE_FAILED = IntakeState._(3, _omitEnumNames ? '' : 'INTAKE_STATE_FAILED');

  static const $core.List<IntakeState> values = <IntakeState> [
    INTAKE_STATE_UNSPECIFIED,
    INTAKE_STATE_ACCEPTED,
    INTAKE_STATE_COMMITTED,
    INTAKE_STATE_FAILED,
  ];

  static final $core.Map<$core.int, IntakeState> _byValue = $pb.ProtobufEnum.initByValue(values);
  static IntakeState? valueOf($core.int value) => _byValue[value];

  const IntakeState._($core.int v, $core.String n) : super(v, n);
}


const _omitEnumNames = $core.bool.fromEnvironment('protobuf.omit_enum_names');
