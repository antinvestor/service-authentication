// This is a generated file - do not edit.
//
// Generated from audit/v1/audit.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports

import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;

/// AuditPhase links a human command to its outcome (GFOS §10.4, K11).
/// A producer records REQUESTED before its own transaction and a linked
/// COMPLETED or FAILED afterwards, so a REQUESTED entry with no outcome
/// reads as "asked, not done". The service never infers completion.
class AuditPhase extends $pb.ProtobufEnum {
  static const AuditPhase AUDIT_PHASE_UNSPECIFIED =
      AuditPhase._(0, _omitEnumNames ? '' : 'AUDIT_PHASE_UNSPECIFIED');

  /// The human command was asked for; the producer transaction had not committed.
  static const AuditPhase AUDIT_PHASE_REQUESTED =
      AuditPhase._(1, _omitEnumNames ? '' : 'AUDIT_PHASE_REQUESTED');

  /// The command succeeded; outcome_of_entry_id names the request.
  static const AuditPhase AUDIT_PHASE_COMPLETED =
      AuditPhase._(2, _omitEnumNames ? '' : 'AUDIT_PHASE_COMPLETED');

  /// The command failed; outcome_of_entry_id names the request.
  static const AuditPhase AUDIT_PHASE_FAILED =
      AuditPhase._(3, _omitEnumNames ? '' : 'AUDIT_PHASE_FAILED');

  static const $core.List<AuditPhase> values = <AuditPhase>[
    AUDIT_PHASE_UNSPECIFIED,
    AUDIT_PHASE_REQUESTED,
    AUDIT_PHASE_COMPLETED,
    AUDIT_PHASE_FAILED,
  ];

  static final $core.List<AuditPhase?> _byValue =
      $pb.ProtobufEnum.$_initByValueList(values, 3);
  static AuditPhase? valueOf($core.int value) =>
      value < 0 || value >= _byValue.length ? null : _byValue[value];

  const AuditPhase._(super.value, super.name);
}

/// IntakeState is the lifecycle of an accepted entry.
class IntakeState extends $pb.ProtobufEnum {
  static const IntakeState INTAKE_STATE_UNSPECIFIED =
      IntakeState._(0, _omitEnumNames ? '' : 'INTAKE_STATE_UNSPECIFIED');

  /// Durably accepted; not yet in the chain.
  static const IntakeState INTAKE_STATE_ACCEPTED =
      IntakeState._(1, _omitEnumNames ? '' : 'INTAKE_STATE_ACCEPTED');

  /// Sequenced, hashed and signed in the chain.
  static const IntakeState INTAKE_STATE_COMMITTED =
      IntakeState._(2, _omitEnumNames ? '' : 'INTAKE_STATE_COMMITTED');

  /// Could not be chained; needs operator action.
  static const IntakeState INTAKE_STATE_FAILED =
      IntakeState._(3, _omitEnumNames ? '' : 'INTAKE_STATE_FAILED');

  static const $core.List<IntakeState> values = <IntakeState>[
    INTAKE_STATE_UNSPECIFIED,
    INTAKE_STATE_ACCEPTED,
    INTAKE_STATE_COMMITTED,
    INTAKE_STATE_FAILED,
  ];

  static final $core.List<IntakeState?> _byValue =
      $pb.ProtobufEnum.$_initByValueList(values, 3);
  static IntakeState? valueOf($core.int value) =>
      value < 0 || value >= _byValue.length ? null : _byValue[value];

  const IntakeState._(super.value, super.name);
}

const $core.bool _omitEnumNames =
    $core.bool.fromEnvironment('protobuf.omit_enum_names');
