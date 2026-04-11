import 'package:antinvestor_api_audit/antinvestor_api_audit.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'audit_providers.dart';

/// Creates an audit entry to record a data export event.
///
/// Call this from any screen's onExport callback to create an audit trail
/// entry for the export action.
///
/// ```dart
/// onExport: (format, rowCount) {
///   logExport(ref, resourceType: 'audit_log', rowCount: rowCount, format: format);
/// }
/// ```
Future<void> logExport(
  WidgetRef ref, {
  required String resourceType,
  required int rowCount,
  required String format,
}) async {
  final details = Struct()
    ..fields['row_count'] = (Value()..numberValue = rowCount.toDouble())
    ..fields['format'] = (Value()..stringValue = format);

  final notifier = ref.read(auditNotifierProvider.notifier);
  await notifier.createEntry(
    action: 'export',
    resourceType: resourceType,
    service: 'admin_ui',
    details: details,
  );
}
