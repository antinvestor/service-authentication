import 'package:antinvestor_api_audit/antinvestor_api_audit.dart';
import 'package:antinvestor_ui_core/widgets/metadata_row.dart';
import 'package:antinvestor_ui_core/widgets/page_header.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../providers/audit_providers.dart';

/// Full detail view for a single audit entry, showing all fields,
/// structured details, and hash chain integrity information.
class AuditDetailScreen extends ConsumerWidget {
  const AuditDetailScreen({super.key, required this.entryId});

  final String entryId;

  static final _dateFormat = DateFormat('yyyy-MM-dd HH:mm:ss');

  String _formatTimestamp(Timestamp ts) {
    if (!ts.hasSeconds()) return '-';
    final dt = DateTime.fromMillisecondsSinceEpoch(
      ts.seconds.toInt() * 1000 + ts.nanos ~/ 1000000,
    );
    return _dateFormat.format(dt);
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final asyncEntry = ref.watch(auditEntryByIdProvider(entryId));

    return asyncEntry.when(
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (error, _) => Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline,
                size: 48, color: Theme.of(context).colorScheme.error),
            const SizedBox(height: 16),
            Text('Failed to load entry: $error'),
            const SizedBox(height: 12),
            OutlinedButton(
              onPressed: () =>
                  ref.invalidate(auditEntryByIdProvider(entryId)),
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
      data: (entry) => _buildDetail(context, ref, entry),
    );
  }

  Widget _buildDetail(
      BuildContext context, WidgetRef ref, AuditEntryObject entry) {
    final theme = Theme.of(context);
    final surfaceColor = theme.colorScheme.surface;
    final borderColor = theme.colorScheme.outlineVariant;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          PageHeader(
            title: 'Audit Entry',
            breadcrumbs: const ['Services', 'Audit', 'Log', 'Detail'],
            actions: [
              OutlinedButton.icon(
                onPressed: () => context.go('/services/audit'),
                icon: const Icon(Icons.arrow_back, size: 18),
                label: const Text('Back to Log'),
              ),
            ],
          ),
          const SizedBox(height: 20),
          // Entry info card
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: surfaceColor,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: borderColor),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Entry Information',
                    style: theme.textTheme.titleMedium
                        ?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 16),
                MetadataRow(label: 'ID', value: entry.id, copiable: true),
                MetadataRow(
                    label: 'Tenant ID',
                    value: entry.tenantId,
                    copiable: true),
                MetadataRow(
                    label: 'Partition ID',
                    value: entry.partitionId,
                    copiable: true),
                MetadataRow(label: 'Action', value: entry.action),
                MetadataRow(
                    label: 'Resource Type', value: entry.resourceType),
                MetadataRow(
                    label: 'Resource ID',
                    value: entry.resourceId,
                    copiable: true),
                MetadataRow(label: 'Service', value: entry.service),
                MetadataRow(
                    label: 'Timestamp',
                    value: _formatTimestamp(entry.createdAt)),
              ],
            ),
          ),
          const SizedBox(height: 16),
          // Actor info card
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: surfaceColor,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: borderColor),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Actor & Context',
                    style: theme.textTheme.titleMedium
                        ?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 16),
                MetadataRow(
                  label: 'Actor Profile',
                  value: entry.profileId,
                  copiable: true,
                ),
                MetadataRow(
                    label: 'IP Address',
                    value: entry.ipAddress,
                    copiable: true),
                MetadataRow(label: 'User Agent', value: entry.userAgent),
                MetadataRow(
                    label: 'Device ID',
                    value: entry.deviceId,
                    copiable: true),
                if (entry.targetProfileId.isNotEmpty)
                  MetadataRow(
                    label: 'Target Profile',
                    value: entry.targetProfileId,
                    copiable: true,
                  ),
                if (entry.traceId.isNotEmpty)
                  MetadataRow(
                    label: 'Trace ID',
                    value: entry.traceId,
                    copiable: true,
                  ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          // Details (Struct) card
          if (entry.hasDetails()) ...[
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: surfaceColor,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: borderColor),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Details',
                      style: theme.textTheme.titleMedium
                          ?.copyWith(fontWeight: FontWeight.w600)),
                  const SizedBox(height: 16),
                  ...entry.details.fields.entries.map((e) {
                    final value = _formatStructValue(e.value);
                    return MetadataRow(label: e.key, value: value);
                  }),
                ],
              ),
            ),
            const SizedBox(height: 16),
          ],
          // Hash chain integrity card
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: surfaceColor,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: borderColor),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(Icons.link, size: 20, color: theme.colorScheme.primary),
                    const SizedBox(width: 8),
                    Text('Hash Chain Integrity',
                        style: theme.textTheme.titleMedium
                            ?.copyWith(fontWeight: FontWeight.w600)),
                  ],
                ),
                const SizedBox(height: 16),
                _HashField(
                    label: 'Previous Hash', value: entry.previousHash),
                const SizedBox(height: 8),
                _HashField(label: 'Entry Hash', value: entry.entryHash),
                const SizedBox(height: 8),
                _HashField(label: 'Signature', value: entry.signature),
                const SizedBox(height: 16),
                OutlinedButton.icon(
                  onPressed: () =>
                      context.go('/services/audit/integrity'),
                  icon: const Icon(Icons.verified_outlined, size: 18),
                  label: const Text('Verify Chain Integrity'),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _formatStructValue(Value value) {
    if (value.hasStringValue()) return value.stringValue;
    if (value.hasNumberValue()) return value.numberValue.toString();
    if (value.hasBoolValue()) return value.boolValue.toString();
    if (value.hasNullValue()) return 'null';
    if (value.hasListValue()) {
      return value.listValue.values
          .map(_formatStructValue)
          .toList()
          .toString();
    }
    if (value.hasStructValue()) {
      return value.structValue.fields.entries
          .map((e) => '${e.key}: ${_formatStructValue(e.value)}')
          .join(', ');
    }
    return '-';
  }
}

/// Displays a hash value in monospace font with a truncated display
/// and copy-to-clipboard button.
class _HashField extends StatelessWidget {
  const _HashField({required this.label, required this.value});
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    if (value.isEmpty) {
      return MetadataRow(label: label, value: '-');
    }

    final truncated =
        value.length > 16 ? '${value.substring(0, 16)}...' : value;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 120,
          child: Text(
            label,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
        Expanded(
          child: Text(
            truncated,
            style: theme.textTheme.bodyMedium?.copyWith(
              fontFamily: 'monospace',
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
        Tooltip(
          message: 'Copy full hash',
          child: InkWell(
            borderRadius: BorderRadius.circular(12),
            onTap: () {
              Clipboard.setData(ClipboardData(text: value));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('Copied to clipboard'),
                  duration: Duration(seconds: 2),
                  behavior: SnackBarBehavior.floating,
                  width: 200,
                ),
              );
            },
            child: Padding(
              padding: const EdgeInsets.all(4),
              child: Icon(
                Icons.copy_rounded,
                size: 14,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
        ),
      ],
    );
  }
}
