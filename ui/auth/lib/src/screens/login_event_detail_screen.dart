import 'package:antinvestor_api_authentication/antinvestor_api_authentication.dart';
import 'package:antinvestor_ui_core/widgets/metadata_row.dart';
import 'package:antinvestor_ui_core/widgets/page_header.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../providers/auth_providers.dart';
import '../widgets/login_event_tile.dart';

/// Full detail view for a single login event, showing all fields
/// including IP, user agent, device, and additional properties.
class LoginEventDetailScreen extends ConsumerWidget {
  const LoginEventDetailScreen({super.key, required this.eventId});

  final String eventId;

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
    final asyncEvent = ref.watch(loginEventByIdProvider(eventId));

    return asyncEvent.when(
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (error, _) => Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline,
                size: 48, color: Theme.of(context).colorScheme.error),
            const SizedBox(height: 16),
            Text('Failed to load login event: $error'),
            const SizedBox(height: 12),
            OutlinedButton(
              onPressed: () =>
                  ref.invalidate(loginEventByIdProvider(eventId)),
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
      data: (event) => _buildDetail(context, event),
    );
  }

  Widget _buildDetail(BuildContext context, LoginEventObject event) {
    final theme = Theme.of(context);
    final surfaceColor = theme.colorScheme.surface;
    final borderColor = theme.colorScheme.outlineVariant;
    final isSuccess = event.status == 0;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          PageHeader(
            title: 'Login Event',
            breadcrumbs: const [
              'Services',
              'Authentication',
              'History',
              'Detail'
            ],
            actions: [
              OutlinedButton.icon(
                onPressed: () => context.go('/services/auth'),
                icon: const Icon(Icons.arrow_back, size: 18),
                label: const Text('Back to History'),
              ),
            ],
          ),
          const SizedBox(height: 20),
          // Status banner
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: isSuccess
                  ? Colors.green.shade50
                  : theme.colorScheme.errorContainer,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: isSuccess
                    ? Colors.green.shade200
                    : theme.colorScheme.error.withValues(alpha: 0.3),
              ),
            ),
            child: Row(
              children: [
                Icon(
                  isSuccess ? Icons.check_circle : Icons.cancel,
                  color: isSuccess
                      ? Colors.green.shade600
                      : theme.colorScheme.error,
                  size: 24,
                ),
                const SizedBox(width: 12),
                Text(
                  isSuccess
                      ? 'Successful Sign-in'
                      : 'Failed Sign-in Attempt',
                  style: theme.textTheme.titleSmall?.copyWith(
                    color: isSuccess
                        ? Colors.green.shade700
                        : theme.colorScheme.onErrorContainer,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const Spacer(),
                Text(
                  _formatTimestamp(event.createdAt),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: isSuccess
                        ? Colors.green.shade700
                        : theme.colorScheme.onErrorContainer,
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          // Authentication details
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
                Text('Authentication Details',
                    style: theme.textTheme.titleMedium
                        ?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 16),
                MetadataRow(label: 'Event ID', value: event.id, copiable: true),
                MetadataRow(
                  label: 'Source',
                  value: LoginEventTile.labelForSource(event.source),
                ),
                MetadataRow(
                    label: 'Profile ID',
                    value: event.profileId,
                    copiable: true),
                MetadataRow(
                    label: 'Client ID',
                    value: event.clientId,
                    copiable: true),
                if (event.contactId.isNotEmpty)
                  MetadataRow(
                      label: 'Contact ID',
                      value: event.contactId,
                      copiable: true),
                MetadataRow(
                    label: 'Timestamp',
                    value: _formatTimestamp(event.createdAt)),
              ],
            ),
          ),
          const SizedBox(height: 16),
          // Context details
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
                Text('Client & Device',
                    style: theme.textTheme.titleMedium
                        ?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 16),
                MetadataRow(
                    label: 'IP Address',
                    value: event.ipAddress,
                    copiable: true),
                MetadataRow(label: 'User Agent', value: event.userAgent),
                MetadataRow(
                    label: 'Device ID',
                    value: event.deviceId,
                    copiable: true),
              ],
            ),
          ),
          const SizedBox(height: 16),
          // Tenancy context
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
                Text('Tenancy Context',
                    style: theme.textTheme.titleMedium
                        ?.copyWith(fontWeight: FontWeight.w600)),
                const SizedBox(height: 16),
                MetadataRow(
                    label: 'Tenant ID',
                    value: event.tenantId,
                    copiable: true),
                MetadataRow(
                    label: 'Partition ID',
                    value: event.partitionId,
                    copiable: true),
              ],
            ),
          ),
          // Properties (if any)
          if (event.hasProperties()) ...[
            const SizedBox(height: 16),
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
                  Text('Additional Properties',
                      style: theme.textTheme.titleMedium
                          ?.copyWith(fontWeight: FontWeight.w600)),
                  const SizedBox(height: 16),
                  ...event.properties.fields.entries.map((e) {
                    final value = _formatStructValue(e.value);
                    return MetadataRow(label: e.key, value: value);
                  }),
                ],
              ),
            ),
          ],
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
