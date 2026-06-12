import 'package:antinvestor_api_audit/antinvestor_api_audit.dart';
import 'package:antinvestor_ui_core/widgets/admin_entity_list_page.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../providers/audit_export_helper.dart';
import '../providers/audit_providers.dart';

/// Known action types for the filter dropdown.
const _actionOptions = [
  '',
  'create',
  'update',
  'delete',
  'login',
  'export',
  'grant_permission',
];

/// Known resource types for the filter dropdown.
const _resourceTypeOptions = [
  '',
  'partition',
  'profile',
  'payment',
  'file',
  'service_account',
  'setting',
];

/// Known service names for the filter dropdown.
const _serviceOptions = [
  '',
  'service_tenancy',
  'service_profile',
  'service_payment',
  'service_files',
  'admin_ui',
];

/// Main audit log screen. Presents a searchable, filterable, paginated
/// DataTable of audit entries with CSV export and detail navigation.
class AuditLogScreen extends ConsumerStatefulWidget {
  const AuditLogScreen({super.key});

  @override
  ConsumerState<AuditLogScreen> createState() => _AuditLogScreenState();
}

class _AuditLogScreenState extends ConsumerState<AuditLogScreen> {
  String _filterProfileId = '';
  String _filterAction = '';
  String _filterResourceType = '';
  String _filterService = '';
  DateTimeRange? _dateRange;

  final _dateFormat = DateFormat('yyyy-MM-dd HH:mm:ss');

  AuditListParams get _params => AuditListParams(
        profileId: _filterProfileId,
        action: _filterAction,
        resourceType: _filterResourceType,
        service: _filterService,
        startDate: _dateRange?.start,
        endDate: _dateRange?.end,
        count: 100,
      );

  Future<void> _pickDateRange(BuildContext context) async {
    final now = DateTime.now();
    final picked = await showDateRangePicker(
      context: context,
      firstDate: now.subtract(const Duration(days: 365)),
      lastDate: now,
      initialDateRange: _dateRange,
    );
    if (picked != null) {
      setState(() => _dateRange = picked);
    }
  }

  String _formatTimestamp(Timestamp ts) {
    if (!ts.hasSeconds()) return '-';
    final dt = DateTime.fromMillisecondsSinceEpoch(
      ts.seconds.toInt() * 1000 + ts.nanos ~/ 1000000,
    );
    return _dateFormat.format(dt);
  }

  @override
  Widget build(BuildContext context) {
    final asyncEntries = ref.watch(auditEntriesProvider(_params));

    return Column(
      children: [
        // Filter bar
        _buildFilterBar(context),
        // Main content
        Expanded(
          child: asyncEntries.when(
            loading: () => const Center(child: CircularProgressIndicator()),
            error: (error, _) => Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.error_outline,
                      size: 48,
                      color: Theme.of(context).colorScheme.error),
                  const SizedBox(height: 16),
                  Text('Failed to load audit entries: $error'),
                  const SizedBox(height: 12),
                  OutlinedButton(
                    onPressed: () =>
                        ref.invalidate(auditEntriesProvider(_params)),
                    child: const Text('Retry'),
                  ),
                ],
              ),
            ),
            data: (entries) => _buildTable(entries),
          ),
        ),
      ],
    );
  }

  Widget _buildFilterBar(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        border: Border(
          bottom: BorderSide(color: theme.colorScheme.outlineVariant),
        ),
      ),
      child: Wrap(
        spacing: 12,
        runSpacing: 8,
        crossAxisAlignment: WrapCrossAlignment.center,
        children: [
          SizedBox(
            width: 180,
            child: TextField(
              decoration: const InputDecoration(
                hintText: 'Profile ID',
                isDense: true,
                prefixIcon: Icon(Icons.person_outline, size: 18),
              ),
              onChanged: (v) => setState(() => _filterProfileId = v.trim()),
            ),
          ),
          SizedBox(
            width: 160,
            child: DropdownButtonFormField<String>(
              initialValue: _filterAction,
              isExpanded: true,
              isDense: true,
              decoration: const InputDecoration(
                labelText: 'Action',
                isDense: true,
              ),
              items: _actionOptions
                  .map((a) => DropdownMenuItem(
                        value: a,
                        child: Text(a.isEmpty ? 'All actions' : a),
                      ))
                  .toList(),
              onChanged: (v) => setState(() => _filterAction = v ?? ''),
            ),
          ),
          SizedBox(
            width: 160,
            child: DropdownButtonFormField<String>(
              initialValue: _filterResourceType,
              isExpanded: true,
              isDense: true,
              decoration: const InputDecoration(
                labelText: 'Resource Type',
                isDense: true,
              ),
              items: _resourceTypeOptions
                  .map((r) => DropdownMenuItem(
                        value: r,
                        child: Text(r.isEmpty ? 'All types' : r),
                      ))
                  .toList(),
              onChanged: (v) => setState(() => _filterResourceType = v ?? ''),
            ),
          ),
          SizedBox(
            width: 180,
            child: DropdownButtonFormField<String>(
              initialValue: _filterService,
              isExpanded: true,
              isDense: true,
              decoration: const InputDecoration(
                labelText: 'Service',
                isDense: true,
              ),
              items: _serviceOptions
                  .map((s) => DropdownMenuItem(
                        value: s,
                        child: Text(s.isEmpty ? 'All services' : s),
                      ))
                  .toList(),
              onChanged: (v) => setState(() => _filterService = v ?? ''),
            ),
          ),
          OutlinedButton.icon(
            onPressed: () => _pickDateRange(context),
            icon: const Icon(Icons.date_range, size: 18),
            label: Text(
              _dateRange != null
                  ? '${DateFormat('MMM d').format(_dateRange!.start)} - ${DateFormat('MMM d').format(_dateRange!.end)}'
                  : 'Date range',
            ),
          ),
          if (_dateRange != null)
            IconButton(
              icon: const Icon(Icons.clear, size: 18),
              tooltip: 'Clear date range',
              onPressed: () => setState(() => _dateRange = null),
            ),
        ],
      ),
    );
  }

  Widget _buildTable(List<AuditEntryObject> entries) {
    return AdminEntityListPage<AuditEntryObject>(
      title: 'Audit Log',
      breadcrumbs: const ['Services', 'Audit', 'Log'],
      columns: const [
        DataColumn(label: Text('Timestamp')),
        DataColumn(label: Text('Actor')),
        DataColumn(label: Text('Action')),
        DataColumn(label: Text('Resource Type')),
        DataColumn(label: Text('Resource ID')),
        DataColumn(label: Text('Service')),
        DataColumn(label: Text('IP')),
      ],
      items: entries,
      rowBuilder: (entry, selected, onSelect) => DataRow(
        selected: selected,
        onSelectChanged: (_) => onSelect(),
        cells: [
          DataCell(Text(
            _formatTimestamp(entry.createdAt),
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
          )),
          DataCell(Text(
            entry.profileId.isNotEmpty
                ? '${entry.profileId.substring(0, entry.profileId.length.clamp(0, 8))}...'
                : '-',
          )),
          DataCell(_ActionChip(action: entry.action)),
          DataCell(Text(entry.resourceType)),
          DataCell(Text(
            entry.resourceId.isNotEmpty
                ? '${entry.resourceId.substring(0, entry.resourceId.length.clamp(0, 8))}...'
                : '-',
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
          )),
          DataCell(_ServiceBadge(service: entry.service)),
          DataCell(Text(entry.ipAddress.isNotEmpty ? entry.ipAddress : '-')),
        ],
      ),
      onRowNavigate: (entry) {
        context.go('/services/audit/${entry.id}');
      },
      exportRow: (entry) => [
        _formatTimestamp(entry.createdAt),
        entry.profileId,
        entry.action,
        entry.resourceType,
        entry.resourceId,
        entry.service,
        entry.ipAddress,
        entry.userAgent,
        entry.deviceId,
        entry.targetProfileId,
        entry.traceId,
      ],
      onExport: (format, rowCount) {
        logExport(
          ref,
          resourceType: 'audit_log',
          rowCount: rowCount,
          format: format,
        );
      },
    );
  }
}

/// Colored chip for audit action types.
class _ActionChip extends StatelessWidget {
  const _ActionChip({required this.action});
  final String action;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final (color, icon) = switch (action) {
      'create' => (Colors.green.shade600, Icons.add_circle_outline),
      'update' => (theme.colorScheme.primary, Icons.edit_outlined),
      'delete' => (theme.colorScheme.error, Icons.delete_outline),
      'login' => (Colors.blue.shade600, Icons.login),
      'export' => (Colors.orange.shade600, Icons.download_outlined),
      'grant_permission' => (Colors.purple.shade600, Icons.security_outlined),
      _ => (theme.colorScheme.onSurfaceVariant, Icons.circle_outlined),
    };
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 14, color: color),
        const SizedBox(width: 4),
        Text(action, style: TextStyle(color: color, fontSize: 13)),
      ],
    );
  }
}

/// Compact badge showing the originating service.
class _ServiceBadge extends StatelessWidget {
  const _ServiceBadge({required this.service});
  final String service;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    if (service.isEmpty) return const Text('-');
    final label = service.replaceFirst('service_', '');
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: theme.colorScheme.secondaryContainer,
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        label,
        style: theme.textTheme.labelSmall?.copyWith(
          color: theme.colorScheme.onSecondaryContainer,
        ),
      ),
    );
  }
}
