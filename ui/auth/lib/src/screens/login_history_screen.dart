import 'package:antinvestor_api_authentication/antinvestor_api_authentication.dart';
import 'package:antinvestor_ui_core/widgets/admin_entity_list_page.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../providers/auth_providers.dart';
import '../widgets/login_event_tile.dart';

/// Known login source options for the filter dropdown.
const _sourceOptions = [
  '',
  'direct',
  'google',
  'facebook',
  'service_account',
  'session_refresh',
];

/// Main login history screen. Presents a filterable, paginated DataTable
/// of login events with detail navigation.
class LoginHistoryScreen extends ConsumerStatefulWidget {
  const LoginHistoryScreen({super.key});

  @override
  ConsumerState<LoginHistoryScreen> createState() =>
      _LoginHistoryScreenState();
}

class _LoginHistoryScreenState extends ConsumerState<LoginHistoryScreen> {
  String _filterProfileId = '';
  String _filterSource = '';
  String _filterDeviceId = '';
  DateTimeRange? _dateRange;

  final _dateFormat = DateFormat('yyyy-MM-dd HH:mm:ss');

  LoginEventListParams get _params => LoginEventListParams(
        profileId: _filterProfileId,
        source: _filterSource,
        deviceId: _filterDeviceId,
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
    final asyncEvents = ref.watch(loginEventsProvider(_params));

    return Column(
      children: [
        _buildFilterBar(context),
        Expanded(
          child: asyncEvents.when(
            loading: () => const Center(child: CircularProgressIndicator()),
            error: (error, _) => Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.error_outline,
                      size: 48,
                      color: Theme.of(context).colorScheme.error),
                  const SizedBox(height: 16),
                  Text('Failed to load login events: $error'),
                  const SizedBox(height: 12),
                  OutlinedButton(
                    onPressed: () =>
                        ref.invalidate(loginEventsProvider(_params)),
                    child: const Text('Retry'),
                  ),
                ],
              ),
            ),
            data: (events) => _buildTable(events),
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
              onChanged: (v) =>
                  setState(() => _filterProfileId = v.trim()),
            ),
          ),
          SizedBox(
            width: 160,
            child: DropdownButtonFormField<String>(
              value: _filterSource,
              isDense: true,
              decoration: const InputDecoration(
                labelText: 'Source',
                isDense: true,
              ),
              items: _sourceOptions
                  .map((s) => DropdownMenuItem(
                        value: s,
                        child: Text(s.isEmpty
                            ? 'All sources'
                            : LoginEventTile.labelForSource(s)),
                      ))
                  .toList(),
              onChanged: (v) =>
                  setState(() => _filterSource = v ?? ''),
            ),
          ),
          SizedBox(
            width: 180,
            child: TextField(
              decoration: const InputDecoration(
                hintText: 'Device ID',
                isDense: true,
                prefixIcon: Icon(Icons.devices_outlined, size: 18),
              ),
              onChanged: (v) =>
                  setState(() => _filterDeviceId = v.trim()),
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

  Widget _buildTable(List<LoginEventObject> events) {
    return AdminEntityListPage<LoginEventObject>(
      title: 'Login History',
      breadcrumbs: const ['Services', 'Authentication', 'Login History'],
      columns: const [
        DataColumn(label: Text('Timestamp')),
        DataColumn(label: Text('Profile')),
        DataColumn(label: Text('Source')),
        DataColumn(label: Text('IP Address')),
        DataColumn(label: Text('User Agent')),
        DataColumn(label: Text('Device')),
        DataColumn(label: Text('Status')),
      ],
      items: events,
      rowBuilder: (event, selected, onSelect) => DataRow(
        selected: selected,
        onSelectChanged: (_) => onSelect(),
        cells: [
          DataCell(Text(
            _formatTimestamp(event.createdAt),
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
          )),
          DataCell(Text(
            event.profileId.isNotEmpty
                ? '${event.profileId.substring(0, event.profileId.length.clamp(0, 8))}...'
                : '-',
          )),
          DataCell(_SourceChip(source: event.source)),
          DataCell(Text(
              event.ipAddress.isNotEmpty ? event.ipAddress : '-')),
          DataCell(Text(
            _truncateUserAgent(event.userAgent),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          )),
          DataCell(Text(
            event.deviceId.isNotEmpty
                ? '${event.deviceId.substring(0, event.deviceId.length.clamp(0, 8))}...'
                : '-',
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
          )),
          DataCell(_StatusBadge(status: event.status)),
        ],
      ),
      onRowNavigate: (event) {
        context.go('/services/auth/${event.id}');
      },
      exportRow: (event) => [
        _formatTimestamp(event.createdAt),
        event.profileId,
        event.source,
        event.ipAddress,
        event.userAgent,
        event.deviceId,
        event.clientId,
        event.status.toString(),
      ],
    );
  }

  String _truncateUserAgent(String ua) {
    if (ua.isEmpty) return '-';
    if (ua.length > 40) return '${ua.substring(0, 40)}...';
    return ua;
  }
}

/// Colored chip for login source types.
class _SourceChip extends StatelessWidget {
  const _SourceChip({required this.source});
  final String source;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final color = LoginEventTile.colorForSource(source, theme);
    final icon = LoginEventTile.iconForSource(source);
    final label = LoginEventTile.labelForSource(source);
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 14, color: color),
        const SizedBox(width: 4),
        Text(label, style: TextStyle(color: color, fontSize: 13)),
      ],
    );
  }
}

/// Status badge showing success/failure.
class _StatusBadge extends StatelessWidget {
  const _StatusBadge({required this.status});
  final int status;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isSuccess = status == 0;
    final color = isSuccess ? Colors.green.shade600 : theme.colorScheme.error;
    final bgColor = isSuccess
        ? Colors.green.shade50
        : theme.colorScheme.errorContainer;
    final label = isSuccess ? 'Success' : 'Failed';

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: bgColor,
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        label,
        style: theme.textTheme.labelSmall?.copyWith(
          color: color,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}
