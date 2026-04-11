import 'package:antinvestor_api_audit/antinvestor_api_audit.dart';
import 'package:antinvestor_ui_core/widgets/service_analytics_page.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../providers/audit_providers.dart';

/// Analytics dashboard for the audit service showing KPI cards,
/// action distribution, and recent entries.
class AuditAnalyticsScreen extends ConsumerWidget {
  const AuditAnalyticsScreen({super.key});

  static final _dateFormat = DateFormat('MMM d, HH:mm');

  String _formatTimestamp(Timestamp ts) {
    if (!ts.hasSeconds()) return '-';
    final dt = DateTime.fromMillisecondsSinceEpoch(
      ts.seconds.toInt() * 1000 + ts.nanos ~/ 1000000,
    );
    return _dateFormat.format(dt);
  }

  String _relativeTime(Timestamp ts) {
    if (!ts.hasSeconds()) return '-';
    final dt = DateTime.fromMillisecondsSinceEpoch(
      ts.seconds.toInt() * 1000 + ts.nanos ~/ 1000000,
    );
    final diff = DateTime.now().difference(dt);
    if (diff.inMinutes < 1) return 'just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Fetch recent entries for KPIs and events list.
    final allEntriesAsync = ref.watch(
      auditEntriesProvider(const AuditListParams(count: 100)),
    );

    // Fetch today's entries specifically.
    final now = DateTime.now();
    final startOfDay = DateTime(now.year, now.month, now.day);
    final todayAsync = ref.watch(
      auditEntriesProvider(AuditListParams(startDate: startOfDay, count: 100)),
    );

    return allEntriesAsync.when(
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (error, _) => Center(child: Text('Error: $error')),
      data: (allEntries) {
        final todayEntries = todayAsync.value ?? [];
        final uniqueActors =
            allEntries.map((e) => e.profileId).toSet().length;
        final uniqueServices =
            allEntries.map((e) => e.service).toSet().length;

        // Build action distribution for chart placeholder.
        final actionCounts = <String, int>{};
        for (final entry in allEntries) {
          actionCounts[entry.action] =
              (actionCounts[entry.action] ?? 0) + 1;
        }

        // Recent events for the sidebar.
        final recentEvents = allEntries.take(10).map((e) {
          final (severity, icon) = switch (e.action) {
            'delete' => (EventSeverity.warning, Icons.delete_outline),
            'login' => (EventSeverity.info, Icons.login),
            'create' => (EventSeverity.success, Icons.add_circle_outline),
            'grant_permission' => (
                EventSeverity.info,
                Icons.security_outlined
              ),
            'export' => (EventSeverity.info, Icons.download_outlined),
            _ => (EventSeverity.info, Icons.edit_outlined),
          };
          return ServiceEvent(
            title: '${e.action} ${e.resourceType}'
                '${e.resourceId.isNotEmpty ? ' (${e.resourceId.substring(0, e.resourceId.length.clamp(0, 8))})' : ''}',
            timeAgo: _relativeTime(e.createdAt),
            icon: icon,
            severity: severity,
          );
        }).toList();

        return ServiceAnalyticsPage(
          title: 'Audit Analytics',
          breadcrumbs: const ['Services', 'Audit', 'Analytics'],
          kpis: [
            ServiceKpi(
              label: 'Total Entries',
              value: '${allEntries.length}',
              icon: Icons.history,
            ),
            ServiceKpi(
              label: 'Entries Today',
              value: '${todayEntries.length}',
              icon: Icons.today,
            ),
            ServiceKpi(
              label: 'Unique Actors',
              value: '$uniqueActors',
              icon: Icons.people_outline,
            ),
            ServiceKpi(
              label: 'Unique Services',
              value: '$uniqueServices',
              icon: Icons.dns_outlined,
            ),
          ],
          chartTitle: 'Action Distribution',
          chartSubtitle: 'Breakdown of audit actions over recent entries',
          chartWidget: _ActionDistributionChart(actionCounts: actionCounts),
          events: recentEvents,
          onViewAllEvents: () => context.go('/services/audit/log'),
          actions: [
            OutlinedButton.icon(
              onPressed: () => context.go('/services/audit/integrity'),
              icon: const Icon(Icons.verified_outlined, size: 18),
              label: const Text('Verify Integrity'),
            ),
          ],
        );
      },
    );
  }
}

/// Simple bar chart showing action distribution using Material widgets.
class _ActionDistributionChart extends StatelessWidget {
  const _ActionDistributionChart({required this.actionCounts});
  final Map<String, int> actionCounts;

  @override
  Widget build(BuildContext context) {
    if (actionCounts.isEmpty) {
      return Center(
        child: Text(
          'No data available',
          style: TextStyle(
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
      );
    }

    final theme = Theme.of(context);
    final sorted = actionCounts.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    final maxCount = sorted.first.value;

    final colors = [
      Colors.green.shade600,
      theme.colorScheme.primary,
      theme.colorScheme.error,
      Colors.blue.shade600,
      Colors.orange.shade600,
      Colors.purple.shade600,
      theme.colorScheme.tertiary,
    ];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (var i = 0; i < sorted.length; i++) ...[
          Row(
            children: [
              SizedBox(
                width: 120,
                child: Text(
                  sorted[i].key,
                  style: theme.textTheme.bodySmall,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              Expanded(
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(4),
                  child: LinearProgressIndicator(
                    value: maxCount > 0 ? sorted[i].value / maxCount : 0,
                    backgroundColor:
                        theme.colorScheme.surfaceContainerHighest,
                    color: colors[i % colors.length],
                    minHeight: 20,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              SizedBox(
                width: 36,
                child: Text(
                  '${sorted[i].value}',
                  style: theme.textTheme.bodySmall
                      ?.copyWith(fontWeight: FontWeight.w600),
                  textAlign: TextAlign.end,
                ),
              ),
            ],
          ),
          if (i < sorted.length - 1) const SizedBox(height: 8),
        ],
      ],
    );
  }
}
