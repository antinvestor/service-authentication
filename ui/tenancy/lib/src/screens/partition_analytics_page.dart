import 'package:antinvestor_api_tenancy/antinvestor_api_tenancy.dart';
import 'package:antinvestor_ui_core/antinvestor_ui_core.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../analytics/tenancy_analytics.dart';
import '../providers/partition_providers.dart';

/// Analytics overview for the tenancy service.
///
/// KPI cards stay entity-derived (tenant / partition / role inventory
/// counts). The growth trend is a real timeseries from the thesa analytics
/// gate ([analyticsDataSourceProvider]) over
/// [organizationsCreatedMetric], and the tenant table is derived from the
/// live tenant/partition entity snapshot. Tenant scoping is injected
/// server-side; this page never sends tenant or partition filters.
class PartitionAnalyticsPage extends ConsumerStatefulWidget {
  const PartitionAnalyticsPage({super.key});

  @override
  ConsumerState<PartitionAnalyticsPage> createState() =>
      _PartitionAnalyticsPageState();
}

class _PartitionAnalyticsPageState
    extends ConsumerState<PartitionAnalyticsPage> {
  AnalyticsTimeRange _timeRange = AnalyticsTimeRange.lastYear();

  ServiceTimeSeriesParams get _growthParams => ServiceTimeSeriesParams(
    tenancyAnalyticsSpec.service,
    organizationsCreatedMetric,
    timeRange: _timeRange,
  );

  void _refresh() => ref.invalidate(serviceTimeSeriesProvider(_growthParams));

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final tenantsAsync = ref.watch(tenantsProvider);
    final partitionsAsync = ref.watch(partitionsProvider);
    final rolesAsync = ref.watch(partitionRolesProvider);
    final growthAsync = ref.watch(serviceTimeSeriesProvider(_growthParams));

    final tenantsCount = tenantsAsync.whenOrNull(data: (d) => d.length) ?? 0;
    final partitionsCount =
        partitionsAsync.whenOrNull(data: (d) => d.length) ?? 0;
    final rolesCount = rolesAsync.whenOrNull(data: (d) => d.length) ?? 0;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Tenancy Service',
            style: theme.textTheme.headlineSmall?.copyWith(
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 24),

          // KPI cards (entity inventory counts)
          Row(
            children: [
              _KpiCard(
                label: 'Total Tenants',
                value: '$tenantsCount',
                icon: Icons.domain_outlined,
              ),
              const SizedBox(width: 16),
              _KpiCard(
                label: 'Total Partitions',
                value: '$partitionsCount',
                icon: Icons.account_tree_outlined,
              ),
              const SizedBox(width: 16),
              _KpiCard(
                label: 'Total Roles',
                value: '$rolesCount',
                icon: Icons.security_outlined,
              ),
            ],
          ),
          const SizedBox(height: 24),

          // Growth trend (thesa analytics gate)
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: theme.colorScheme.surface,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: theme.colorScheme.outlineVariant),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Organization Growth',
                            style: theme.textTheme.titleMedium?.copyWith(
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            'Organizations created over time',
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ),
                    ),
                    SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      reverse: true,
                      child: TimeRangeSelector(
                        value: _timeRange,
                        initialPreset: TimeRangePreset.lastYear,
                        onChanged: (range) =>
                            setState(() => _timeRange = range),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                growthAsync.when(
                  data: (series) => TimeSeriesChart(
                    series: series,
                    mode: ChartMode.bar,
                    granularity:
                        _timeRange.granularity ?? TimeGranularity.month,
                  ),
                  loading: () => const SizedBox(
                    height: 240,
                    child: Center(child: CircularProgressIndicator()),
                  ),
                  error: (e, _) => _GateErrorCard(
                    message: analyticsGateMessage(e),
                    onRetry: _refresh,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),

          // Tenants by partition count (entity inventory)
          _TenantsTable(
            tenants: tenantsAsync.value ?? const [],
            partitions: partitionsAsync.value ?? const [],
          ),
        ],
      ),
    );
  }
}

/// Real tenant table derived from the entity snapshot, ranked by the number
/// of partitions each tenant owns.
class _TenantsTable extends StatelessWidget {
  const _TenantsTable({required this.tenants, required this.partitions});

  final List<TenantObject> tenants;
  final List<PartitionObject> partitions;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    final partitionCounts = <String, int>{};
    for (final p in partitions) {
      partitionCounts.update(p.tenantId, (v) => v + 1, ifAbsent: () => 1);
    }
    final ranked = tenants.toList()
      ..sort(
        (a, b) =>
            (partitionCounts[b.id] ?? 0).compareTo(partitionCounts[a.id] ?? 0),
      );
    final top = ranked.take(5).toList();

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Largest Tenants',
            style: theme.textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 16),
          if (top.isEmpty)
            Text(
              'No tenants in the current scope',
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            )
          else
            SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: DataTable(
                showCheckboxColumn: false,
                columns: const [
                  DataColumn(label: Text('TENANT')),
                  DataColumn(label: Text('PARTITIONS'), numeric: true),
                  DataColumn(label: Text('STATUS')),
                ],
                rows: [
                  for (final tenant in top)
                    DataRow(
                      cells: [
                        DataCell(
                          Text(
                            tenant.name.isNotEmpty ? tenant.name : tenant.id,
                          ),
                        ),
                        DataCell(Text('${partitionCounts[tenant.id] ?? 0}')),
                        DataCell(
                          _StatusBadge(
                            tenant.state.name,
                            tenant.state == STATE.ACTIVE
                                ? Colors.green
                                : Colors.blue,
                          ),
                        ),
                      ],
                    ),
                ],
              ),
            ),
        ],
      ),
    );
  }
}

class _KpiCard extends StatelessWidget {
  const _KpiCard({
    required this.label,
    required this.value,
    required this.icon,
  });

  final String label;
  final String value;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Expanded(
      child: Container(
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          color: theme.colorScheme.surface,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: theme.colorScheme.outlineVariant),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, size: 24, color: theme.colorScheme.tertiary),
            const SizedBox(height: 12),
            Text(
              value,
              style: theme.textTheme.headlineMedium?.copyWith(
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              label,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _StatusBadge extends StatelessWidget {
  const _StatusBadge(this.label, this.color);

  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        label,
        style: Theme.of(context).textTheme.labelSmall?.copyWith(
          color: color,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}

/// Friendly inline error card for analytics gate failures.
class _GateErrorCard extends StatelessWidget {
  const _GateErrorCard({required this.message, this.onRetry});

  final String message;
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: cs.errorContainer.withValues(alpha: 0.25),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(Icons.insights_outlined, color: cs.error, size: 20),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              message,
              style: TextStyle(color: cs.error, fontSize: 13),
            ),
          ),
          if (onRetry != null) ...[
            const SizedBox(width: 8),
            TextButton(onPressed: onRetry, child: const Text('Retry')),
          ],
        ],
      ),
    );
  }
}
