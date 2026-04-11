import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../providers/partition_providers.dart';

class PartitionAnalyticsPage extends ConsumerWidget {
  const PartitionAnalyticsPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final tenantsAsync = ref.watch(tenantsProvider);
    final partitionsAsync = ref.watch(partitionsProvider);
    final rolesAsync = ref.watch(partitionRolesProvider);

    final tenantsCount = tenantsAsync.whenOrNull(data: (d) => d.length) ?? 0;
    final partitionsCount =
        partitionsAsync.whenOrNull(data: (d) => d.length) ?? 0;
    final rolesCount = rolesAsync.whenOrNull(data: (d) => d.length) ?? 0;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Tenancy Service',
              style: theme.textTheme.headlineSmall
                  ?.copyWith(fontWeight: FontWeight.w700)),
          const SizedBox(height: 24),

          // KPI cards
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

          // Chart
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
                Text('Partition Growth',
                    style: theme.textTheme.titleMedium
                        ?.copyWith(fontWeight: FontWeight.w600)),
                Text('12-month network-wide scaling metrics',
                    style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant)),
                const SizedBox(height: 16),
                SizedBox(
                  height: 200,
                  child: _PartitionGrowthChart(),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),

          // Top tenants
          _buildTopTenants(context),
        ],
      ),
    );
  }

  Widget _buildTopTenants(BuildContext context) {
    final theme = Theme.of(context);
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
          Text('Top Performing Tenants',
              style: theme.textTheme.titleMedium
                  ?.copyWith(fontWeight: FontWeight.w600)),
          const SizedBox(height: 16),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              showCheckboxColumn: false,
              columns: const [
                DataColumn(label: Text('ORGANIZATION')),
                DataColumn(label: Text('PARTITIONS'), numeric: true),
                DataColumn(label: Text('IOPS AVG')),
                DataColumn(label: Text('SECURITY SCORE')),
                DataColumn(label: Text('STATUS')),
              ],
              rows: [
                DataRow(cells: [
                  const DataCell(Text('Vortex Dynamics')),
                  const DataCell(Text('2,490')),
                  const DataCell(Text('14.2k/s')),
                  const DataCell(Text('98%')),
                  DataCell(_StatusBadge('OPTIMIZED', Colors.green)),
                ]),
                DataRow(cells: [
                  const DataCell(Text('Nexus Logistics')),
                  const DataCell(Text('1,823')),
                  const DataCell(Text('11.8k/s')),
                  const DataCell(Text('95%')),
                  DataCell(_StatusBadge('OPTIMIZED', Colors.green)),
                ]),
                DataRow(cells: [
                  const DataCell(Text('Atlas Industries')),
                  const DataCell(Text('1,204')),
                  const DataCell(Text('9.4k/s')),
                  const DataCell(Text('87%')),
                  DataCell(_StatusBadge('ACTIVE', Colors.blue)),
                ]),
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
            Text(value,
                style: theme.textTheme.headlineMedium
                    ?.copyWith(fontWeight: FontWeight.w700)),
            const SizedBox(height: 4),
            Text(label,
                style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant)),
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

class _PartitionGrowthChart extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return BarChart(
      BarChartData(
        alignment: BarChartAlignment.spaceAround,
        maxY: 2000,
        barTouchData: BarTouchData(enabled: false),
        titlesData: FlTitlesData(
          show: true,
          bottomTitles: AxisTitles(
            sideTitles: SideTitles(
              showTitles: true,
              getTitlesWidget: (value, meta) {
                const months = [
                  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
                ];
                if (value.toInt() >= 0 && value.toInt() < months.length) {
                  return Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: Text(months[value.toInt()],
                        style: TextStyle(
                            fontSize: 10,
                            color: theme.colorScheme.onSurfaceVariant)),
                  );
                }
                return const SizedBox.shrink();
              },
            ),
          ),
          leftTitles: AxisTitles(
            sideTitles: SideTitles(
              showTitles: true,
              reservedSize: 40,
              getTitlesWidget: (value, meta) {
                return Text('${value.toInt()}',
                    style: TextStyle(
                        fontSize: 10,
                        color: theme.colorScheme.onSurfaceVariant));
              },
            ),
          ),
          topTitles:
              const AxisTitles(sideTitles: SideTitles(showTitles: false)),
          rightTitles:
              const AxisTitles(sideTitles: SideTitles(showTitles: false)),
        ),
        borderData: FlBorderData(show: false),
        gridData: FlGridData(
          show: true,
          drawVerticalLine: false,
          horizontalInterval: 500,
          getDrawingHorizontalLine: (_) => FlLine(
            color: theme.colorScheme.outlineVariant,
            strokeWidth: 1,
          ),
        ),
        barGroups: List.generate(12, (i) {
          final values = [
            800, 950, 1100, 1050, 1200, 1400,
            1350, 1500, 1600, 1550, 1700, 1850,
          ];
          return BarChartGroupData(
            x: i,
            barRods: [
              BarChartRodData(
                toY: values[i].toDouble(),
                color: theme.colorScheme.tertiary,
                width: 16,
                borderRadius: const BorderRadius.only(
                  topLeft: Radius.circular(4),
                  topRight: Radius.circular(4),
                ),
              ),
            ],
          );
        }),
      ),
    );
  }
}
