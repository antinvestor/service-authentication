import 'package:antinvestor_api_tenancy/antinvestor_api_tenancy.dart';
import 'package:antinvestor_ui_core/widgets/page_header.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../providers/partition_providers.dart';
import '../providers/partition_repository.dart';
import '../widgets/create_partition_wizard.dart';
import '../widgets/partition_tree.dart';

class PartitionsPage extends ConsumerWidget {
  const PartitionsPage({super.key});

  Future<void> _showCreatePartitionDialog(
    BuildContext context,
    WidgetRef ref,
    List<PartitionObject> partitions,
  ) async {
    final tenants = await ref.read(tenantsProvider.future);
    if (!context.mounted) return;

    final result = await showCreatePartitionWizard(
      context: context,
      tenants: tenants,
      existingPartitions: partitions,
    );
    if (result == null || !context.mounted) return;

    try {
      final repo = ref.read(partitionRepositoryProvider);
      final partition = await repo.createPartition(
        tenantId: result.tenantId,
        name: result.name,
        parentId: result.parentId,
        description: result.description,
        domain: result.domain,
        properties: result.toPropertiesStruct(),
      );
      // Auto-create default roles
      for (final roleName in ['owner', 'admin', 'member']) {
        try {
          await repo.createPartitionRole(
            partitionId: partition.id,
            name: roleName,
          );
        } catch (_) {
          // Role may already exist; continue
        }
      }
      ref.invalidate(partitionsProvider);
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
              content:
                  Text('Partition created with default roles')),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Error: $e')));
      }
    }
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final asyncPartitions = ref.watch(partitionsProvider);

    return asyncPartitions.when(
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (error, _) => Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline, size: 48,
                color: theme.colorScheme.error),
            const SizedBox(height: 16),
            Text('Failed to load partitions',
                style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(error.toString(),
                style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant)),
            const SizedBox(height: 16),
            OutlinedButton.icon(
              onPressed: () => ref.invalidate(partitionsProvider),
              icon: const Icon(Icons.refresh, size: 18),
              label: const Text('Retry'),
            ),
          ],
        ),
      ),
      data: (partitions) => SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            PageHeader(
              title: 'Partitions',
              breadcrumbs: const ['Services', 'Tenancy Service', 'Partitions'],
              actions: [
                ElevatedButton.icon(
                  onPressed: () =>
                      _showCreatePartitionDialog(context, ref, partitions),
                  icon: const Icon(Icons.add, size: 18),
                  label: const Text('New Partition'),
                ),
              ],
            ),
            const SizedBox(height: 20),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    decoration: const InputDecoration(
                      hintText: 'Search partitions...',
                      prefixIcon: Icon(Icons.search, size: 20),
                      isDense: true,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                OutlinedButton.icon(
                  onPressed: () {},
                  icon: const Icon(Icons.filter_list, size: 18),
                  label: const Text('Filter'),
                ),
                const SizedBox(width: 8),
                OutlinedButton.icon(
                  onPressed: () => ref.invalidate(partitionsProvider),
                  icon: const Icon(Icons.refresh, size: 18),
                  label: const Text('Refresh'),
                ),
              ],
            ),
            const SizedBox(height: 16),
            PartitionTreeView(partitions: partitions),
          ],
        ),
      ),
    );
  }
}
