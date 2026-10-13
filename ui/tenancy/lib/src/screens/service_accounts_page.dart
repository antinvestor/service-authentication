import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Placeholder page for Service Accounts management.
///
/// The ServiceAccount RPCs are not yet available in the current version
/// of `antinvestor_api_tenancy`. This page will be implemented once
/// the API is updated.
class ServiceAccountsPage extends ConsumerWidget {
  const ServiceAccountsPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.engineering_outlined, size: 48,
              color: theme.colorScheme.onSurfaceVariant),
          const SizedBox(height: 16),
          Text(
            'Service Accounts',
            style: theme.textTheme.titleLarge
                ?.copyWith(fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 8),
          Text(
            'Service account management will be available in a future API update.',
            style: theme.textTheme.bodyMedium
                ?.copyWith(color: theme.colorScheme.onSurfaceVariant),
          ),
        ],
      ),
    );
  }
}
