import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/audit_providers.dart';
import 'audit_entry_tile.dart';

/// A dynamic list showing recent system activity. Embed in dashboards
/// or sidebars to show real-time user actions.
///
/// Usage:
/// ```dart
/// // Show all recent activity:
/// LiveActivityFeed(maxItems: 20)
///
/// // Show activity for a specific service:
/// LiveActivityFeed(service: 'service_payment', maxItems: 10)
/// ```
class LiveActivityFeed extends ConsumerStatefulWidget {
  const LiveActivityFeed({
    super.key,
    this.service = '',
    this.maxItems = 20,
    this.refreshInterval = const Duration(seconds: 30),
    this.title = 'Recent Activity',
    this.showHeader = true,
  });

  /// Filter to a specific service (empty = all services).
  final String service;

  /// Maximum number of items to display.
  final int maxItems;

  /// How often to auto-refresh the feed.
  final Duration refreshInterval;

  /// Title shown in the header.
  final String title;

  /// Whether to show the header with title and refresh button.
  final bool showHeader;

  @override
  ConsumerState<LiveActivityFeed> createState() => _LiveActivityFeedState();
}

class _LiveActivityFeedState extends ConsumerState<LiveActivityFeed> {
  Timer? _refreshTimer;

  AuditListParams get _params => AuditListParams(
        service: widget.service,
        count: widget.maxItems,
      );

  @override
  void initState() {
    super.initState();
    _refreshTimer = Timer.periodic(widget.refreshInterval, (_) {
      if (mounted) {
        ref.invalidate(auditEntriesProvider(_params));
      }
    });
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final surfaceColor = theme.colorScheme.surface;
    final borderColor = theme.colorScheme.outlineVariant;
    final asyncEntries = ref.watch(auditEntriesProvider(_params));

    return Container(
      decoration: BoxDecoration(
        color: surfaceColor,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: borderColor),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          if (widget.showHeader) ...[
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 12, 8, 8),
              child: Row(
                children: [
                  Icon(Icons.bolt,
                      size: 18, color: theme.colorScheme.primary),
                  const SizedBox(width: 8),
                  Text(
                    widget.title,
                    style: theme.textTheme.titleSmall
                        ?.copyWith(fontWeight: FontWeight.w600),
                  ),
                  const Spacer(),
                  IconButton(
                    icon: const Icon(Icons.refresh, size: 18),
                    tooltip: 'Refresh',
                    onPressed: () =>
                        ref.invalidate(auditEntriesProvider(_params)),
                  ),
                ],
              ),
            ),
            const Divider(height: 1),
          ],
          asyncEntries.when(
            loading: () => const Padding(
              padding: EdgeInsets.all(24),
              child: Center(child: CircularProgressIndicator()),
            ),
            error: (error, _) => Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.error_outline,
                      size: 32, color: theme.colorScheme.error),
                  const SizedBox(height: 8),
                  Text(
                    'Could not load activity',
                    style: theme.textTheme.bodySmall
                        ?.copyWith(color: theme.colorScheme.error),
                  ),
                ],
              ),
            ),
            data: (entries) {
              if (entries.isEmpty) {
                return Padding(
                  padding: const EdgeInsets.all(24),
                  child: Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.inbox_outlined,
                            size: 32,
                            color: theme.colorScheme.onSurfaceVariant),
                        const SizedBox(height: 8),
                        Text(
                          'No recent activity',
                          style: TextStyle(
                              color: theme.colorScheme.onSurfaceVariant),
                        ),
                      ],
                    ),
                  ),
                );
              }

              return Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  for (final entry in entries)
                    AuditEntryTile(
                      entry: entry,
                      dense: true,
                      onTap: () =>
                          context.go('/services/audit/${entry.id}'),
                    ),
                ],
              );
            },
          ),
        ],
      ),
    );
  }
}
