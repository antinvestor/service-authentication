import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/audit_providers.dart';
import 'audit_entry_tile.dart';

/// Shows recent activity by a specific user/actor. Embed in profile
/// detail screens to see what a user has been doing.
///
/// Usage:
/// ```dart
/// // In a profile detail screen:
/// ActorActivityWidget(profileId: user.id)
///
/// // Limit entries and hide service badge:
/// ActorActivityWidget(profileId: user.id, maxItems: 5)
/// ```
class ActorActivityWidget extends ConsumerWidget {
  const ActorActivityWidget({
    super.key,
    required this.profileId,
    this.maxItems = 10,
    this.title = 'Recent Activity',
  });

  /// The profile ID of the actor whose activity to display.
  final String profileId;

  /// Maximum number of entries to show.
  final int maxItems;

  /// Title shown in the widget header.
  final String title;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final surfaceColor = theme.colorScheme.surface;
    final borderColor = theme.colorScheme.outlineVariant;

    final params = AuditListParams(profileId: profileId, count: maxItems);
    final asyncEntries = ref.watch(auditEntriesProvider(params));

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
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 8, 8),
            child: Row(
              children: [
                Icon(Icons.person_outline,
                    size: 18, color: theme.colorScheme.primary),
                const SizedBox(width: 8),
                Text(
                  title,
                  style: theme.textTheme.titleSmall
                      ?.copyWith(fontWeight: FontWeight.w600),
                ),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.refresh, size: 18),
                  tooltip: 'Refresh',
                  onPressed: () =>
                      ref.invalidate(auditEntriesProvider(params)),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          asyncEntries.when(
            loading: () => const Padding(
              padding: EdgeInsets.all(24),
              child: Center(child: CircularProgressIndicator()),
            ),
            error: (error, _) => Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                'Could not load activity: $error',
                style: TextStyle(color: theme.colorScheme.error),
              ),
            ),
            data: (entries) {
              if (entries.isEmpty) {
                return Padding(
                  padding: const EdgeInsets.all(24),
                  child: Center(
                    child: Text(
                      'No activity recorded for this user',
                      style: TextStyle(
                          color: theme.colorScheme.onSurfaceVariant),
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
                      showService: true,
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
