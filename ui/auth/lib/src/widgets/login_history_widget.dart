import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/auth_providers.dart';
import 'login_event_tile.dart';

/// Shows recent login activity for a specific user. Drop this into ANY
/// profile detail screen to show sign-in history.
///
/// Usage:
/// ```dart
/// // In a profile detail screen:
/// LoginHistoryWidget(profileId: user.id)
///
/// // Limit entries:
/// LoginHistoryWidget(profileId: user.id, maxEntries: 5)
/// ```
class LoginHistoryWidget extends ConsumerStatefulWidget {
  const LoginHistoryWidget({
    super.key,
    required this.profileId,
    this.maxEntries = 20,
    this.title = 'Recent Sign-ins',
  });

  /// The profile ID to show login history for.
  final String profileId;

  /// Maximum number of entries to fetch.
  final int maxEntries;

  /// Title shown in the widget header.
  final String title;

  @override
  ConsumerState<LoginHistoryWidget> createState() =>
      _LoginHistoryWidgetState();
}

class _LoginHistoryWidgetState extends ConsumerState<LoginHistoryWidget> {
  bool _expanded = false;
  static const _collapsedCount = 5;

  LoginEventListParams get _params => LoginEventListParams(
        profileId: widget.profileId,
        count: widget.maxEntries,
      );

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final surfaceColor = theme.colorScheme.surface;
    final borderColor = theme.colorScheme.outlineVariant;
    final asyncEvents = ref.watch(loginEventsProvider(_params));

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
          // Header
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 8, 8),
            child: Row(
              children: [
                Icon(Icons.login, size: 18, color: theme.colorScheme.primary),
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
                      ref.invalidate(loginEventsProvider(_params)),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          // Content
          asyncEvents.when(
            loading: () => const Padding(
              padding: EdgeInsets.all(24),
              child: Center(child: CircularProgressIndicator()),
            ),
            error: (error, _) => Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                'Could not load login history: $error',
                style: TextStyle(color: theme.colorScheme.error),
              ),
            ),
            data: (events) {
              if (events.isEmpty) {
                return Padding(
                  padding: const EdgeInsets.all(24),
                  child: Center(
                    child: Text(
                      'No sign-in activity recorded',
                      style: TextStyle(
                          color: theme.colorScheme.onSurfaceVariant),
                    ),
                  ),
                );
              }

              final visible = _expanded
                  ? events
                  : events.take(_collapsedCount).toList();
              final hasMore = events.length > _collapsedCount;

              return Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  for (final event in visible)
                    LoginEventTile(
                      event: event,
                      dense: true,
                      onTap: () =>
                          context.go('/services/auth/${event.id}'),
                    ),
                  if (hasMore)
                    InkWell(
                      onTap: () =>
                          setState(() => _expanded = !_expanded),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(
                            vertical: 10, horizontal: 16),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              _expanded
                                  ? Icons.expand_less
                                  : Icons.expand_more,
                              size: 18,
                              color: theme.colorScheme.primary,
                            ),
                            const SizedBox(width: 4),
                            Text(
                              _expanded
                                  ? 'Show less'
                                  : 'Show ${events.length - _collapsedCount} more',
                              style: theme.textTheme.labelMedium?.copyWith(
                                color: theme.colorScheme.primary,
                              ),
                            ),
                          ],
                        ),
                      ),
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
