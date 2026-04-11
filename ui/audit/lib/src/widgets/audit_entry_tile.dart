import 'package:antinvestor_api_audit/antinvestor_api_audit.dart';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

/// Compact tile for a single audit entry. Displays an action icon,
/// title, actor, relative timestamp, and a service badge.
///
/// Used by [ObjectAuditTrail], [LiveActivityFeed], and [ActorActivityWidget].
class AuditEntryTile extends StatelessWidget {
  const AuditEntryTile({
    super.key,
    required this.entry,
    this.onTap,
    this.showService = true,
    this.dense = false,
  });

  final AuditEntryObject entry;
  final VoidCallback? onTap;
  final bool showService;
  final bool dense;

  static IconData iconForAction(String action) => switch (action) {
        'create' => Icons.add_circle_outline,
        'update' => Icons.edit_outlined,
        'delete' => Icons.delete_outline,
        'login' => Icons.login,
        'export' => Icons.download_outlined,
        'grant_permission' => Icons.security_outlined,
        _ => Icons.circle_outlined,
      };

  static Color colorForAction(String action, ThemeData theme) =>
      switch (action) {
        'create' => Colors.green.shade600,
        'update' => theme.colorScheme.primary,
        'delete' => theme.colorScheme.error,
        'login' => Colors.blue.shade600,
        'export' => Colors.orange.shade600,
        'grant_permission' => Colors.purple.shade600,
        _ => theme.colorScheme.onSurfaceVariant,
      };

  String _formatRelativeTime(Timestamp ts) {
    if (!ts.hasSeconds()) return '-';
    final dt = DateTime.fromMillisecondsSinceEpoch(
      ts.seconds.toInt() * 1000 + ts.nanos ~/ 1000000,
    );
    final diff = DateTime.now().difference(dt);
    if (diff.inMinutes < 1) return 'just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    if (diff.inDays < 7) return '${diff.inDays}d ago';
    return DateFormat('MMM d').format(dt);
  }

  String _capitalize(String s) =>
      s.isEmpty ? s : '${s[0].toUpperCase()}${s.substring(1)}';

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final color = colorForAction(entry.action, theme);
    final icon = iconForAction(entry.action);
    final mutedColor = theme.colorScheme.onSurfaceVariant;

    final title =
        '${_capitalize(entry.action)} ${entry.resourceType.replaceAll('_', ' ')}';
    final actorLabel = entry.profileId.isNotEmpty
        ? entry.profileId.substring(
            0, entry.profileId.length.clamp(0, 8))
        : 'system';

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Padding(
        padding: EdgeInsets.symmetric(
          vertical: dense ? 6 : 10,
          horizontal: dense ? 8 : 12,
        ),
        child: Row(
          children: [
            Container(
              padding: EdgeInsets.all(dense ? 6 : 8),
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Icon(icon, size: dense ? 14 : 16, color: color),
            ),
            SizedBox(width: dense ? 8 : 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: (dense
                            ? theme.textTheme.bodySmall
                            : theme.textTheme.bodyMedium)
                        ?.copyWith(fontWeight: FontWeight.w500),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 2),
                  Text(
                    '$actorLabel \u00b7 ${_formatRelativeTime(entry.createdAt)}',
                    style: theme.textTheme.labelSmall
                        ?.copyWith(color: mutedColor),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            if (showService && entry.service.isNotEmpty) ...[
              const SizedBox(width: 8),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: theme.colorScheme.secondaryContainer,
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  entry.service.replaceFirst('service_', ''),
                  style: theme.textTheme.labelSmall?.copyWith(
                    color: theme.colorScheme.onSecondaryContainer,
                    fontSize: 10,
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
