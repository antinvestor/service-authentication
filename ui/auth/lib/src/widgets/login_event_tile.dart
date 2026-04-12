import 'package:antinvestor_api_authentication/antinvestor_api_authentication.dart';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

/// Compact tile for a single login event. Displays a source icon,
/// description, IP address, and relative timestamp.
///
/// Used by [LoginHistoryWidget] and [DeviceActivityWidget].
class LoginEventTile extends StatelessWidget {
  const LoginEventTile({
    super.key,
    required this.event,
    this.onTap,
    this.dense = false,
    this.showDevice = true,
  });

  final LoginEventObject event;
  final VoidCallback? onTap;
  final bool dense;
  final bool showDevice;

  static IconData iconForSource(String source) => switch (source) {
        'direct' => Icons.email_outlined,
        'google' => Icons.g_mobiledata,
        'facebook' => Icons.facebook_outlined,
        'service_account' => Icons.smart_toy_outlined,
        'session_refresh' => Icons.refresh,
        _ => Icons.login,
      };

  static Color colorForSource(String source, ThemeData theme) =>
      switch (source) {
        'direct' => theme.colorScheme.primary,
        'google' => Colors.red.shade600,
        'facebook' => Colors.blue.shade700,
        'service_account' => Colors.purple.shade600,
        'session_refresh' => Colors.grey.shade600,
        _ => theme.colorScheme.onSurfaceVariant,
      };

  static String labelForSource(String source) => switch (source) {
        'direct' => 'Email/Phone',
        'google' => 'Google',
        'facebook' => 'Facebook',
        'service_account' => 'Service Account',
        'session_refresh' => 'Token Refresh',
        _ => 'Sign In',
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

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final source = event.source.isNotEmpty ? event.source : 'unknown';
    final color = colorForSource(source, theme);
    final icon = iconForSource(source);
    final label = labelForSource(source);
    final mutedColor = theme.colorScheme.onSurfaceVariant;

    final ipLabel = event.ipAddress.isNotEmpty ? event.ipAddress : 'Unknown IP';
    final isSuccess = event.status == 0;

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
                  Row(
                    children: [
                      Text(
                        label,
                        style: (dense
                                ? theme.textTheme.bodySmall
                                : theme.textTheme.bodyMedium)
                            ?.copyWith(fontWeight: FontWeight.w500),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      if (!isSuccess) ...[
                        const SizedBox(width: 6),
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 4, vertical: 1),
                          decoration: BoxDecoration(
                            color: theme.colorScheme.errorContainer,
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            'Failed',
                            style: theme.textTheme.labelSmall?.copyWith(
                              color: theme.colorScheme.onErrorContainer,
                              fontSize: 9,
                            ),
                          ),
                        ),
                      ],
                    ],
                  ),
                  const SizedBox(height: 2),
                  Text(
                    '$ipLabel \u00b7 ${_formatRelativeTime(event.createdAt)}',
                    style: theme.textTheme.labelSmall
                        ?.copyWith(color: mutedColor),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            if (showDevice && event.deviceId.isNotEmpty) ...[
              const SizedBox(width: 8),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: theme.colorScheme.secondaryContainer,
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  event.deviceId.substring(
                      0, event.deviceId.length.clamp(0, 8)),
                  style: theme.textTheme.labelSmall?.copyWith(
                    color: theme.colorScheme.onSecondaryContainer,
                    fontSize: 10,
                    fontFamily: 'monospace',
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
