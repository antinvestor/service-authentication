import 'package:flutter/material.dart';
import 'package:protobuf/protobuf.dart' show ProtobufEnum;

/// Reusable badge for displaying protobuf STATE values.
///
/// Uses [Theme] colors instead of hard-coded palette so the badge adapts
/// to the host application's theme.
class TenancyStateBadge extends StatelessWidget {
  const TenancyStateBadge(this.state, {super.key});

  final ProtobufEnum state;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final (label, color) = switch (state.name) {
      'ACTIVE' => ('ACTIVE', Colors.green),
      'INACTIVE' => ('INACTIVE', theme.colorScheme.onSurfaceVariant),
      'DELETED' => ('DELETED', theme.colorScheme.error),
      _ => (state.name, theme.colorScheme.onSurfaceVariant),
    };

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        label,
        style: theme.textTheme.labelSmall?.copyWith(
              color: color,
              fontWeight: FontWeight.w600,
            ),
      ),
    );
  }
}

/// Badge for TenantEnvironment enum.
class EnvironmentBadge extends StatelessWidget {
  const EnvironmentBadge(this.label, {super.key});

  final String label;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final color = label.contains('PRODUCTION')
        ? theme.colorScheme.tertiary
        : label.contains('STAGING')
            ? Colors.orange
            : theme.colorScheme.onSurfaceVariant;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        label.replaceAll('TENANT_ENVIRONMENT_', ''),
        style: theme.textTheme.labelSmall?.copyWith(
              color: color,
              fontWeight: FontWeight.w600,
            ),
      ),
    );
  }
}

/// Generic colored badge.
class ColorBadge extends StatelessWidget {
  const ColorBadge(this.label, this.color, {super.key});

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
