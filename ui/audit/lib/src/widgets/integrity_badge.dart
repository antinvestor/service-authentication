import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../providers/audit_providers.dart';

/// A compact badge indicating hash chain integrity status.
///
/// Shows a green "Verified" or red "Integrity Issue" badge based on
/// the result of the integrity verification provider.
///
/// Usage:
/// ```dart
/// IntegrityBadge(
///   startDate: DateTime.now().subtract(Duration(days: 7)),
///   endDate: DateTime.now(),
/// )
/// ```
class IntegrityBadge extends ConsumerWidget {
  const IntegrityBadge({
    super.key,
    required this.startDate,
    required this.endDate,
  });

  /// Start of the date range to verify.
  final DateTime startDate;

  /// End of the date range to verify.
  final DateTime endDate;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final range = DateRange(start: startDate, end: endDate);
    final asyncResult = ref.watch(verifyIntegrityProvider(range));

    return asyncResult.when(
      loading: () => Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            SizedBox(
              width: 12,
              height: 12,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(width: 6),
            Text(
              'Verifying...',
              style: theme.textTheme.labelSmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
      error: (_, __) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        decoration: BoxDecoration(
          color: Colors.orange.shade50,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.warning_amber, size: 14, color: Colors.orange.shade700),
            const SizedBox(width: 4),
            Text(
              'Check Failed',
              style: theme.textTheme.labelSmall?.copyWith(
                color: Colors.orange.shade700,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
      data: (result) {
        final isValid = result.valid;
        final color = isValid ? Colors.green.shade600 : theme.colorScheme.error;
        final bgColor = isValid
            ? Colors.green.shade50
            : theme.colorScheme.errorContainer;
        final icon = isValid ? Icons.verified : Icons.error_outline;
        final label = isValid
            ? 'Verified (${result.entriesVerified})'
            : 'Integrity Issue';

        return Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
          decoration: BoxDecoration(
            color: bgColor,
            borderRadius: BorderRadius.circular(12),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon, size: 14, color: color),
              const SizedBox(width: 4),
              Text(
                label,
                style: theme.textTheme.labelSmall?.copyWith(
                  color: color,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}
