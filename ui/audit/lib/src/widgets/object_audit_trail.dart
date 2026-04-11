import 'package:antinvestor_api_audit/antinvestor_api_audit.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/audit_export_helper.dart';
import '../providers/audit_providers.dart';
import 'audit_entry_tile.dart';

/// Shows all audit entries for a specific object. Drop this into ANY
/// detail screen to see the complete history of actions on that object.
///
/// Usage:
/// ```dart
/// // In a profile detail screen:
/// ObjectAuditTrail(resourceType: 'profile', resourceId: profileId)
///
/// // In a payment detail screen:
/// ObjectAuditTrail(resourceType: 'payment', resourceId: paymentId)
///
/// // In a file detail screen:
/// ObjectAuditTrail(resourceType: 'file', resourceId: contentId)
/// ```
class ObjectAuditTrail extends ConsumerStatefulWidget {
  const ObjectAuditTrail({
    super.key,
    required this.resourceType,
    required this.resourceId,
    this.maxEntries = 50,
    this.showExportButton = true,
  });

  /// The type of resource to show audit entries for (e.g. 'profile', 'payment').
  final String resourceType;

  /// The ID of the specific resource.
  final String resourceId;

  /// Maximum number of entries to fetch.
  final int maxEntries;

  /// Whether to show the CSV export button.
  final bool showExportButton;

  @override
  ConsumerState<ObjectAuditTrail> createState() => _ObjectAuditTrailState();
}

class _ObjectAuditTrailState extends ConsumerState<ObjectAuditTrail> {
  bool _expanded = false;
  static const _collapsedCount = 10;

  AuditListParams get _params => AuditListParams(
        resourceType: widget.resourceType,
        resourceId: widget.resourceId,
        count: widget.maxEntries,
      );

  void _exportCsv(List<AuditEntryObject> entries) {
    // Create CSV content
    final buffer = StringBuffer();
    buffer.writeln(
        'Timestamp,Action,Actor,Service,IP Address,Device ID,Trace ID');
    for (final entry in entries) {
      final ts = entry.hasCreatedAt()
          ? DateTime.fromMillisecondsSinceEpoch(
                  entry.createdAt.seconds.toInt() * 1000)
              .toIso8601String()
          : '';
      buffer.writeln(
          '$ts,${entry.action},${entry.profileId},${entry.service},${entry.ipAddress},${entry.deviceId},${entry.traceId}');
    }

    // Log the export as an audit entry itself.
    logExport(
      ref,
      resourceType: widget.resourceType,
      rowCount: entries.length,
      format: 'csv',
    );

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
              'Exported ${entries.length} entries for ${widget.resourceType}'),
        ),
      );
    }
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
          // Header
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 8, 8),
            child: Row(
              children: [
                Icon(Icons.history,
                    size: 18, color: theme.colorScheme.primary),
                const SizedBox(width: 8),
                Text(
                  'Activity History',
                  style: theme.textTheme.titleSmall
                      ?.copyWith(fontWeight: FontWeight.w600),
                ),
                const Spacer(),
                if (widget.showExportButton)
                  asyncEntries.whenOrNull(
                        data: (entries) => entries.isNotEmpty
                            ? IconButton(
                                icon: const Icon(Icons.download_outlined,
                                    size: 18),
                                tooltip: 'Export CSV',
                                onPressed: () => _exportCsv(entries),
                              )
                            : null,
                      ) ??
                      const SizedBox.shrink(),
              ],
            ),
          ),
          const Divider(height: 1),
          // Content
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
                      'No activity recorded',
                      style: TextStyle(
                          color: theme.colorScheme.onSurfaceVariant),
                    ),
                  ),
                );
              }

              final visible = _expanded
                  ? entries
                  : entries.take(_collapsedCount).toList();
              final hasMore = entries.length > _collapsedCount;

              return Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  // Timeline of entries
                  for (final entry in visible)
                    AuditEntryTile(
                      entry: entry,
                      dense: true,
                      onTap: () =>
                          context.go('/services/audit/${entry.id}'),
                    ),
                  // Show more/less toggle
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
                                  : 'Show ${entries.length - _collapsedCount} more',
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
