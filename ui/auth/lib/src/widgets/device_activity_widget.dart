import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/auth_providers.dart';
import 'login_event_tile.dart';

/// Shows login activity from a specific device. Embed in device
/// detail screens to see all sign-in attempts from that device.
///
/// Usage:
/// ```dart
/// // In a device detail screen:
/// DeviceActivityWidget(deviceId: device.id)
/// ```
class DeviceActivityWidget extends ConsumerWidget {
  const DeviceActivityWidget({
    super.key,
    required this.deviceId,
    this.maxItems = 10,
    this.title = 'Device Sign-ins',
  });

  /// The device ID to show activity for.
  final String deviceId;

  /// Maximum number of entries to show.
  final int maxItems;

  /// Title shown in the widget header.
  final String title;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final surfaceColor = theme.colorScheme.surface;
    final borderColor = theme.colorScheme.outlineVariant;

    final params = LoginEventListParams(deviceId: deviceId, count: maxItems);
    final asyncEvents = ref.watch(loginEventsProvider(params));

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
                Icon(Icons.devices_outlined,
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
                      ref.invalidate(loginEventsProvider(params)),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          asyncEvents.when(
            loading: () => const Padding(
              padding: EdgeInsets.all(24),
              child: Center(child: CircularProgressIndicator()),
            ),
            error: (error, _) => Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                'Could not load device activity: $error',
                style: TextStyle(color: theme.colorScheme.error),
              ),
            ),
            data: (events) {
              if (events.isEmpty) {
                return Padding(
                  padding: const EdgeInsets.all(24),
                  child: Center(
                    child: Text(
                      'No sign-in activity from this device',
                      style: TextStyle(
                          color: theme.colorScheme.onSurfaceVariant),
                    ),
                  ),
                );
              }

              return Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  for (final event in events)
                    LoginEventTile(
                      event: event,
                      dense: true,
                      showDevice: false,
                      onTap: () =>
                          context.go('/services/auth/${event.id}'),
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
