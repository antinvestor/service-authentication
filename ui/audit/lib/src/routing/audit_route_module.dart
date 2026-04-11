import 'package:antinvestor_ui_core/navigation/nav_items.dart';
import 'package:antinvestor_ui_core/routing/route_module.dart';
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../screens/audit_analytics_screen.dart';
import '../screens/audit_detail_screen.dart';
import '../screens/audit_log_screen.dart';
import '../screens/integrity_check_screen.dart';

/// Route module for the Audit service UI.
///
/// Provides routes for the audit log, analytics dashboard, entry detail,
/// and integrity verification. The host application merges these into
/// its router:
/// ```dart
/// final modules = [AuditRouteModule(), ...];
/// ShellRoute(
///   routes: [...ownRoutes, for (final m in modules) ...m.buildRoutes()],
/// )
/// ```
class AuditRouteModule extends RouteModule {
  @override
  String get moduleId => 'audit';

  @override
  List<RouteBase> buildRoutes() => [
        GoRoute(
          path: '/services/audit',
          builder: (context, state) => const AuditAnalyticsScreen(),
          routes: [
            GoRoute(
              path: 'log',
              builder: (context, state) => const AuditLogScreen(),
            ),
            GoRoute(
              path: 'integrity',
              builder: (context, state) => const IntegrityCheckScreen(),
            ),
            GoRoute(
              path: ':entryId',
              builder: (context, state) => AuditDetailScreen(
                entryId: state.pathParameters['entryId']!,
              ),
            ),
          ],
        ),
      ];

  @override
  List<NavItem> buildNavItems() => [
        const NavItem(
          id: 'audit',
          label: 'Audit Trail',
          icon: Icons.history_outlined,
          activeIcon: Icons.history,
          route: '/services/audit',
          children: [
            NavItem(
              id: 'audit_log',
              label: 'Audit Log',
              icon: Icons.list_alt_outlined,
              activeIcon: Icons.list_alt,
              route: '/services/audit/log',
            ),
            NavItem(
              id: 'audit_integrity',
              label: 'Integrity Check',
              icon: Icons.verified_outlined,
              activeIcon: Icons.verified,
              route: '/services/audit/integrity',
            ),
          ],
        ),
      ];

  @override
  Map<String, Set<String>> get routePermissions => {
        '/services/audit': {'admin', 'owner', 'internal', 'audit_view'},
        '/services/audit/integrity': {
          'admin',
          'owner',
          'internal',
          'audit_verify'
        },
      };
}
