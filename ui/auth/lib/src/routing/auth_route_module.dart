import 'package:antinvestor_ui_core/navigation/nav_items.dart';
import 'package:antinvestor_ui_core/permissions/permission_manifest.dart';
import 'package:antinvestor_ui_core/routing/route_module.dart';
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../screens/login_event_detail_screen.dart';
import '../screens/login_history_screen.dart';

/// Route module for the Authentication service UI.
///
/// Provides routes for viewing login history and event details.
/// The host application merges these into its router:
/// ```dart
/// final modules = [AuthRouteModule(), ...];
/// ShellRoute(
///   routes: [...ownRoutes, for (final m in modules) ...m.buildRoutes()],
/// )
/// ```
class AuthRouteModule extends RouteModule {
  @override
  String get moduleId => 'auth';

  @override
  List<RouteBase> buildRoutes() => [
        GoRoute(
          path: '/services/auth',
          builder: (context, state) => const LoginHistoryScreen(),
          routes: [
            GoRoute(
              path: ':eventId',
              builder: (context, state) => LoginEventDetailScreen(
                eventId: state.pathParameters['eventId']!,
              ),
            ),
          ],
        ),
      ];

  @override
  List<NavItem> buildNavItems() => [
        const NavItem(
          id: 'auth',
          label: 'Sign-in Activity',
          icon: Icons.login_outlined,
          activeIcon: Icons.login,
          route: '/services/auth',
          requiredPermissions: {'auth_view_own'},
        ),
      ];

  @override
  Map<String, Set<String>> get routePermissions => {
        '/services/auth': {'auth_view_own'},
      };

  @override
  PermissionManifest get permissionManifest => const PermissionManifest(
        namespace: 'service_authentication',
        permissions: [
          PermissionEntry(
            key: 'auth_view_own',
            label: 'View Own Login History',
            scope: PermissionScope.service,
          ),
          PermissionEntry(
            key: 'auth_view_all',
            label: 'View All Login History',
            scope: PermissionScope.service,
          ),
        ],
      );
}
