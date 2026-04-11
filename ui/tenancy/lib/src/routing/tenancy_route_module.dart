import 'package:antinvestor_ui_core/navigation/nav_items.dart';
import 'package:antinvestor_ui_core/permissions/permission_manifest.dart';
import 'package:antinvestor_ui_core/routing/route_module.dart';
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../screens/partition_analytics_page.dart';
import '../screens/partition_detail_page.dart';
import '../screens/partitions_page.dart';
import '../screens/tenant_detail_page.dart';
import '../screens/tenants_page.dart';

/// Route module for the Tenancy service UI.
///
/// Provides routes for tenants, partitions, and the tenancy analytics
/// dashboard. The host application merges these into its router:
/// ```dart
/// final modules = [TenancyRouteModule(), ...];
/// ShellRoute(
///   routes: [...ownRoutes, for (final m in modules) ...m.buildRoutes()],
/// )
/// ```
class TenancyRouteModule extends RouteModule {
  @override
  String get moduleId => 'tenancy';

  @override
  List<RouteBase> buildRoutes() => [
        GoRoute(
          path: '/services/tenancy',
          builder: (context, state) => const PartitionAnalyticsPage(),
          routes: [
            GoRoute(
              path: 'tenants',
              builder: (context, state) => const TenantsPage(),
              routes: [
                GoRoute(
                  path: ':tenantId',
                  builder: (context, state) => TenantDetailPage(
                    tenantId: state.pathParameters['tenantId']!,
                  ),
                ),
              ],
            ),
            GoRoute(
              path: 'partitions',
              builder: (context, state) => const PartitionsPage(),
              routes: [
                GoRoute(
                  path: ':partitionId',
                  builder: (context, state) => PartitionDetailPage(
                    partitionId: state.pathParameters['partitionId']!,
                  ),
                ),
              ],
            ),
          ],
        ),
      ];

  @override
  List<NavItem> buildNavItems() => [
        const NavItem(
          id: 'tenancy',
          label: 'Tenancy',
          icon: Icons.hub_outlined,
          activeIcon: Icons.hub,
          route: '/services/tenancy',
          requiredPermissions: {'tenancy_view'},
          children: [
            NavItem(
              id: 'tenants',
              label: 'Tenants',
              icon: Icons.domain_outlined,
              activeIcon: Icons.domain,
              route: '/services/tenancy/tenants',
              requiredPermissions: {'tenancy_view'},
            ),
            NavItem(
              id: 'partitions',
              label: 'Partitions',
              icon: Icons.account_tree_outlined,
              activeIcon: Icons.account_tree,
              route: '/services/tenancy/partitions',
              requiredPermissions: {'partition_view'},
            ),
          ],
        ),
      ];

  @override
  Map<String, Set<String>> get routePermissions => {
        '/services/tenancy': {'tenancy_view'},
        '/services/tenancy/tenants': {'tenancy_view'},
        '/services/tenancy/partitions': {'partition_view'},
      };

  @override
  PermissionManifest get permissionManifest => const PermissionManifest(
        namespace: 'service_tenancy',
        permissions: [
          PermissionEntry(
            key: 'tenancy_view',
            label: 'View Tenants',
            scope: PermissionScope.service,
          ),
          PermissionEntry(
            key: 'tenancy_create',
            label: 'Create Tenants',
            scope: PermissionScope.action,
          ),
          PermissionEntry(
            key: 'tenancy_update',
            label: 'Update Tenants',
            scope: PermissionScope.action,
          ),
          PermissionEntry(
            key: 'partition_view',
            label: 'View Partitions',
            scope: PermissionScope.feature,
          ),
          PermissionEntry(
            key: 'partition_create',
            label: 'Create Partitions',
            scope: PermissionScope.action,
          ),
        ],
      );
}
