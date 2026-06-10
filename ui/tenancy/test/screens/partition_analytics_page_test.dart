import 'dart:convert';

import 'package:antinvestor_api_tenancy/antinvestor_api_tenancy.dart';
import 'package:antinvestor_ui_core/antinvestor_ui_core.dart';
import 'package:antinvestor_ui_tenancy/antinvestor_ui_tenancy.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

import '../_helpers/fake_analytics_transport.dart';

void main() {
  late FakeAnalyticsTransport transport;

  setUp(() {
    transport = FakeAnalyticsTransport();
  });

  final tenants = [
    TenantObject(id: 't1', name: 'Acme Group', state: STATE.ACTIVE),
    TenantObject(id: 't2', name: 'Umbrella Ltd', state: STATE.ACTIVE),
  ];
  final partitions = [
    PartitionObject(id: 'p1', name: 'HQ', tenantId: 't1'),
    PartitionObject(id: 'p2', name: 'Branch', tenantId: 't1'),
    PartitionObject(id: 'p3', name: 'Main', tenantId: 't2'),
  ];
  final roles = [PartitionRoleObject(partitionId: 'p1', name: 'admin')];

  Future<void> pumpPage(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1600, 2400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(
      ProviderScope(
        // Disable Riverpod's automatic retry so failed gate queries settle
        // in their error state instead of flipping back to loading.
        retry: (retryCount, error) => null,
        overrides: [
          tenantsProvider.overrideWith((ref) => Future.value(tenants)),
          partitionsProvider.overrideWith((ref) => Future.value(partitions)),
          partitionRolesProvider.overrideWith((ref) => Future.value(roles)),
          analyticsDataSourceProvider.overrideWithValue(
            ThesaAnalyticsDataSource(
              transport.call,
              specs: const [tenancyAnalyticsSpec],
            ),
          ),
        ],
        child: const MaterialApp(
          home: Scaffold(body: PartitionAnalyticsPage()),
        ),
      ),
    );
    await tester.pumpAndSettle();
  }

  testWidgets('keeps entity-derived KPI counts', (tester) async {
    await pumpPage(tester);

    expect(find.text('Total Tenants'), findsOneWidget);
    expect(find.text('2'), findsAtLeastNWidgets(1));
    expect(find.text('Total Partitions'), findsOneWidget);
    expect(find.text('3'), findsAtLeastNWidgets(1));
    expect(find.text('Total Roles'), findsOneWidget);
    expect(find.text('1'), findsAtLeastNWidgets(1));
  });

  testWidgets('renders the growth trend from the gate timeseries', (
    tester,
  ) async {
    transport.handler = (path, body) {
      expect(path, '/api/analytics/query/timeseries');
      expect(body['metric'], organizationsCreatedMetric);
      expect(body['step'], 'month');
      return http.Response(
        json.encode({
          'points': [
            {'timestamp': '2026-01-01T00:00:00Z', 'value': 4},
            {'timestamp': '2026-02-01T00:00:00Z', 'value': 7},
          ],
        }),
        200,
      );
    };

    await pumpPage(tester);

    expect(find.text('Organization Growth'), findsOneWidget);
    expect(find.byType(TimeSeriesChart), findsOneWidget);
    expect(find.text('No data'), findsNothing);
  });

  testWidgets('mock growth and tenant fixtures are gone', (tester) async {
    await pumpPage(tester);

    // The fake hard-coded table rows from the previous implementation.
    expect(find.text('Vortex Dynamics'), findsNothing);
    expect(find.text('Nexus Logistics'), findsNothing);
    expect(find.text('Atlas Industries'), findsNothing);
    // Empty gate response renders an honest empty state, not fake bars.
    expect(find.text('No data'), findsOneWidget);
  });

  testWidgets('ranks real tenants by partition count', (tester) async {
    await pumpPage(tester);

    expect(find.text('Largest Tenants'), findsOneWidget);
    expect(find.text('Acme Group'), findsOneWidget);
    expect(find.text('Umbrella Ltd'), findsOneWidget);

    // Acme (2 partitions) is ranked above Umbrella (1 partition).
    final acmeY = tester.getTopLeft(find.text('Acme Group')).dy;
    final umbrellaY = tester.getTopLeft(find.text('Umbrella Ltd')).dy;
    expect(acmeY, lessThan(umbrellaY));
  });

  for (final (status, fragment) in [
    (400, 'not available from the analytics gate'),
    (403, 'not available for your current sign-in scope'),
    (503, 'temporarily unavailable'),
  ]) {
    testWidgets('renders friendly state for gate HTTP $status', (tester) async {
      transport.handler = (path, body) =>
          http.Response(json.encode({'error': 'gate says no'}), status);

      await pumpPage(tester);

      expect(find.textContaining(fragment), findsOneWidget);
      expect(find.textContaining('gate says no'), findsNothing);
      expect(find.text('Retry'), findsOneWidget);
      // Entity-derived KPIs and the tenant table are unaffected.
      expect(find.text('Total Tenants'), findsOneWidget);
      expect(find.text('Largest Tenants'), findsOneWidget);
    });
  }
}
