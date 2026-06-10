import 'dart:convert';

import 'package:antinvestor_api_audit/antinvestor_api_audit.dart';
import 'package:antinvestor_ui_audit/antinvestor_ui_audit.dart';
import 'package:antinvestor_ui_core/antinvestor_ui_core.dart';
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

  List<AuditEntryObject> sampleEntries() => [
    AuditEntryObject(
      id: 'a1',
      profileId: 'p1',
      action: 'create',
      resourceType: 'tenant',
      service: 'tenancy',
    ),
    AuditEntryObject(
      id: 'a2',
      profileId: 'p2',
      action: 'delete',
      resourceType: 'partition',
      service: 'tenancy',
    ),
    AuditEntryObject(
      id: 'a3',
      profileId: 'p1',
      action: 'login',
      resourceType: 'session',
      service: 'auth',
    ),
  ];

  Future<void> pumpScreen(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1600, 2600);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(
      ProviderScope(
        // Disable Riverpod's automatic retry so failed gate queries settle
        // in their error state instead of flipping back to loading.
        retry: (retryCount, error) => null,
        overrides: [
          auditEntriesProvider.overrideWith(
            (ref, params) => Future.value(sampleEntries()),
          ),
          analyticsDataSourceProvider.overrideWithValue(
            ThesaAnalyticsDataSource(
              transport.call,
              specs: const [auditAnalyticsSpec],
            ),
          ),
        ],
        child: const MaterialApp(home: Scaffold(body: AuditAnalyticsScreen())),
      ),
    );
    await tester.pumpAndSettle();
  }

  testWidgets('keeps entry-derived KPI tiles', (tester) async {
    await pumpScreen(tester);

    expect(find.text('Total Entries'), findsOneWidget);
    expect(find.text('Unique Actors'), findsOneWidget);
    expect(find.text('2'), findsAtLeastNWidgets(1)); // unique actors/services
    expect(find.text('Unique Services'), findsOneWidget);
  });

  testWidgets('renders the gate-backed request activity trend', (tester) async {
    transport.handler = (path, body) {
      expect(path, '/api/analytics/query/timeseries');
      expect(body['metric'], auditCompletedCallsMetric);
      return http.Response(
        json.encode({
          'points': [
            {'timestamp': '2026-06-01T00:00:00Z', 'value': 10},
            {'timestamp': '2026-06-02T00:00:00Z', 'value': 14},
          ],
        }),
        200,
      );
    };

    await pumpScreen(tester);

    expect(find.text('Request Activity'), findsOneWidget);
    expect(find.byType(TimeSeriesChart), findsOneWidget);
    expect(find.text('No data'), findsNothing);
  });

  testWidgets('shows an empty trend state when the gate has no data', (
    tester,
  ) async {
    await pumpScreen(tester);

    expect(find.text('Request Activity'), findsOneWidget);
    expect(find.text('No data'), findsOneWidget);
  });

  for (final (status, fragment) in [
    (400, 'not available from the analytics gate'),
    (403, 'not available for your current sign-in scope'),
    (503, 'temporarily unavailable'),
  ]) {
    testWidgets('renders friendly state for gate HTTP $status', (tester) async {
      transport.handler = (path, body) =>
          http.Response(json.encode({'error': 'gate says no'}), status);

      await pumpScreen(tester);

      expect(find.textContaining(fragment), findsOneWidget);
      expect(find.textContaining('gate says no'), findsNothing);
      expect(find.text('Retry'), findsOneWidget);
      // Entity-derived KPIs are unaffected by gate failures.
      expect(find.text('Total Entries'), findsOneWidget);
    });
  }
}
