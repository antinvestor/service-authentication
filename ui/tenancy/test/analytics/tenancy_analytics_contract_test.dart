import 'dart:convert';

import 'package:antinvestor_ui_core/antinvestor_ui_core.dart';
import 'package:antinvestor_ui_tenancy/antinvestor_ui_tenancy.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

import '../_helpers/fake_analytics_transport.dart';

void main() {
  final timeRange = AnalyticsTimeRange(
    start: DateTime.utc(2025, 6, 1),
    end: DateTime.utc(2026, 6, 1),
    granularity: TimeGranularity.month,
  );
  const wireTimeRange = {
    'start': '2025-06-01T00:00:00.000Z',
    'end': '2026-06-01T00:00:00.000Z',
  };

  late FakeAnalyticsTransport transport;
  late ThesaAnalyticsDataSource dataSource;

  setUp(() {
    transport = FakeAnalyticsTransport();
    dataSource = ThesaAnalyticsDataSource(
      transport.call,
      specs: const [tenancyAnalyticsSpec],
    );
  });

  test('growth trend posts an exact monthly timeseries body', () async {
    await dataSource.getTimeSeries(
      'tenancy',
      organizationsCreatedMetric,
      timeRange: timeRange,
    );

    expect(transport.calls, hasLength(1));
    expect(transport.calls.single.path, '/api/analytics/query/timeseries');
    expect(transport.calls.single.body, {
      'metric': 'identity_organizations_created_total',
      'aggregation': 'sum',
      'time_range': wireTimeRange,
      'step': 'month',
    });
  });

  test('spec granularity wins over the time range granularity', () async {
    await dataSource.getTimeSeries(
      'tenancy',
      organizationsCreatedMetric,
      timeRange: AnalyticsTimeRange(
        start: DateTime.utc(2025, 6, 1),
        end: DateTime.utc(2026, 6, 1),
        granularity: TimeGranularity.week,
      ),
    );

    expect(transport.calls.single.body['step'], 'month');
  });

  test('no request ever carries tenant or partition filters', () async {
    await dataSource.getTimeSeries(
      'tenancy',
      organizationsCreatedMetric,
      timeRange: timeRange,
    );

    for (final call in transport.calls) {
      final filters =
          (call.body['filters'] as Map<String, dynamic>?) ?? const {};
      expect(filters.keys, isNot(contains('tenant_id')));
      expect(filters.keys, isNot(contains('partition_id')));
    }
  });

  test('gate errors surface status code and server message', () async {
    transport.handler = (path, body) =>
        http.Response(json.encode({'error': 'no tenant scope'}), 403);

    await expectLater(
      dataSource.getTimeSeries(
        'tenancy',
        organizationsCreatedMetric,
        timeRange: timeRange,
      ),
      throwsA(
        isA<AnalyticsQueryException>()
            .having((e) => e.statusCode, 'statusCode', 403)
            .having((e) => e.message, 'message', 'no tenant scope'),
      ),
    );
  });

  test('analyticsGateMessage maps gate statuses to friendly text', () {
    const path = '/api/analytics/query/timeseries';
    expect(
      analyticsGateMessage(
        const AnalyticsQueryException(
          statusCode: 400,
          message: 'metric not allowed',
          path: path,
        ),
      ),
      'This metric is not available from the analytics gate.',
    );
    expect(
      analyticsGateMessage(
        const AnalyticsQueryException(
          statusCode: 403,
          message: 'no tenant scope',
          path: path,
        ),
      ),
      'Analytics are not available for your current sign-in scope.',
    );
    expect(
      analyticsGateMessage(
        const AnalyticsQueryException(
          statusCode: 503,
          message: 'backend down',
          path: path,
        ),
      ),
      contains('temporarily unavailable'),
    );
    expect(
      analyticsGateMessage(StateError('boom')),
      'Could not load analytics.',
    );
  });
}
