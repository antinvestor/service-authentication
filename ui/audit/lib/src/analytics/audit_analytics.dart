import 'package:antinvestor_ui_core/antinvestor_ui_core.dart';

/// Frame's built-in RPC volume metric for the audit service.
///
/// Frame names these instruments `{pkg}/completed_calls` (the
/// `telemetry.Views` rewrite of the `{pkg}/latency` histogram), labelled by
/// `method` and `status`. The thesa gate allowlists any
/// `.+/completed_calls$` metric.
///
/// TODO(analytics): the audit service does not currently register a
/// `telemetry.NewTracer` with an explicit package name, so the exact `{pkg}`
/// segment is unconfirmed. Verify with a grouped or timeseries query against
/// the gate once audit telemetry is visible and update this constant (it is
/// the single place the metric name is declared).
const String auditCompletedCallsMetric = 'audit/completed_calls';

/// Analytics catalog for the audit service, consumed by the thesa-gated
/// metrics pipeline.
///
/// Host apps register this spec on their [ThesaAnalyticsDataSource]:
///
/// ```dart
/// analyticsDataSourceProvider.overrideWith(
///   (ref) => ThesaAnalyticsDataSource(transport, specs: [auditAnalyticsSpec]),
/// );
/// ```
///
/// KPI tiles on the audit dashboard stay entry-derived (entity API); only
/// the request-activity trend is queried through the gate. Tenant scoping
/// is injected server-side from the caller's JWT; no tenant/partition
/// filters are declared (or ever sent) here.
const ServiceAnalyticsSpec auditAnalyticsSpec = ServiceAnalyticsSpec(
  service: 'audit',
  charts: [
    ChartConfig.timeSeries(
      auditCompletedCallsMetric,
      label: 'Request activity',
    ),
  ],
);

/// Maps analytics gate failures to short, user-facing messages.
///
/// The gate's error contract: 400 -> metric rejected by the server-side
/// allowlist, 403 -> caller's JWT carries no tenant scope, 5xx -> metrics
/// backend unreachable.
String analyticsGateMessage(Object error) {
  if (error is AnalyticsQueryException) {
    return switch (error.statusCode) {
      400 => 'This metric is not available from the analytics gate.',
      403 => 'Analytics are not available for your current sign-in scope.',
      >= 500 =>
        'The analytics backend is temporarily unavailable. '
            'Please try again shortly.',
      _ => 'Could not load analytics (HTTP ${error.statusCode}).',
    };
  }
  return 'Could not load analytics.';
}
