import 'package:antinvestor_ui_core/antinvestor_ui_core.dart';

/// Organization creation counter emitted by the fintech identity service
/// (`identity_organizations_created_total`). Organizations are the closest
/// gate-visible signal for tenant/partition growth until the tenancy
/// service emits its own business metrics.
const String organizationsCreatedMetric =
    'identity_organizations_created_total';

/// Analytics catalog for the tenancy service, consumed by the thesa-gated
/// metrics pipeline.
///
/// Host apps register this spec on their [ThesaAnalyticsDataSource]:
///
/// ```dart
/// analyticsDataSourceProvider.overrideWith(
///   (ref) =>
///       ThesaAnalyticsDataSource(transport, specs: [tenancyAnalyticsSpec]),
/// );
/// ```
///
/// KPI tiles on the partition analytics page stay entity-derived (tenant /
/// partition / role counts); only the growth trend is queried through the
/// gate. Tenant scoping is injected server-side from the caller's JWT; no
/// tenant/partition filters are declared (or ever sent) here.
const ServiceAnalyticsSpec tenancyAnalyticsSpec = ServiceAnalyticsSpec(
  service: 'tenancy',
  charts: [
    ChartConfig.timeSeries(
      organizationsCreatedMetric,
      label: 'Organizations created',
      granularity: TimeGranularity.month,
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
