## 0.4.0

- **Breaking:** moves to connect-dart 2 and the protobuf 6 runtime
  (`antinvestor_ui_core ^0.6.0`, 2.x/0.2+ `antinvestor_api_*` SDKs,
  `connectrpc ^2.0.0`, `protobuf ^6.1.0`).
- `AuditNotifier.createEntry` returns the intake receipt (`CreateAuditEntryResponse`) and `batchCreate` returns the per-entry receipts, as audit v2 does; the deprecated `data` field is no longer read.

## 0.3.2

- Fix: audit log filter dropdowns (Action, Resource Type, Service) set
  `isExpanded` so long option labels ellipsize within their fixed-width
  boxes instead of overflowing the filter row.

## 0.3.0

- `AuditAnalyticsScreen` keeps its entry-derived KPI tiles and adds a
  gate-backed Request Activity trend (`AuditRequestActivitySection`)
  sourced from the thesa analytics gate via `antinvestor_ui_core`'s
  `analyticsDataSourceProvider`, querying frame's built-in
  `{pkg}/completed_calls` metric (`auditCompletedCallsMetric`, a spec
  constant pending confirmation of the exact package segment).
- Added `auditAnalyticsSpec` (a `ServiceAnalyticsSpec`) for host apps to
  register on their `ThesaAnalyticsDataSource`, plus `analyticsGateMessage`
  for friendly gate error states (400 allowlist, 403 unscoped, 5xx backend
  down).
- Requires `antinvestor_ui_core` >= 0.5.0 (unpublished; use a local path
  override during development).

## 0.1.0

- Initial release
- Audit trail UI with log browser, analytics, integrity verification, ObjectAuditTrail/LiveActivityFeed widgets
