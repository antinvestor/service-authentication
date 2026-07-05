## 0.4.0

- Move OAuth client and service-account management to `tenancy.v2.AuthContractService`.
- Require canonical resource-recipient URLs and explicit service-account permission grants.
- Remove all UI use of the retired v1 audience/role contract.

## 0.3.0

- `PartitionAnalyticsPage` drops its mocked 12-month growth bars and fake
  "Top Performing Tenants" table. Growth is now a real timeseries from the
  thesa analytics gate (`identity_organizations_created_total`) with a
  selectable time range, and the tenant table ranks live tenants by their
  actual partition counts. KPI cards stay entity-derived inventory counts.
- Added `tenancyAnalyticsSpec` (a `ServiceAnalyticsSpec`) for host apps to
  register on their `ThesaAnalyticsDataSource`, plus `analyticsGateMessage`
  for friendly gate error states (400 allowlist, 403 unscoped, 5xx backend
  down).
- Dropped the now-unused `fl_chart` dependency.
- Requires `antinvestor_ui_core` >= 0.5.0 (unpublished; use a local path
  override during development).

## 0.1.0

- Initial release
- Tenancy UI with tenants, partitions, roles, access control, service accounts, permission management
