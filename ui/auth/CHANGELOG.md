## 0.2.0

- **Breaking:** moves to connect-dart 2 and the protobuf 6 runtime
  (`antinvestor_ui_core ^0.6.0`, 2.x/0.2+ `antinvestor_api_*` SDKs,
  `connectrpc ^2.0.0`, `protobuf ^6.1.0`).

## 0.1.0

- Initial release
- Login history screen with source, device, and date range filters
- Login event detail screen with full context (IP, user agent, device, tenancy)
- Embeddable `LoginHistoryWidget` for profile screens
- Embeddable `DeviceActivityWidget` for device detail screens
- `LoginEventTile` compact tile for login events
- `AuthRouteModule` with GoRouter integration and permissions
