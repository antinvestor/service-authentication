# antinvestor_ui_audit

Embeddable audit trail UI for Antinvestor applications. Provides screens and widgets for browsing, searching, and analyzing audit entries with support for object-level and system-wide activity tracking.

## Installation

```yaml
dependencies:
  antinvestor_ui_audit: ^0.1.0
```

## Features

- **Audit Log**: Paginated log with filters, search, and CSV export
- **Audit Detail**: Full detail view for individual audit entries
- **Analytics Dashboard**: KPI cards and charts for audit data trends
- **Integrity Verification**: Hash chain integrity checking over date ranges
- **Embeddable Widgets**: `ObjectAuditTrail`, `LiveActivityFeed`, `ActorActivityWidget`, `AuditEntryTile`, `IntegrityBadge`
- **Routing**: `AuditRouteModule` with GoRouter integration

## Usage

```dart
import 'package:antinvestor_ui_audit/antinvestor_ui_audit.dart';

// Drop audit trail into any detail screen
ObjectAuditTrail(resourceType: 'profile', resourceId: 'profile-123')

// Real-time activity feed for dashboards
LiveActivityFeed(maxItems: 20)

// Show recent activity by a specific user
ActorActivityWidget(profileId: 'user-456')

// Register routes in your host app
final module = AuditRouteModule();
ShellRoute(
  routes: [...ownRoutes, ...module.buildRoutes()],
);
```

## Routes

| Path | Screen |
|------|--------|
| `/services/audit` | Audit analytics dashboard |
| `/services/audit/log` | Paginated audit log |
| `/services/audit/integrity` | Integrity check screen |
| `/services/audit/:entryId` | Audit entry detail |

## Embedding Widgets

```dart
// Hash chain integrity indicator
IntegrityBadge(
  startDate: DateTime.now().subtract(Duration(days: 7)),
  endDate: DateTime.now(),
)

// Compact audit entry row
AuditEntryTile(entry: auditEntry)

// Log a data export as an audit entry
logExport(ref, resourceType: 'audit_log', rowCount: 50, format: 'csv')
```
