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
ObjectAuditTrail(objectId: 'profile-123', objectType: 'profile')

// Real-time activity feed for dashboards
LiveActivityFeed(limit: 20)

// Show recent activity by a specific user
ActorActivityWidget(actorId: 'user-456')

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
IntegrityBadge(status: IntegrityStatus.valid)

// Compact audit entry row
AuditEntryTile(entry: auditEntry)

// Export audit data
AuditExportHelper.exportCsv(entries: entries)
```
