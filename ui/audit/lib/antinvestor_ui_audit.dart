/// Audit trail UI library for Antinvestor.
///
/// Provides screens for browsing, searching, and analyzing audit entries,
/// plus embeddable widgets for object-level and system-wide activity tracking.
///
/// ## Embeddable Widgets (primary reuse points)
///
/// * [ObjectAuditTrail] - Drop into any detail screen to show the
///   complete history of actions on a specific object.
/// * [LiveActivityFeed] - Real-time activity feed for dashboards.
/// * [ActorActivityWidget] - Recent activity by a specific user.
/// * [AuditEntryTile] - Compact tile for a single audit entry.
/// * [IntegrityBadge] - Hash chain integrity status badge.
///
/// ## Screens
///
/// * [AuditLogScreen] - Main paginated audit log with filters and CSV export.
/// * [AuditDetailScreen] - Full detail view for a single entry.
/// * [AuditAnalyticsScreen] - KPI dashboard for audit data.
/// * [IntegrityCheckScreen] - Verify hash chain integrity over a date range.
///
/// ## Routing
///
/// * [AuditRouteModule] - GoRouter routes and navigation items.
library antinvestor_ui_audit;

// -- Embeddable Widgets (most important for reuse) --
export 'src/widgets/object_audit_trail.dart';
export 'src/widgets/live_activity_feed.dart';
export 'src/widgets/actor_activity_widget.dart';
export 'src/widgets/audit_entry_tile.dart';
export 'src/widgets/integrity_badge.dart';

// -- Screens --
export 'src/screens/audit_log_screen.dart';
export 'src/screens/audit_detail_screen.dart';
export 'src/screens/audit_analytics_screen.dart';
export 'src/screens/integrity_check_screen.dart';

// -- Routing --
export 'src/routing/audit_route_module.dart';

// -- Providers --
export 'src/providers/audit_transport_provider.dart';
export 'src/providers/audit_providers.dart';
export 'src/providers/audit_export_helper.dart';
