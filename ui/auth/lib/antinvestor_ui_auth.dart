/// Authentication UI library for Antinvestor.
///
/// Provides embeddable widgets for viewing login history, session details,
/// and sign-in activity. Designed to be dropped into profile screens
/// or standalone admin views.
///
/// ## Embeddable Widgets (primary reuse points)
///
/// * [LoginHistoryWidget] - Drop into any profile screen to show
///   recent sign-in activity for a user.
/// * [LoginEventTile] - Compact tile for a single login event.
/// * [DeviceActivityWidget] - Shows login activity from a specific device.
///
/// ## Screens
///
/// * [LoginHistoryScreen] - Full-page login history with filters.
/// * [LoginEventDetailScreen] - Detailed view of a single login event.
///
/// ## Routing
///
/// * [AuthRouteModule] - GoRouter routes and navigation items.
library antinvestor_ui_auth;

// -- Embeddable Widgets (most important for reuse) --
export 'src/widgets/login_history_widget.dart';
export 'src/widgets/login_event_tile.dart';
export 'src/widgets/device_activity_widget.dart';

// -- Screens --
export 'src/screens/login_history_screen.dart';
export 'src/screens/login_event_detail_screen.dart';

// -- Routing --
export 'src/routing/auth_route_module.dart';

// -- Providers --
export 'src/providers/auth_transport_provider.dart';
export 'src/providers/auth_providers.dart';
