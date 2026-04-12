# antinvestor_ui_auth

Embeddable authentication UI for Antinvestor applications. Provides widgets and screens for browsing login history, viewing session details, and monitoring sign-in activity.

## Installation

```yaml
dependencies:
  antinvestor_ui_auth: ^0.1.0
```

## Features

- **Login History**: Paginated log with filters by source, device, and date range
- **Event Details**: Full detail view for individual login events
- **Embeddable Widgets**: `LoginHistoryWidget`, `DeviceActivityWidget`, `LoginEventTile`
- **Routing**: `AuthRouteModule` with GoRouter integration

## Usage

```dart
import 'package:antinvestor_ui_auth/antinvestor_ui_auth.dart';

// Drop login history into any profile detail screen
LoginHistoryWidget(profileId: 'user-123')

// Show login activity from a specific device
DeviceActivityWidget(deviceId: 'device-456')

// Register routes in your host app
final module = AuthRouteModule();
ShellRoute(
  routes: [...ownRoutes, ...module.buildRoutes()],
);
```

## Routes

| Path | Screen |
|------|--------|
| `/services/auth` | Login history with filters |
| `/services/auth/:eventId` | Login event detail |

## Embedding in Profile Screens

The primary use case is embedding `LoginHistoryWidget` alongside profile details:

```dart
Column(
  children: [
    ProfileHeader(profile: profile),
    const SizedBox(height: 16),
    LoginHistoryWidget(profileId: profile.id),
    const SizedBox(height: 16),
    ActorActivityWidget(profileId: profile.id), // from antinvestor_ui_audit
  ],
)
```
