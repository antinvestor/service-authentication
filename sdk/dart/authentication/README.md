# antinvestor_api_authentication

Dart client library for the Ant Investor Authentication Service. Provides read-only access to login history and session information using Connect RPC protocol.

## Installation

```yaml
dependencies:
  antinvestor_api_authentication: ^0.1.0
```

## Features

- **Login History**: Query login events by profile, device, source, and time range
- **Login Event Details**: Retrieve detailed information about individual login events
- **Connect RPC**: Type-safe client generated from protobuf definitions
- **Protobuf Types**: Full protobuf message types for login events and sessions

## Usage

```dart
import 'package:antinvestor_api_authentication/antinvestor_api_authentication.dart';
import 'package:connectrpc/connect.dart';

// Create a transport (configure with your server URL)
final transport = createConnectTransport(
  baseUrl: 'https://api.example.com',
);

// Instantiate the authentication service client
final client = AuthenticationServiceClient(transport);

// List recent login events for a profile
final request = ListLoginEventsRequest()
  ..profileId = 'user-123'
  ..count = 20;
final stream = client.listLoginEvents(request);

// Get a specific login event
final getRequest = GetLoginEventRequest()
  ..id = 'event-456';
final response = await client.getLoginEvent(getRequest);
```

## Generated Types

This package exports protobuf-generated types from the `authentication.v1` namespace:

- `LoginEventObject` - Core login event data type
- `LoginSource` - Enum of authentication methods (direct, google, facebook, etc.)
- `ListLoginEventsRequest/Response` - Filtered listing with pagination
- `GetLoginEventRequest/Response` - Single event retrieval
- `AuthenticationServiceClient` - Connect RPC client

## Related Packages

- `antinvestor_ui_auth` - Flutter UI widgets for login history visualization
- `antinvestor_ui_core` - Shared design system used by all Antinvestor UI packages
