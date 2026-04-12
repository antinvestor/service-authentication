# antinvestor_api_audit

Dart client library for the Ant Investor Audit Service. Provides tamper-proof audit trail management with hash chaining and digital signatures using Connect RPC protocol.

## Installation

```yaml
dependencies:
  antinvestor_api_audit: ^0.1.0
```

## Features

- **Audit Entry Management**: Create, retrieve, and search audit entries
- **Hash Chain Integrity**: Tamper-proof audit trail with cryptographic hash chaining
- **Digital Signatures**: Entry-level digital signature support
- **Connect RPC**: Type-safe client generated from protobuf definitions
- **Search & Filter**: Query audit entries by actor, object, action, and time range
- **Protobuf Types**: Full protobuf message types for audit entries, actors, and actions

## Usage

```dart
import 'package:antinvestor_api_audit/antinvestor_api_audit.dart';
import 'package:connectrpc/connect.dart';

// Create a transport (configure with your server URL)
final transport = createConnectTransport(
  baseUrl: 'https://api.example.com',
);

// Instantiate the audit service client
final client = AuditServiceClient(transport);

// Create an audit entry
final entry = CreateAuditEntryRequest()
  ..profileId = 'user-123'
  ..action = 'update'
  ..resourceType = 'profile'
  ..resourceId = 'profile-456'
  ..service = 'service_profile';
final response = await client.createAuditEntry(entry);

// Search audit entries
final searchRequest = SearchAuditEntriesRequest()
  ..query = 'profile-456';
final results = client.searchAuditEntries(searchRequest);

// Verify hash chain integrity
final verifyRequest = VerifyIntegrityRequest()
  ..startDate = startTimestamp
  ..endDate = endTimestamp;
final integrity = await client.verifyIntegrity(verifyRequest);
```

## Generated Types

This package exports protobuf-generated types from the `audit.v1` namespace:

- `AuditEntryObject` - Core audit entry data type
- `CreateAuditEntryRequest/Response` - Entry creation
- `ListAuditEntriesRequest/Response` - Filtered listing with pagination
- `SearchAuditEntriesRequest/Response` - Free-text search
- `VerifyIntegrityRequest/Response` - Hash chain verification
- `AuditServiceClient` - Connect RPC client

## Related Packages

- `antinvestor_ui_audit` - Flutter UI widgets and screens for audit trail visualization
- `antinvestor_ui_core` - Shared design system used by all Antinvestor UI packages
