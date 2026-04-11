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
  ..actorId = 'user-123'
  ..objectId = 'profile-456'
  ..objectType = 'profile'
  ..action = 'update';
final response = await client.createAuditEntry(entry);

// Search audit entries
final searchRequest = SearchAuditEntriesRequest()
  ..objectId = 'profile-456';
final results = await client.searchAuditEntries(searchRequest);

// Verify hash chain integrity
final verifyRequest = VerifyIntegrityRequest()
  ..startTime = startTimestamp
  ..endTime = endTimestamp;
final integrity = await client.verifyIntegrity(verifyRequest);
```

## Generated Types

This package exports protobuf-generated types from the `audit.v1` namespace:

- `AuditEntry`, `AuditAction` - Core audit data types
- `CreateAuditEntryRequest/Response` - Entry creation
- `SearchAuditEntriesRequest/Response` - Querying entries
- `VerifyIntegrityRequest/Response` - Hash chain verification
- `AuditServiceClient` - Connect RPC client

## Related Packages

- `antinvestor_ui_audit` - Flutter UI widgets and screens for audit trail visualization
- `antinvestor_ui_core` - Shared design system used by all Antinvestor UI packages
