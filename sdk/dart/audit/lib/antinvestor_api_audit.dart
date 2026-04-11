/// Dart client library for Ant Investor Audit Service.
///
/// Provides tamper-proof audit trail management with hash chaining
/// and digital signatures using Connect RPC protocol.
library;

// Export generated protobuf files
export 'src/audit/v1/audit.pb.dart';
export 'src/audit/v1/audit.pbenum.dart';
export 'src/audit/v1/audit.pbjson.dart';
export 'src/audit/v1/audit.connect.client.dart';
export 'src/audit/v1/audit.connect.spec.dart';

// Export common types used in audit API
export 'src/google/protobuf/struct.pb.dart';
export 'src/google/protobuf/timestamp.pb.dart';
