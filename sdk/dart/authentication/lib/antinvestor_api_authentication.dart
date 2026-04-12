/// Dart client library for Ant Investor Authentication Service.
///
/// Provides read-only access to login history and session information
/// using Connect RPC protocol.
library;

// Export generated protobuf files
export 'src/authentication/v1/authentication.pb.dart';
export 'src/authentication/v1/authentication.pbenum.dart';
export 'src/authentication/v1/authentication.pbjson.dart';
export 'src/authentication/v1/authentication.connect.client.dart';
export 'src/authentication/v1/authentication.connect.spec.dart';

// Export common types used in authentication API
export 'src/google/protobuf/struct.pb.dart';
export 'src/google/protobuf/timestamp.pb.dart';
