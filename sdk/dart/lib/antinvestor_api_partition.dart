/// Dart client library for Ant Investor Partition Service.
///
/// Provides Partition service functionality using Connect RPC protocol.
///
/// ## Usage
///
/// ```dart
/// import 'package:antinvestor_api_partition/antinvestor_api_partition.dart';
/// import 'package:connectrpc/connect.dart';
///
/// void main() async {
///   final interceptors = PartitionClientFactory.createAuthInterceptors(
///     tokenManager: tokenManager,
///     onTokenRefresh: (refreshToken) async {
///       return await authClient.refresh(refreshToken);
///     },
///   );
///
///   final transport = YourTransportImplementation(
///     baseUrl: Uri.parse(defaultPartitionEndpoint),
///     interceptors: interceptors,
///   );
///
///   final client = PartitionServiceClient(transport);
/// }
/// ```
library;

// Export client wrapper
export 'src/client.dart';

// Export generated protobuf files
export 'src/partition/v1/partition.pb.dart';
export 'src/partition/v1/partition.pbenum.dart';
export 'src/partition/v1/partition.pbjson.dart';
export 'src/partition/v1/partition.connect.client.dart';
export 'src/partition/v1/partition.connect.spec.dart';

// Export common types used in partition API
export 'src/common/v1/common.pb.dart';
export 'src/common/v1/common.pbenum.dart';
export 'src/google/protobuf/struct.pb.dart';
export 'src/google/protobuf/timestamp.pb.dart';
