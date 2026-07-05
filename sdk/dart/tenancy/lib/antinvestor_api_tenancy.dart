/// Dart client library for Ant Investor Tenancy Service.
///
/// Provides Tenancy service functionality using Connect RPC protocol.
///
/// ## Usage
///
/// ```dart
/// import 'package:antinvestor_api_tenancy/antinvestor_api_tenancy.dart';
/// import 'package:connectrpc/connect.dart';
///
/// void main() async {
///   final interceptors = TenancyClientFactory.createAuthInterceptors(
///     tokenManager: tokenManager,
///     onTokenRefresh: (refreshToken) async {
///       return await authClient.refresh(refreshToken);
///     },
///   );
///
///   final transport = YourTransportImplementation(
///     baseUrl: Uri.parse(defaultTenancyEndpoint),
///     interceptors: interceptors,
///   );
///
///   final client = TenancyServiceClient(transport);
/// }
/// ```
library;

// Export client wrapper
export 'src/client.dart';

// Export generated protobuf files
export 'src/tenancy/v1/tenancy.pb.dart';
export 'src/tenancy/v1/tenancy.pbenum.dart';
export 'src/tenancy/v1/tenancy.pbjson.dart';
export 'src/tenancy/v1/tenancy.connect.client.dart';
export 'src/tenancy/v1/tenancy.connect.spec.dart';

// Export the v2 OAuth client and service-account contract.
export 'src/tenancy/v2/auth_contract.pb.dart';
export 'src/tenancy/v2/auth_contract.pbenum.dart';
export 'src/tenancy/v2/auth_contract.pbjson.dart';
export 'src/tenancy/v2/auth_contract.connect.client.dart';
export 'src/tenancy/v2/auth_contract.connect.spec.dart';

// Export common types used in tenancy API
export 'src/common/v1/common.pb.dart';
export 'src/common/v1/common.pbenum.dart';
export 'src/google/protobuf/struct.pb.dart';
export 'src/google/protobuf/timestamp.pb.dart';
