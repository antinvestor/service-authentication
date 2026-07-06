import 'package:antinvestor_api_tenancy/antinvestor_api_tenancy.dart';
import 'package:antinvestor_ui_core/api/api_base.dart';
import 'package:connectrpc/connect.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

const _tenancyUrl = String.fromEnvironment(
  'TENANCY_URL',
  defaultValue: 'https://api.antinvestor.com/tenancy',
);

final tenancyTransportProvider = Provider<Transport>((ref) {
  final tokenProvider = ref.watch(authTokenProviderProvider);
  return createTransport(tokenProvider, baseUrl: _tenancyUrl);
});

final tenancyServiceClientProvider = Provider<TenancyServiceClient>((ref) {
  final transport = ref.watch(tenancyTransportProvider);
  return TenancyServiceClient(transport);
});

final authContractServiceClientProvider = Provider<AuthContractServiceClient>((
  ref,
) {
  final transport = ref.watch(tenancyTransportProvider);
  return AuthContractServiceClient(transport);
});
