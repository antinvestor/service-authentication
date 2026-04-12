import 'package:antinvestor_api_authentication/antinvestor_api_authentication.dart';
import 'package:antinvestor_ui_core/api/api_base.dart';
import 'package:connectrpc/connect.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

const _authUrl = String.fromEnvironment(
  'AUTHENTICATION_URL',
  defaultValue: 'https://api.antinvestor.com/authentication',
);

final authTransportProvider = Provider<Transport>((ref) {
  final tokenProvider = ref.watch(authTokenProviderProvider);
  return createTransport(tokenProvider, baseUrl: _authUrl);
});

final authServiceClientProvider =
    Provider<AuthenticationServiceClient>((ref) {
  final transport = ref.watch(authTransportProvider);
  return AuthenticationServiceClient(transport);
});
