import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  tearDown(() {
    debugDefaultTargetPlatformOverride = null;
  });

  group('NativeCredentialConfig', () {
    test('android with googleServerClientId builds Google provider only', () {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;

      final providers = const NativeCredentialConfig(
        googleServerClientId: 'web-client.apps.googleusercontent.com',
        enableApple: true,
      ).buildProviders();

      expect(providers, hasLength(1));
      expect(providers.single, isA<GoogleCredentialProvider>());
      expect(providers.single.kind, NativeCredentialProviderKind.google);
    });

    test('ios honors provider order for Apple and Google', () {
      debugDefaultTargetPlatformOverride = TargetPlatform.iOS;

      final providers = const NativeCredentialConfig(
        googleServerClientId: 'web-client.apps.googleusercontent.com',
        enableApple: true,
        providerOrder: <NativeCredentialProviderKind>[
          NativeCredentialProviderKind.google,
          NativeCredentialProviderKind.apple,
        ],
      ).buildProviders();

      expect(providers, hasLength(2));
      expect(providers[0], isA<GoogleCredentialProvider>());
      expect(providers[1], isA<AppleCredentialProvider>());
    });

    test('missing googleServerClientId skips Google provider', () {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;

      final providers = const NativeCredentialConfig(
        googleServerClientId: '  ',
      ).buildProviders();

      expect(providers, isEmpty);
    });

    test('duplicates in providerOrder are ignored after first occurrence', () {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;

      final providers = const NativeCredentialConfig(
        googleServerClientId: 'web-client.apps.googleusercontent.com',
        providerOrder: <NativeCredentialProviderKind>[
          NativeCredentialProviderKind.google,
          NativeCredentialProviderKind.google,
        ],
      ).buildProviders();

      expect(providers, hasLength(1));
      expect(providers.single, isA<GoogleCredentialProvider>());
    });
  });
}
