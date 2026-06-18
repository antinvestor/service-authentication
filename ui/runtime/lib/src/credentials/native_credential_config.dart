import 'package:antinvestor_auth_runtime/src/credentials/apple_credential_provider.dart';
import 'package:antinvestor_auth_runtime/src/credentials/google_credential_provider.dart';
import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';
import 'package:equatable/equatable.dart';
import 'package:flutter/foundation.dart';

/// High-level native credential configuration for [createAuthRuntime].
///
/// This is the preferred integration point for app code. It builds the
/// platform-appropriate [NativeCredentialProvider] list while keeping the
/// lower-level `nativeProviders` override available for tests and custom
/// provider stacks.
class NativeCredentialConfig extends Equatable {
  const NativeCredentialConfig({
    this.googleServerClientId,
    this.enableApple = false,
    this.providerOrder = const <NativeCredentialProviderKind>[
      NativeCredentialProviderKind.apple,
      NativeCredentialProviderKind.google,
    ],
    this.preferSilent = true,
  });

  /// Google OAuth client ID of type "Web application".
  ///
  /// On Android this enables the `google_sign_in` v7 flow backed by Android
  /// Credential Manager / Sign in with Google. It also enables Google native
  /// sign-in on iOS and macOS when those platforms are targeted.
  final String? googleServerClientId;

  /// Whether to include Sign in with Apple on Apple platforms.
  final bool enableApple;

  /// Provider order for the native credential waterfall.
  ///
  /// Providers unsupported on the current platform, or missing required
  /// configuration, are skipped. Duplicate entries are ignored after the first
  /// occurrence.
  final List<NativeCredentialProviderKind> providerOrder;

  /// Whether the runtime should attempt a no-UI native credential on app
  /// startup before the user taps sign in.
  ///
  /// On Android this is the returning-user One Tap / automatic sign-in path
  /// exposed by Google Sign-In through Credential Manager.
  final bool preferSilent;

  /// Builds providers for the current Flutter target platform.
  List<NativeCredentialProvider> buildProviders() {
    final googleClientId = googleServerClientId?.trim();
    final providers = <NativeCredentialProvider>[];
    final seen = <NativeCredentialProviderKind>{};

    for (final kind in providerOrder) {
      if (!seen.add(kind)) continue;
      switch (kind) {
        case NativeCredentialProviderKind.apple:
          if (enableApple && _supportsApple(defaultTargetPlatform)) {
            providers.add(AppleCredentialProvider());
          }
          break;
        case NativeCredentialProviderKind.google:
          if (googleClientId != null &&
              googleClientId.isNotEmpty &&
              _supportsGoogle(defaultTargetPlatform)) {
            providers.add(
              GoogleCredentialProvider(serverClientId: googleClientId),
            );
          }
          break;
      }
    }

    return List<NativeCredentialProvider>.unmodifiable(providers);
  }

  @override
  List<Object?> get props => [
    googleServerClientId,
    enableApple,
    providerOrder,
    preferSilent,
  ];
}

bool _supportsApple(TargetPlatform platform) {
  if (kIsWeb) return false;
  return platform == TargetPlatform.iOS || platform == TargetPlatform.macOS;
}

bool _supportsGoogle(TargetPlatform platform) {
  if (kIsWeb) return false;
  return platform == TargetPlatform.android ||
      platform == TargetPlatform.iOS ||
      platform == TargetPlatform.macOS;
}
