import 'dart:convert';

import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:crypto/crypto.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

/// Thin seam over the `sign_in_with_apple` static API so that tests can
/// inject a fake. Exposes only the calls the runtime actually uses.
abstract class SignInWithAppleAdapter {
  const SignInWithAppleAdapter();

  /// Default adapter backed by the real `SignInWithApple` static methods.
  const factory SignInWithAppleAdapter.defaultAdapter() =
      _RealSignInWithAppleAdapter;

  Future<bool> isAvailable();

  Future<AuthorizationCredentialAppleID> getAppleIDCredential({
    required List<AppleIDAuthorizationScopes> scopes,
    String? nonce,
  });
}

class _RealSignInWithAppleAdapter extends SignInWithAppleAdapter {
  const _RealSignInWithAppleAdapter();

  @override
  Future<bool> isAvailable() => SignInWithApple.isAvailable();

  @override
  Future<AuthorizationCredentialAppleID> getAppleIDCredential({
    required List<AppleIDAuthorizationScopes> scopes,
    String? nonce,
  }) =>
      SignInWithApple.getAppleIDCredential(scopes: scopes, nonce: nonce);
}

/// [NativeCredentialProvider] implementation backed by Sign in with Apple.
///
/// Apple's SDK has no silent / auto-select API — an ID token is only
/// issued after an explicit user gesture. Consequently
/// [attemptSilent] always returns `noSession()`. Callers should invoke
/// [attemptInteractive] from a button press handler.
///
/// Apple requires the `nonce` sent in the authorization request to be
/// the SHA-256 hash of the raw nonce that will be verified on the
/// server. We compute that hash here so callers only ever deal in the
/// raw runtime-generated nonce.
class AppleCredentialProvider implements NativeCredentialProvider {
  AppleCredentialProvider({SignInWithAppleAdapter? adapter})
      : _adapter = adapter ?? const SignInWithAppleAdapter.defaultAdapter();

  final SignInWithAppleAdapter _adapter;

  @override
  NativeCredentialProviderKind get kind => NativeCredentialProviderKind.apple;

  @override
  Future<bool> isAvailable() => _adapter.isAvailable();

  /// Apple requires an explicit user gesture; silent attempts are not
  /// supported. Use [attemptInteractive] from a button handler.
  @override
  Future<NativeCredentialOutcome> attemptSilent({required String nonce}) async {
    return const NativeCredentialOutcome.noSession();
  }

  @override
  Future<NativeCredentialOutcome> attemptInteractive({
    required String nonce,
  }) async {
    final hashedNonce = sha256.convert(utf8.encode(nonce)).toString();
    try {
      final credential = await _adapter.getAppleIDCredential(
        scopes: const [
          AppleIDAuthorizationScopes.email,
          AppleIDAuthorizationScopes.fullName,
        ],
        nonce: hashedNonce,
      );

      final idToken = credential.identityToken;
      if (idToken == null) {
        return NativeCredentialOutcome.error(
          AuthError(
            AuthErrorCode.nativeCredentialUnavailable,
            'Apple returned no identityToken',
          ),
        );
      }

      return NativeCredentialOutcome.ok(
        NativeCredentialResult(
          provider: NativeCredentialProviderKind.apple,
          idToken: idToken,
          authorizationCode: credential.authorizationCode,
          nonce: nonce,
          autoSelected: false,
        ),
      );
    } on SignInWithAppleAuthorizationException catch (e) {
      if (e.code == AuthorizationErrorCode.canceled) {
        return const NativeCredentialOutcome.cancelled();
      }
      return NativeCredentialOutcome.error(
        AuthError(
          AuthErrorCode.nativeCredentialUnavailable,
          'Sign in with Apple failed: ${e.code.name} (${e.message})',
          cause: e,
        ),
      );
    } catch (e) {
      return NativeCredentialOutcome.error(
        AuthError(
          AuthErrorCode.nativeCredentialExchangeFailed,
          'Sign in with Apple threw: $e',
          cause: e,
        ),
      );
    }
  }

  /// No-op — Apple's session lives at the IdP, there is nothing local to
  /// clear.
  @override
  Future<void> signOut() async {}
}
