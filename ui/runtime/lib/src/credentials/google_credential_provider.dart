import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:google_sign_in/google_sign_in.dart';

/// Minimal view of a google_sign_in account — only the fields the runtime
/// reads. Keeps the adapter / tests from depending on the full
/// [GoogleSignInAccount] surface.
abstract class GoogleSignInAccountView {
  String? get idToken;
}

class _AccountView implements GoogleSignInAccountView {
  _AccountView(this._account);

  final GoogleSignInAccount _account;

  @override
  String? get idToken => _account.authentication.idToken;
}

/// Thin seam over the `google_sign_in` v7 API.
///
/// The v7 SDK binds the OIDC `nonce` at `initialize()` time (not per
/// authenticate call). Because the runtime rotates the nonce per sign-in
/// attempt, the default adapter re-invokes `initialize()` with the new
/// nonce on every attempt. This is intentionally hidden behind the
/// adapter so provider logic doesn't have to care about the SDK's
/// lifecycle quirk.
abstract class GoogleSignInAdapter {
  const GoogleSignInAdapter();

  /// Default adapter backed by `GoogleSignIn.instance`.
  const factory GoogleSignInAdapter.defaultAdapter() =
      _RealGoogleSignInAdapter;

  Future<void> initialize({
    required String serverClientId,
    required String nonce,
  });

  /// Returns `null` if there is no cached session; throws
  /// [GoogleSignInException] for failures.
  Future<GoogleSignInAccountView?> attemptLightweightAuthentication();

  Future<GoogleSignInAccountView> authenticate({
    List<String> scopeHint = const <String>[],
  });

  Future<void> signOut();
}

class _RealGoogleSignInAdapter extends GoogleSignInAdapter {
  const _RealGoogleSignInAdapter();

  @override
  Future<void> initialize({
    required String serverClientId,
    required String nonce,
  }) =>
      GoogleSignIn.instance.initialize(
        serverClientId: serverClientId,
        nonce: nonce,
      );

  @override
  Future<GoogleSignInAccountView?>
      attemptLightweightAuthentication() async {
    final future = GoogleSignIn.instance.attemptLightweightAuthentication();
    if (future == null) {
      // The SDK returns null synchronously on platforms (e.g. FedCM on
      // web) where lightweight auth is push-based through
      // `authenticationEvents`. In this mode there is nothing to await,
      // so we surface it as "no session" from a silent attempt — the
      // worker will still fall through to the web flow.
      return null;
    }
    final account = await future;
    if (account == null) return null;
    return _AccountView(account);
  }

  @override
  Future<GoogleSignInAccountView> authenticate({
    List<String> scopeHint = const <String>[],
  }) async {
    final account = await GoogleSignIn.instance.authenticate(
      scopeHint: scopeHint,
    );
    return _AccountView(account);
  }

  @override
  Future<void> signOut() => GoogleSignIn.instance.signOut();
}

/// [NativeCredentialProvider] backed by `google_sign_in` v7. On Android
/// this is the Credential Manager / One Tap flow.
class GoogleCredentialProvider implements NativeCredentialProvider {
  GoogleCredentialProvider({
    required String serverClientId,
    GoogleSignInAdapter? adapter,
  })  : _serverClientId = serverClientId,
        _adapter = adapter ?? const GoogleSignInAdapter.defaultAdapter();

  final String _serverClientId;
  final GoogleSignInAdapter _adapter;

  @override
  NativeCredentialProviderKind get kind => NativeCredentialProviderKind.google;

  @override
  Future<bool> isAvailable() async => true;

  @override
  Future<NativeCredentialOutcome> attemptSilent({
    required String nonce,
  }) async {
    try {
      await _adapter.initialize(
        serverClientId: _serverClientId,
        nonce: nonce,
      );
      final account = await _adapter.attemptLightweightAuthentication();
      if (account == null) {
        return const NativeCredentialOutcome.noSession();
      }
      return _buildOk(account, nonce: nonce, autoSelected: true);
    } on GoogleSignInException catch (e) {
      return NativeCredentialOutcome.error(
        AuthError(
          AuthErrorCode.nativeCredentialExchangeFailed,
          'Google silent sign-in failed: ${e.code.name} (${e.description})',
          cause: e,
        ),
      );
    } catch (e) {
      return NativeCredentialOutcome.error(
        AuthError(
          AuthErrorCode.nativeCredentialExchangeFailed,
          'Google silent sign-in threw: $e',
          cause: e,
        ),
      );
    }
  }

  @override
  Future<NativeCredentialOutcome> attemptInteractive({
    required String nonce,
  }) async {
    try {
      await _adapter.initialize(
        serverClientId: _serverClientId,
        nonce: nonce,
      );
      final account =
          await _adapter.authenticate(scopeHint: const <String>['openid']);
      return _buildOk(account, nonce: nonce, autoSelected: false);
    } on GoogleSignInException catch (e) {
      if (e.code == GoogleSignInExceptionCode.canceled) {
        return const NativeCredentialOutcome.cancelled();
      }
      return NativeCredentialOutcome.error(
        AuthError(
          AuthErrorCode.nativeCredentialExchangeFailed,
          'Google sign-in failed: ${e.code.name} (${e.description})',
          cause: e,
        ),
      );
    } catch (e) {
      return NativeCredentialOutcome.error(
        AuthError(
          AuthErrorCode.nativeCredentialExchangeFailed,
          'Google sign-in threw: $e',
          cause: e,
        ),
      );
    }
  }

  @override
  Future<void> signOut() => _adapter.signOut();

  NativeCredentialOutcome _buildOk(
    GoogleSignInAccountView account, {
    required String nonce,
    required bool autoSelected,
  }) {
    final idToken = account.idToken;
    if (idToken == null) {
      return NativeCredentialOutcome.error(
        AuthError(
          AuthErrorCode.nativeCredentialUnavailable,
          'Google returned no id_token',
        ),
      );
    }
    return NativeCredentialOutcome.ok(
      NativeCredentialResult(
        provider: NativeCredentialProviderKind.google,
        idToken: idToken,
        nonce: nonce,
        autoSelected: autoSelected,
      ),
    );
  }
}
