import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';

/// Which native credential provider produced a result.
enum NativeCredentialProviderKind { apple, google }

/// A successful native credential acquisition.
///
/// The [idToken] is the signed JWT we will exchange upstream via
/// `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693). The
/// [nonce] is the original random value the runtime generated and bound
/// into the request; the worker must verify it matches the `nonce` claim
/// of the ID token before trusting it.
///
/// [authorizationCode] is populated when the native SDK returned a code
/// (Apple sets this); Google's ID-token flow does not.
///
/// [autoSelected] indicates the credential was obtained without any user
/// interaction (silent / one-tap auto-select). The runtime treats these
/// differently from interactive sign-ins (e.g. for analytics and for
/// deciding whether to fall back to the web flow).
class NativeCredentialResult {
  const NativeCredentialResult({
    required this.provider,
    required this.idToken,
    required this.autoSelected,
    this.authorizationCode,
    this.nonce,
  });

  final NativeCredentialProviderKind provider;
  final String idToken;
  final String? authorizationCode;
  final String? nonce;
  final bool autoSelected;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is NativeCredentialResult &&
          runtimeType == other.runtimeType &&
          provider == other.provider &&
          idToken == other.idToken &&
          authorizationCode == other.authorizationCode &&
          nonce == other.nonce &&
          autoSelected == other.autoSelected;

  @override
  int get hashCode => Object.hash(
        provider,
        idToken,
        authorizationCode,
        nonce,
        autoSelected,
      );
}

/// Outcome of a native credential attempt.
///
/// Sealed so callers (the worker, tests) can switch exhaustively. Mirrors
/// the [StateInput] pattern elsewhere in the runtime.
sealed class NativeCredentialOutcome {
  const NativeCredentialOutcome();

  const factory NativeCredentialOutcome.ok(NativeCredentialResult result) = Ok;
  const factory NativeCredentialOutcome.noSession() = NoSession;
  const factory NativeCredentialOutcome.cancelled() = Cancelled;
  const factory NativeCredentialOutcome.unavailable(String reason) =
      Unavailable;
  const factory NativeCredentialOutcome.error(AuthError error) = ErrorOutcome;
}

final class Ok extends NativeCredentialOutcome {
  const Ok(this.result);

  final NativeCredentialResult result;
}

final class NoSession extends NativeCredentialOutcome {
  const NoSession();
}

final class Cancelled extends NativeCredentialOutcome {
  const Cancelled();
}

final class Unavailable extends NativeCredentialOutcome {
  const Unavailable(this.reason);

  final String reason;
}

final class ErrorOutcome extends NativeCredentialOutcome {
  const ErrorOutcome(this.error);

  final AuthError error;
}

/// A platform-specific native credential provider (Apple / Google / ...).
///
/// Concrete implementations wrap a platform SDK (Sign in with Apple,
/// google_sign_in / CredentialManager, etc.) and normalise success and
/// failure modes into a [NativeCredentialOutcome].
///
/// Providers must NOT perform any upstream token exchange — they return a
/// raw IdP ID token; the worker owns the exchange with the authentication
/// service.
abstract class NativeCredentialProvider {
  /// Which provider this is. Used for routing and telemetry.
  NativeCredentialProviderKind get kind;

  /// Whether the provider can run on this platform right now.
  ///
  /// Should be safe to call before any user interaction — e.g. used to
  /// decide whether to render a "Continue with Apple" button.
  Future<bool> isAvailable();

  /// Attempt a silent / auto-select sign-in. Must never show UI. Returns
  /// [NoSession] if there is no existing credential and [Ok] if one was
  /// obtained without user interaction.
  Future<NativeCredentialOutcome> attemptSilent({required String nonce});

  /// Attempt an interactive sign-in (shows the native sheet / browser).
  /// Must be called from a user gesture.
  Future<NativeCredentialOutcome> attemptInteractive({required String nonce});

  /// Clear any cached session with this provider.
  Future<void> signOut();
}
