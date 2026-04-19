import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';

/// Input to the [reduce] function.
///
/// Sealed so the reducer can exhaustively switch and the compiler catches
/// new variants at their call sites.
sealed class StateInput {
  const StateInput();

  const factory StateInput.initDone({required bool hasTokens}) = InitDone;
  const factory StateInput.signInStart() = SignInStart;
  const factory StateInput.signInDone() = SignInDone;
  const factory StateInput.signInFail(AuthError error) = SignInFail;
  const factory StateInput.refreshStart() = RefreshStart;
  const factory StateInput.refreshDone() = RefreshDone;
  const factory StateInput.refreshFail({
    required AuthError error,
    required bool wipe,
  }) = RefreshFail;
  const factory StateInput.logout() = Logout;
  const factory StateInput.securityWipe(String reason) = SecurityWipe;
}

final class InitDone extends StateInput {
  const InitDone({required this.hasTokens});

  final bool hasTokens;
}

final class SignInStart extends StateInput {
  const SignInStart();
}

final class SignInDone extends StateInput {
  const SignInDone();
}

final class SignInFail extends StateInput {
  const SignInFail(this.error);

  final AuthError error;
}

final class RefreshStart extends StateInput {
  const RefreshStart();
}

final class RefreshDone extends StateInput {
  const RefreshDone();
}

final class RefreshFail extends StateInput {
  const RefreshFail({required this.error, required this.wipe});

  final AuthError error;
  final bool wipe;
}

final class Logout extends StateInput {
  const Logout();
}

final class SecurityWipe extends StateInput {
  const SecurityWipe(this.reason);

  final String reason;
}

/// Pure reducer: given a current [state] and an [input], returns the next
/// state. No side effects. Invariants enforced here:
///
/// * `securityWipe` always lands in `unauthenticated` regardless of the
///   prior state (spec §8 wipe rule).
/// * `refreshDone` only applies while `refreshing` (no-ops otherwise so
///   late events from a cancelled refresh can't spuriously revive an
///   authenticated session).
/// * `initDone` is only honoured from `initializing` (the worker should
///   never init twice; defensively ignore).
AuthState reduce(AuthState state, StateInput input) {
  // Security wipe short-circuits every transition.
  if (input is SecurityWipe) {
    return AuthState.unauthenticated;
  }

  switch (state) {
    case AuthState.initializing:
      return switch (input) {
        InitDone(hasTokens: final t) =>
          t ? AuthState.authenticated : AuthState.unauthenticated,
        SignInDone() => AuthState.authenticated,
        SignInFail() => AuthState.unauthenticated,
        // Ignore stray inputs while initializing.
        _ => state,
      };

    case AuthState.unauthenticated:
      return switch (input) {
        SignInStart() => AuthState.initializing,
        // Everything else is a no-op from unauthenticated.
        _ => state,
      };

    case AuthState.authenticated:
      return switch (input) {
        RefreshStart() => AuthState.refreshing,
        Logout() => AuthState.unauthenticated,
        // Ignore sign-in variants once authenticated.
        _ => state,
      };

    case AuthState.refreshing:
      return switch (input) {
        RefreshDone() => AuthState.authenticated,
        RefreshFail() => AuthState.unauthenticated,
        Logout() => AuthState.unauthenticated,
        _ => state,
      };

    case AuthState.error:
      // Error is a terminal-ish state — only securityWipe (handled
      // above) or an explicit sign-in start can leave it.
      return switch (input) {
        SignInStart() => AuthState.initializing,
        _ => state,
      };
  }
}
