import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:antinvestor_auth_runtime/src/providers/auth_providers.dart';
import 'package:antinvestor_auth_runtime/src/widgets/sign_in_button.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Renders [child] only when authenticated.
///
/// Matches the shape sketched in the design spec §4.1: three optional
/// builders let apps customize the loading / unauthenticated / error
/// affordances without sub-classing.
///
/// Defaults:
/// - [loadingBuilder] → centered [CircularProgressIndicator]
/// - [unauthenticatedBuilder] → centered [SignInButton], which handles
///   the sign-in call and loading/error affordances. Apps can supply
///   their own [unauthenticatedBuilder] (optionally wrapping
///   [SignInButton]) for richer UX.
/// - [errorBuilder] → centered error message + "Retry" button that
///   invalidates the state provider so the next frame re-subscribes.
class AuthGate extends ConsumerWidget {
  const AuthGate({
    required this.child,
    this.unauthenticatedBuilder,
    this.loadingBuilder,
    this.errorBuilder,
    super.key,
  });

  final Widget child;
  final WidgetBuilder? unauthenticatedBuilder;
  final WidgetBuilder? loadingBuilder;
  final Widget Function(BuildContext, AuthError)? errorBuilder;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final snap = ref.watch(authStateProvider);
    return snap.when(
      loading: () => (loadingBuilder ?? _defaultLoading)(context),
      error: (err, _) {
        final authErr = err is AuthError
            ? err
            : AuthError(
                AuthErrorCode.networkError,
                err.toString(),
              );
        return (errorBuilder ?? _defaultError)(context, authErr);
      },
      data: (state) {
        switch (state) {
          case AuthState.authenticated:
            return child;
          case AuthState.initializing:
          case AuthState.refreshing:
            return (loadingBuilder ?? _defaultLoading)(context);
          case AuthState.error:
            return (errorBuilder ?? _defaultError)(
              context,
              AuthError(AuthErrorCode.networkError, 'authentication error'),
            );
          case AuthState.unauthenticated:
            return (unauthenticatedBuilder ?? _defaultUnauthenticated)(
              context,
            );
        }
      },
    );
  }
}

Widget _defaultLoading(BuildContext context) =>
    const Center(child: CircularProgressIndicator());

Widget _defaultUnauthenticated(BuildContext context) =>
    const Center(child: SignInButton());

Widget _defaultError(BuildContext context, AuthError err) {
  return Center(
    child: Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        Text(err.message, textAlign: TextAlign.center),
        const SizedBox(height: 12),
        _RetryButton(),
      ],
    ),
  );
}

class _RetryButton extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return TextButton(
      onPressed: () {
        // Invalidating the stream provider forces Riverpod to
        // re-subscribe to the runtime's `authStateStream` on the next
        // frame, giving the UI another shot at settling.
        ref.invalidate(authStateProvider);
      },
      child: const Text('Retry'),
    );
  }
}
