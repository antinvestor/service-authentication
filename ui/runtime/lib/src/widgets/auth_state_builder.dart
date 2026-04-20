import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:antinvestor_auth_runtime/src/providers/auth_providers.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Rebuilds its [builder] every time the [AuthState] transitions.
///
/// Thin wrapper around `authStateProvider` — inlineable in one line at
/// the call site, but documenting and testing the pattern in one place
/// keeps the reactive plumbing out of app code.
///
/// While the stream is still loading (pre-first-event) or encounters an
/// error the widget forwards [AuthState.initializing]; callers that need
/// to distinguish loading/error from a real state transition should
/// subscribe to `authStateProvider` directly.
class AuthStateBuilder extends ConsumerWidget {
  const AuthStateBuilder({required this.builder, super.key});

  final Widget Function(BuildContext context, AuthState state) builder;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final snap = ref.watch(authStateProvider);
    final state = snap.when(
      data: (s) => s,
      loading: () => AuthState.initializing,
      error: (_, _) => AuthState.initializing,
    );
    return builder(context, state);
  }
}
