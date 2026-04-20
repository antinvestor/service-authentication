import 'package:antinvestor_auth_runtime/src/auth_runtime.dart';
import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:antinvestor_auth_runtime/src/models/security_event.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Entry point for reaching the [AuthRuntime] from a Riverpod tree.
///
/// Apps MUST override this provider at the root, typically like:
///
/// ```dart
/// ProviderScope(
///   overrides: [
///     authRuntimeProvider.overrideWithValue(createAuthRuntime(cfg)),
///   ],
///   child: const MyApp(),
/// )
/// ```
///
/// The default throws so usage without the override surfaces
/// immediately rather than silently yielding nulls.
final authRuntimeProvider = Provider<AuthRuntime>(
  (ref) => throw UnimplementedError(
    'Override authRuntimeProvider at the app root with a concrete '
    'AuthRuntime built via createAuthRuntime().',
  ),
);

/// Current [AuthState] as a stream.
///
/// The stream is the runtime's own `authStateStream`. Callers can
/// `watch` this provider to rebuild on state transitions without
/// reaching into the runtime directly.
final authStateProvider = StreamProvider<AuthState>(
  (ref) => ref.watch(authRuntimeProvider).authStateStream,
);

/// `true` iff the current [AuthState] is [AuthState.authenticated].
///
/// While the stream is loading (pre-first-event) we conservatively
/// report `false`: widgets built on this provider should assume the user
/// is not signed in until the stream emits.
final isAuthenticatedProvider = Provider<bool>(
  (ref) {
    final snap = ref.watch(authStateProvider);
    return snap.value == AuthState.authenticated;
  },
);

/// Decoded ID-token claims. Returns `{}` while unauthenticated so
/// widgets don't have to special-case the pre-sign-in state.
final userClaimsProvider = FutureProvider<Map<String, dynamic>>(
  (ref) async {
    final rt = ref.watch(authRuntimeProvider);
    final snap = ref.watch(authStateProvider);
    if (snap.value != AuthState.authenticated) {
      return const <String, dynamic>{};
    }
    return rt.getClaims();
  },
);

/// Roles extracted from the access token. Returns `[]` while
/// unauthenticated.
final rolesProvider = FutureProvider<List<String>>(
  (ref) async {
    final rt = ref.watch(authRuntimeProvider);
    final snap = ref.watch(authStateProvider);
    if (snap.value != AuthState.authenticated) {
      return const <String>[];
    }
    return rt.getRoles();
  },
);

/// Security events (refresh reuse, storage corruption, …). Typically
/// piped into `AuthEventListener` to surface SnackBars / Dialogs.
final securityEventsProvider = StreamProvider<SecurityEvent>(
  (ref) => ref.watch(authRuntimeProvider).securityEventStream,
);
