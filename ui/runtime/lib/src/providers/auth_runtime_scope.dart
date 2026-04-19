import 'package:antinvestor_auth_runtime/src/auth_runtime.dart';
import 'package:flutter/widgets.dart';

/// Non-Riverpod alternative for exposing an [AuthRuntime] to descendants.
///
/// Apps that don't want a Riverpod root can wrap their widget tree in
/// [AuthRuntimeScope] and pull the runtime out with
/// `AuthRuntimeScope.of(context)`.
///
/// Updating the runtime after mount is supported: the scope fires a
/// rebuild only when [runtime] actually differs, so hot-reloading with
/// a fresh factory is cheap.
class AuthRuntimeScope extends InheritedWidget {
  const AuthRuntimeScope({
    required this.runtime,
    required super.child,
    super.key,
  });

  final AuthRuntime runtime;

  /// Retrieves the nearest [AuthRuntime] ancestor. Throws if missing so
  /// usage bugs surface at call-site rather than later as a null deref.
  static AuthRuntime of(BuildContext context) {
    final scope =
        context.dependOnInheritedWidgetOfExactType<AuthRuntimeScope>();
    if (scope == null) {
      throw FlutterError(
        'AuthRuntimeScope.of(context) called without an ancestor '
        'AuthRuntimeScope. Wrap your app with AuthRuntimeScope or use '
        'Riverpod via authRuntimeProvider.',
      );
    }
    return scope.runtime;
  }

  /// Non-throwing lookup. Returns `null` when no ancestor scope exists.
  static AuthRuntime? maybeOf(BuildContext context) {
    final scope =
        context.dependOnInheritedWidgetOfExactType<AuthRuntimeScope>();
    return scope?.runtime;
  }

  @override
  bool updateShouldNotify(AuthRuntimeScope oldWidget) =>
      !identical(runtime, oldWidget.runtime);
}
