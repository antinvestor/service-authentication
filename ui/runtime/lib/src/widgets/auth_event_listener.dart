import 'package:antinvestor_auth_runtime/src/models/security_event.dart';
import 'package:antinvestor_auth_runtime/src/providers/auth_providers.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Listens for [SecurityEvent]s and surfaces them in the UI.
///
/// By default each event produces a [SnackBar] via the enclosing
/// [ScaffoldMessenger]. Apps that need richer UX (dialogs, telemetry,
/// logging) can supply a [builder] which receives the event and a
/// "default widget" helper they can either discard, wrap, or return as-is.
///
/// The listener itself is invisible: it renders [child] and reacts to
/// events as a side-effect. Place it high in the widget tree — typically
/// under [MaterialApp] but inside the [ProviderScope].
class AuthEventListener extends ConsumerStatefulWidget {
  const AuthEventListener({
    required this.child,
    this.builder,
    super.key,
  });

  final Widget child;

  /// Optional customisation hook.
  ///
  /// Receives the current [BuildContext], the emitted [SecurityEvent], and
  /// the default [SnackBar]-shaped widget the listener would have shown.
  /// Return null to suppress the default; return a widget to display an
  /// alternative (e.g. a [Dialog]).
  final Widget? Function(
    BuildContext context,
    SecurityEvent event,
    Widget defaultSnackBarChild,
  )? builder;

  @override
  ConsumerState<AuthEventListener> createState() =>
      _AuthEventListenerState();
}

class _AuthEventListenerState extends ConsumerState<AuthEventListener> {
  @override
  Widget build(BuildContext context) {
    ref.listen<AsyncValue<SecurityEvent>>(
      securityEventsProvider,
      (prev, next) {
        next.whenData((event) => _onEvent(context, event));
      },
    );
    return widget.child;
  }

  void _onEvent(BuildContext context, SecurityEvent event) {
    if (!mounted) return;
    final messenger = ScaffoldMessenger.maybeOf(context);
    if (messenger == null) return;
    final defaultChild = _defaultSnackBarChild(event);
    final customBuilder = widget.builder;
    if (customBuilder == null) {
      messenger.showSnackBar(SnackBar(content: defaultChild));
      return;
    }
    // Caller opted in to custom UX. They get three choices:
    // - return null → suppress entirely (silent handling / telemetry only)
    // - return `defaultChild` → keep the default message
    // - return a new widget → show an alternative
    final override = customBuilder(context, event, defaultChild);
    if (override == null) return;
    messenger.showSnackBar(SnackBar(content: override));
  }
}

Widget _defaultSnackBarChild(SecurityEvent event) {
  return Text(_messageFor(event));
}

String _messageFor(SecurityEvent event) {
  return switch (event) {
    RefreshReuseDetected() =>
      'We detected suspicious session activity and signed you out for safety.',
    StorageCorruption() =>
      'Your saved session could not be read; please sign in again.',
    BindingInvalidated() =>
      'Your device credentials expired; please sign in again.',
    LoggedOutElsewhere() =>
      'You were signed out on another device.',
  };
}
