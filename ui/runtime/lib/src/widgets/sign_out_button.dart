import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/providers/auth_providers.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Material button that calls [AuthRuntime.logout] on tap.
///
/// Disables itself while logout is in flight to avoid double-invocations
/// during slow end-session round-trips.
class SignOutButton extends ConsumerStatefulWidget {
  const SignOutButton({
    this.label = 'Sign out',
    this.style,
    this.onSignedOut,
    this.onError,
    super.key,
  });

  final String label;
  final ButtonStyle? style;
  final VoidCallback? onSignedOut;
  final void Function(AuthError error)? onError;

  @override
  ConsumerState<SignOutButton> createState() => _SignOutButtonState();
}

class _SignOutButtonState extends ConsumerState<SignOutButton> {
  bool _pending = false;

  @override
  Widget build(BuildContext context) {
    return TextButton(
      style: widget.style,
      onPressed: _pending ? null : _onTap,
      child: _pending
          ? const SizedBox(
              height: 16,
              width: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : Text(widget.label),
    );
  }

  Future<void> _onTap() async {
    setState(() => _pending = true);
    try {
      await ref.read(authRuntimeProvider).logout();
      widget.onSignedOut?.call();
    } on AuthError catch (err) {
      final cb = widget.onError;
      if (cb != null) {
        cb(err);
      } else {
        rethrow;
      }
    } finally {
      if (mounted) setState(() => _pending = false);
    }
  }
}
