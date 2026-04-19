import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/providers/auth_providers.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Material button that calls [AuthRuntime.ensureAuthenticated] on tap.
///
/// The button disables itself while a sign-in is in flight so users
/// can't stack concurrent OAuth flows. Errors surface through [onError]
/// when supplied; otherwise they propagate up the default `FlutterError`
/// path. Success is signalled via [onAuthenticated] after
/// `ensureAuthenticated` returns.
class SignInButton extends ConsumerStatefulWidget {
  const SignInButton({
    this.label = 'Sign in',
    this.style,
    this.onAuthenticated,
    this.onError,
    super.key,
  });

  final String label;
  final ButtonStyle? style;
  final VoidCallback? onAuthenticated;
  final void Function(AuthError error)? onError;

  @override
  ConsumerState<SignInButton> createState() => _SignInButtonState();
}

class _SignInButtonState extends ConsumerState<SignInButton> {
  bool _pending = false;

  @override
  Widget build(BuildContext context) {
    return ElevatedButton(
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
      await ref.read(authRuntimeProvider).ensureAuthenticated();
      widget.onAuthenticated?.call();
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
