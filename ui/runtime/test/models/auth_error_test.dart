import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('AuthError preserves code/message/cause and computes retryable', () {
    final e = AuthError(
      AuthErrorCode.networkTimeout,
      'boom',
      cause: StateError('x'),
    );
    expect(e.code, AuthErrorCode.networkTimeout);
    expect(e.message, 'boom');
    expect(e.cause, isA<StateError>());
    expect(e.retryable, isTrue);
  });

  test('non-retryable codes flagged', () {
    for (final c in const [
      AuthErrorCode.invalidConfig,
      AuthErrorCode.refreshReuseDetected,
      AuthErrorCode.cryptoUnsupported,
      AuthErrorCode.deepLinkMismatch,
      AuthErrorCode.securityWipe,
    ]) {
      expect(AuthError(c, 'm').retryable, isFalse, reason: c.name);
    }
  });

  test('toString includes code and message', () {
    final e = AuthError(AuthErrorCode.discoveryFailed, 'well-known 404');
    expect(e.toString(), contains('discoveryFailed'));
    expect(e.toString(), contains('well-known 404'));
  });

  test('traceId round-trips', () {
    final e = AuthError(
      AuthErrorCode.apiServerError,
      '500',
      traceId: 'abc-123',
    );
    expect(e.traceId, 'abc-123');
  });
}
