import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('NativeCredentialProviderKind', () {
    test('has apple and google values', () {
      expect(NativeCredentialProviderKind.values, hasLength(2));
      expect(
        NativeCredentialProviderKind.values,
        containsAll(<NativeCredentialProviderKind>[
          NativeCredentialProviderKind.apple,
          NativeCredentialProviderKind.google,
        ]),
      );
    });
  });

  group('NativeCredentialResult', () {
    test('preserves fields', () {
      const r = NativeCredentialResult(
        provider: NativeCredentialProviderKind.google,
        idToken: 'id.token',
        authorizationCode: 'code-1',
        nonce: 'nonce-1',
        autoSelected: true,
      );
      expect(r.provider, NativeCredentialProviderKind.google);
      expect(r.idToken, 'id.token');
      expect(r.authorizationCode, 'code-1');
      expect(r.nonce, 'nonce-1');
      expect(r.autoSelected, isTrue);
    });

    test('allows optional authorizationCode and nonce', () {
      const r = NativeCredentialResult(
        provider: NativeCredentialProviderKind.apple,
        idToken: 'id.token',
        autoSelected: false,
      );
      expect(r.authorizationCode, isNull);
      expect(r.nonce, isNull);
    });

    test('equality and hashCode by value', () {
      const a = NativeCredentialResult(
        provider: NativeCredentialProviderKind.apple,
        idToken: 'id',
        authorizationCode: 'code',
        nonce: 'n',
        autoSelected: false,
      );
      const b = NativeCredentialResult(
        provider: NativeCredentialProviderKind.apple,
        idToken: 'id',
        authorizationCode: 'code',
        nonce: 'n',
        autoSelected: false,
      );
      const c = NativeCredentialResult(
        provider: NativeCredentialProviderKind.apple,
        idToken: 'different',
        authorizationCode: 'code',
        nonce: 'n',
        autoSelected: false,
      );
      expect(a, equals(b));
      expect(a.hashCode, b.hashCode);
      expect(a, isNot(equals(c)));
    });
  });

  group('NativeCredentialOutcome', () {
    test('ok carries a result and matches exhaustively', () {
      const result = NativeCredentialResult(
        provider: NativeCredentialProviderKind.google,
        idToken: 'id',
        autoSelected: true,
      );
      const NativeCredentialOutcome outcome = NativeCredentialOutcome.ok(
        result,
      );

      final matched = switch (outcome) {
        Ok(result: final r) => 'ok-${r.idToken}',
        NoSession() => 'no-session',
        Cancelled() => 'cancelled',
        Unavailable() => 'unavailable',
        ErrorOutcome() => 'error',
      };
      expect(matched, 'ok-id');
    });

    test('noSession, cancelled, unavailable, error variants', () {
      const NativeCredentialOutcome noSession =
          NativeCredentialOutcome.noSession();
      const NativeCredentialOutcome cancelled =
          NativeCredentialOutcome.cancelled();
      const NativeCredentialOutcome unavailable =
          NativeCredentialOutcome.unavailable('reason-xyz');
      final NativeCredentialOutcome error = NativeCredentialOutcome.error(
        AuthError(AuthErrorCode.nativeCredentialExchangeFailed, 'fail'),
      );

      expect(noSession, isA<NoSession>());
      expect(cancelled, isA<Cancelled>());
      expect(unavailable, isA<Unavailable>());
      expect((unavailable as Unavailable).reason, 'reason-xyz');
      expect(error, isA<ErrorOutcome>());
      expect(
        (error as ErrorOutcome).error.code,
        AuthErrorCode.nativeCredentialExchangeFailed,
      );
    });
  });

  group('AuthErrorCode native credential codes', () {
    test('retryability: issuerMismatch is non-retryable', () {
      expect(
        AuthError(AuthErrorCode.nativeCredentialIssuerMismatch, 'x').retryable,
        isFalse,
      );
    });

    test('retryability: other native credential codes are retryable', () {
      for (final c in const [
        AuthErrorCode.nativeCredentialCancelled,
        AuthErrorCode.nativeCredentialUnavailable,
        AuthErrorCode.nativeCredentialExchangeFailed,
      ]) {
        expect(AuthError(c, 'm').retryable, isTrue, reason: c.name);
      }
    });
  });
}
