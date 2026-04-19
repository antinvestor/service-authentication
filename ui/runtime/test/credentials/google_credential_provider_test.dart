import 'package:antinvestor_auth_runtime/src/credentials/google_credential_provider.dart';
import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:mocktail/mocktail.dart';

class _MockAdapter extends Mock implements GoogleSignInAdapter {}

/// Fake account exposing only what the provider reads.
class _FakeGoogleAccount implements GoogleSignInAccountView {
  _FakeGoogleAccount({required this.idToken});

  @override
  final String? idToken;
}

void main() {
  group('GoogleCredentialProvider', () {
    test('kind is google', () {
      final provider = GoogleCredentialProvider(
        serverClientId: 'server-id',
        adapter: _MockAdapter(),
      );
      expect(provider.kind, NativeCredentialProviderKind.google);
    });

    test('isAvailable returns true', () async {
      final provider = GoogleCredentialProvider(
        serverClientId: 'server-id',
        adapter: _MockAdapter(),
      );
      expect(await provider.isAvailable(), isTrue);
    });

    test('attemptSilent returns noSession when adapter returns null',
        () async {
      final adapter = _MockAdapter();
      when(
        () => adapter.initialize(
          serverClientId: any(named: 'serverClientId'),
          nonce: any(named: 'nonce'),
        ),
      ).thenAnswer((_) async {});
      when(adapter.attemptLightweightAuthentication)
          .thenAnswer((_) async => null);

      final provider = GoogleCredentialProvider(
        serverClientId: 'sc',
        adapter: adapter,
      );
      final outcome = await provider.attemptSilent(nonce: 'n1');

      expect(outcome, isA<NoSession>());
      verify(
        () => adapter.initialize(serverClientId: 'sc', nonce: 'n1'),
      ).called(1);
    });

    test('attemptSilent returns unavailable when account has no idToken',
        () async {
      final adapter = _MockAdapter();
      when(
        () => adapter.initialize(
          serverClientId: any(named: 'serverClientId'),
          nonce: any(named: 'nonce'),
        ),
      ).thenAnswer((_) async {});
      when(adapter.attemptLightweightAuthentication)
          .thenAnswer((_) async => _FakeGoogleAccount(idToken: null));

      final provider = GoogleCredentialProvider(
        serverClientId: 'sc',
        adapter: adapter,
      );
      final outcome = await provider.attemptSilent(nonce: 'n1');

      expect(outcome, isA<ErrorOutcome>());
      final e = outcome as ErrorOutcome;
      expect(e.error.code, AuthErrorCode.nativeCredentialUnavailable);
    });

    test('attemptSilent returns ok with autoSelected=true on account',
        () async {
      final adapter = _MockAdapter();
      when(
        () => adapter.initialize(
          serverClientId: any(named: 'serverClientId'),
          nonce: any(named: 'nonce'),
        ),
      ).thenAnswer((_) async {});
      when(adapter.attemptLightweightAuthentication).thenAnswer(
        (_) async => _FakeGoogleAccount(idToken: 'id.silent'),
      );

      final provider = GoogleCredentialProvider(
        serverClientId: 'sc',
        adapter: adapter,
      );
      final outcome = await provider.attemptSilent(nonce: 'n1');

      expect(outcome, isA<Ok>());
      final ok = outcome as Ok;
      expect(ok.result.idToken, 'id.silent');
      expect(ok.result.provider, NativeCredentialProviderKind.google);
      expect(ok.result.nonce, 'n1');
      expect(ok.result.autoSelected, isTrue);
      expect(ok.result.authorizationCode, isNull);
    });

    test('attemptInteractive returns ok with autoSelected=false', () async {
      final adapter = _MockAdapter();
      when(
        () => adapter.initialize(
          serverClientId: any(named: 'serverClientId'),
          nonce: any(named: 'nonce'),
        ),
      ).thenAnswer((_) async {});
      when(
        () => adapter.authenticate(scopeHint: any(named: 'scopeHint')),
      ).thenAnswer(
        (_) async => _FakeGoogleAccount(idToken: 'id.interactive'),
      );

      final provider = GoogleCredentialProvider(
        serverClientId: 'sc',
        adapter: adapter,
      );
      final outcome = await provider.attemptInteractive(nonce: 'n2');

      expect(outcome, isA<Ok>());
      final ok = outcome as Ok;
      expect(ok.result.idToken, 'id.interactive');
      expect(ok.result.autoSelected, isFalse);
      expect(ok.result.nonce, 'n2');
      verify(() => adapter.initialize(serverClientId: 'sc', nonce: 'n2'))
          .called(1);
    });

    test('attemptInteractive maps canceled → cancelled()', () async {
      final adapter = _MockAdapter();
      when(
        () => adapter.initialize(
          serverClientId: any(named: 'serverClientId'),
          nonce: any(named: 'nonce'),
        ),
      ).thenAnswer((_) async {});
      when(
        () => adapter.authenticate(scopeHint: any(named: 'scopeHint')),
      ).thenThrow(
        const GoogleSignInException(
          code: GoogleSignInExceptionCode.canceled,
          description: 'user cancelled',
        ),
      );

      final provider = GoogleCredentialProvider(
        serverClientId: 'sc',
        adapter: adapter,
      );
      final outcome = await provider.attemptInteractive(nonce: 'n');
      expect(outcome, isA<Cancelled>());
    });

    test('attemptInteractive maps other exceptions → exchangeFailed',
        () async {
      final adapter = _MockAdapter();
      when(
        () => adapter.initialize(
          serverClientId: any(named: 'serverClientId'),
          nonce: any(named: 'nonce'),
        ),
      ).thenAnswer((_) async {});
      when(
        () => adapter.authenticate(scopeHint: any(named: 'scopeHint')),
      ).thenThrow(StateError('boom'));

      final provider = GoogleCredentialProvider(
        serverClientId: 'sc',
        adapter: adapter,
      );
      final outcome = await provider.attemptInteractive(nonce: 'n');
      expect(outcome, isA<ErrorOutcome>());
      final e = outcome as ErrorOutcome;
      expect(e.error.code, AuthErrorCode.nativeCredentialExchangeFailed);
    });

    test('attemptInteractive with GoogleSignInException (non-cancel) → error',
        () async {
      final adapter = _MockAdapter();
      when(
        () => adapter.initialize(
          serverClientId: any(named: 'serverClientId'),
          nonce: any(named: 'nonce'),
        ),
      ).thenAnswer((_) async {});
      when(
        () => adapter.authenticate(scopeHint: any(named: 'scopeHint')),
      ).thenThrow(
        const GoogleSignInException(
          code: GoogleSignInExceptionCode.clientConfigurationError,
          description: 'bad client id',
        ),
      );

      final provider = GoogleCredentialProvider(
        serverClientId: 'sc',
        adapter: adapter,
      );
      final outcome = await provider.attemptInteractive(nonce: 'n');
      expect(outcome, isA<ErrorOutcome>());
      final e = outcome as ErrorOutcome;
      expect(e.error.code, AuthErrorCode.nativeCredentialExchangeFailed);
      expect(e.error.message, contains('clientConfigurationError'));
    });

    test('signOut delegates to adapter', () async {
      final adapter = _MockAdapter();
      when(adapter.signOut).thenAnswer((_) async {});
      final provider = GoogleCredentialProvider(
        serverClientId: 'sc',
        adapter: adapter,
      );

      await provider.signOut();
      verify(adapter.signOut).called(1);
    });
  });
}
