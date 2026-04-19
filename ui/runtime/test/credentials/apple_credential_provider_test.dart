import 'dart:convert';

import 'package:antinvestor_auth_runtime/src/credentials/apple_credential_provider.dart';
import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

class _MockAdapter extends Mock implements SignInWithAppleAdapter {}

class _FakeCredential implements AuthorizationCredentialAppleID {
  _FakeCredential({
    required this.identityToken,
    required this.authorizationCode,
  });

  @override
  final String? identityToken;

  @override
  final String authorizationCode;

  @override
  String? get email => null;
  @override
  String? get familyName => null;
  @override
  String? get givenName => null;
  @override
  String? get state => null;
  @override
  String? get userIdentifier => 'user-1';
}

void main() {
  setUpAll(() {
    registerFallbackValue(<AppleIDAuthorizationScopes>[]);
  });

  group('AppleCredentialProvider', () {
    test('kind is apple', () {
      final provider = AppleCredentialProvider(adapter: _MockAdapter());
      expect(provider.kind, NativeCredentialProviderKind.apple);
    });

    test('isAvailable delegates to adapter', () async {
      final adapter = _MockAdapter();
      when(adapter.isAvailable).thenAnswer((_) async => true);
      final provider = AppleCredentialProvider(adapter: adapter);

      expect(await provider.isAvailable(), isTrue);
      verify(adapter.isAvailable).called(1);
    });

    test('attemptSilent always returns noSession', () async {
      final adapter = _MockAdapter();
      final provider = AppleCredentialProvider(adapter: adapter);

      final outcome = await provider.attemptSilent(nonce: 'n');
      expect(outcome, isA<NoSession>());
      verifyNever(
        () => adapter.getAppleIDCredential(
          scopes: any(named: 'scopes'),
          nonce: any(named: 'nonce'),
        ),
      );
    });

    test('attemptInteractive passes SHA-256 hex of nonce and wraps result',
        () async {
      const nonce = 'raw-nonce-xyz';
      final expectedHash = sha256.convert(utf8.encode(nonce)).toString();

      final adapter = _MockAdapter();
      when(
        () => adapter.getAppleIDCredential(
          scopes: any(named: 'scopes'),
          nonce: any(named: 'nonce'),
        ),
      ).thenAnswer(
        (_) async => _FakeCredential(
          identityToken: 'id.token',
          authorizationCode: 'code-abc',
        ),
      );

      final provider = AppleCredentialProvider(adapter: adapter);
      final outcome = await provider.attemptInteractive(nonce: nonce);

      expect(outcome, isA<Ok>());
      final ok = outcome as Ok;
      expect(ok.result.provider, NativeCredentialProviderKind.apple);
      expect(ok.result.idToken, 'id.token');
      expect(ok.result.authorizationCode, 'code-abc');
      expect(ok.result.nonce, nonce);
      expect(ok.result.autoSelected, isFalse);

      final captured = verify(
        () => adapter.getAppleIDCredential(
          scopes: captureAny(named: 'scopes'),
          nonce: captureAny(named: 'nonce'),
        ),
      ).captured;
      final capturedScopes =
          captured[0] as List<AppleIDAuthorizationScopes>;
      final capturedNonce = captured[1] as String?;
      expect(
        capturedScopes,
        containsAll(<AppleIDAuthorizationScopes>[
          AppleIDAuthorizationScopes.email,
          AppleIDAuthorizationScopes.fullName,
        ]),
      );
      expect(capturedNonce, expectedHash);
    });

    test('attemptInteractive with null identityToken returns error', () async {
      final adapter = _MockAdapter();
      when(
        () => adapter.getAppleIDCredential(
          scopes: any(named: 'scopes'),
          nonce: any(named: 'nonce'),
        ),
      ).thenAnswer(
        (_) async => _FakeCredential(
          identityToken: null,
          authorizationCode: 'code-abc',
        ),
      );

      final provider = AppleCredentialProvider(adapter: adapter);
      final outcome = await provider.attemptInteractive(nonce: 'n');

      expect(outcome, isA<ErrorOutcome>());
      final e = outcome as ErrorOutcome;
      expect(e.error.code, AuthErrorCode.nativeCredentialUnavailable);
    });

    test('attemptInteractive maps canceled → cancelled()', () async {
      final adapter = _MockAdapter();
      when(
        () => adapter.getAppleIDCredential(
          scopes: any(named: 'scopes'),
          nonce: any(named: 'nonce'),
        ),
      ).thenThrow(
        const SignInWithAppleAuthorizationException(
          code: AuthorizationErrorCode.canceled,
          message: 'user cancelled',
        ),
      );

      final provider = AppleCredentialProvider(adapter: adapter);
      final outcome = await provider.attemptInteractive(nonce: 'n');
      expect(outcome, isA<Cancelled>());
    });

    test('attemptInteractive maps other auth error codes → unavailable',
        () async {
      final adapter = _MockAdapter();
      when(
        () => adapter.getAppleIDCredential(
          scopes: any(named: 'scopes'),
          nonce: any(named: 'nonce'),
        ),
      ).thenThrow(
        const SignInWithAppleAuthorizationException(
          code: AuthorizationErrorCode.notHandled,
          message: 'no handler',
        ),
      );

      final provider = AppleCredentialProvider(adapter: adapter);
      final outcome = await provider.attemptInteractive(nonce: 'n');
      expect(outcome, isA<ErrorOutcome>());
      final e = outcome as ErrorOutcome;
      expect(e.error.code, AuthErrorCode.nativeCredentialUnavailable);
      expect(e.error.message, contains('notHandled'));
    });

    test('attemptInteractive maps other exceptions → exchangeFailed',
        () async {
      final adapter = _MockAdapter();
      when(
        () => adapter.getAppleIDCredential(
          scopes: any(named: 'scopes'),
          nonce: any(named: 'nonce'),
        ),
      ).thenThrow(StateError('boom'));

      final provider = AppleCredentialProvider(adapter: adapter);
      final outcome = await provider.attemptInteractive(nonce: 'n');
      expect(outcome, isA<ErrorOutcome>());
      final e = outcome as ErrorOutcome;
      expect(e.error.code, AuthErrorCode.nativeCredentialExchangeFailed);
    });

    test('signOut is a no-op', () async {
      final adapter = _MockAdapter();
      final provider = AppleCredentialProvider(adapter: adapter);
      await provider.signOut();
      verifyZeroInteractions(adapter);
    });
  });
}
