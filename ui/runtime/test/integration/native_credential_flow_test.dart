import 'dart:convert';

import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter_test/flutter_test.dart';

import '_helpers.dart';
import 'mock_idp.dart';

/// Unsigned JWT builder — MockIdp does not verify signatures, so a plain
/// `header.payload.` suffices to exercise the exchange path.
String _jwt(Map<String, dynamic> payload) {
  String strip(String s) => s.replaceAll('=', '');
  final header = strip(
    base64Url.encode(
      utf8.encode(json.encode(const <String, String>{'alg': 'none'})),
    ),
  );
  final body = strip(base64Url.encode(utf8.encode(json.encode(payload))));
  return '$header.$body.';
}

/// Native provider stub that issues a matching-iss / matching-nonce
/// ID token the real `TokenWorker.completeNativeCredential` and the real
/// MockIdp will both accept. The goal of this test is to exercise every
/// production layer below the platform SDK — HTTP, DPoP, token-exchange,
/// session persistence — without spinning up a real Apple/Google stack.
class _StubGoogleProvider implements NativeCredentialProvider {
  _StubGoogleProvider();

  int silentCalls = 0;
  int interactiveCalls = 0;
  int signOutCalls = 0;

  @override
  NativeCredentialProviderKind get kind => NativeCredentialProviderKind.google;

  @override
  Future<bool> isAvailable() async => true;

  @override
  Future<NativeCredentialOutcome> attemptSilent({required String nonce}) async {
    silentCalls++;
    // Silent returns noSession so the waterfall proceeds to interactive
    // on `ensureAuthenticated`; keeps the test flow deterministic.
    return const NativeCredentialOutcome.noSession();
  }

  @override
  Future<NativeCredentialOutcome> attemptInteractive({
    required String nonce,
  }) async {
    interactiveCalls++;
    return NativeCredentialOutcome.ok(
      NativeCredentialResult(
        provider: NativeCredentialProviderKind.google,
        idToken: _jwt(<String, dynamic>{
          'iss': 'https://accounts.google.com',
          'sub': 'google-user-1',
          'aud': 'antinvestor-mobile',
          'nonce': nonce,
          'email': 'user@example.com',
          'email_verified': true,
          'name': 'Test User',
        }),
        autoSelected: false,
        nonce: nonce,
      ),
    );
  }

  @override
  Future<void> signOut() async {
    signOutCalls++;
  }
}

void main() {
  late IntegrationHarness harness;
  late _StubGoogleProvider provider;

  setUp(() async {
    // Pre-start the mock so we can configure the allowlist before the
    // runtime's first call — MockIdp defaults already cover Apple+Google
    // but we set the list explicitly to match the task spec.
    final mock = MockIdp();
    await mock.start();
    mock.setAllowedIssuers(const <String>[
      'https://appleid.apple.com',
      'https://accounts.google.com',
    ]);
    provider = _StubGoogleProvider();
    harness = await buildHarness(
      mock: mock,
      nativeProviders: <NativeCredentialProvider>[provider],
    );
  });

  tearDown(() async {
    await harness.dispose();
  });

  test('ensureAuthenticated completes via RFC 8693 token-exchange through the '
      'real MockIdp; no authorization_code grant; no OAuth popup', () async {
    // Let initialization and provider probes drain. Native credentials
    // must not be requested until the explicit interactive call below.
    for (var i = 0; i < 10; i++) {
      await Future<void>.delayed(Duration.zero);
    }
    expect(harness.runtime.state, AuthState.unauthenticated);
    expect(provider.silentCalls, 0);
    expect(harness.mock.tokenRequests, isEmpty);

    await harness.runtime.ensureAuthenticated();

    // Runtime is authenticated off the back of the token-exchange
    // response from MockIdp.
    expect(harness.runtime.state, AuthState.authenticated);

    // Exactly one /token hit, and it was the token-exchange grant —
    // the authorization_code path was never taken.
    expect(harness.mock.tokenRequests, hasLength(1));
    final req = harness.mock.tokenRequests.single;
    expect(req.grantType, 'urn:ietf:params:oauth:grant-type:token-exchange');
    expect(req.form['subject_issuer'], 'https://accounts.google.com');
    expect(
      req.form['subject_token_type'],
      'urn:ietf:params:oauth:token-type:id_token',
    );
    expect(req.form['client_id'], 'antinvestor-mobile');

    // Interactive was exercised exactly once; the OAuth popup (the
    // FakeOAuthFlow) was never invoked.
    expect(provider.interactiveCalls, 1);
    expect(harness.fakeOAuth.calls, 0);

    // Claims from the exchanged session are populated from the
    // MockIdp-issued ID token (sub carried over from the subject
    // token via the mock's claim-mapping rule).
    final claims = await harness.runtime.getClaims();
    expect(claims['sub'], 'google-user-1');
  });
}
