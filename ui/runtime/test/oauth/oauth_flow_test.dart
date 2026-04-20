import 'package:antinvestor_auth_runtime/src/config/auth_config.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/oauth/oauth_flow.dart';
import 'package:antinvestor_auth_runtime/src/protocol/discovery.dart';
import 'package:flutter_appauth/flutter_appauth.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';

class _MockAppAuth extends Mock implements FlutterAppAuth {}

class _FakeAuthorizationRequest extends Fake implements AuthorizationRequest {}

ResolvedConfig _cfg({String? redirectUri}) => resolveConfig(AuthConfig(
      clientId: 'c',
      idpBaseUrl: 'https://idp.example.com',
      apiBaseUrl: 'https://api.example.com',
      redirectScheme: 'com.example.app',
      redirectUri: redirectUri,
    ));

Future<OidcDiscovery> _fakeDiscovery(ResolvedConfig cfg) async =>
    const OidcDiscovery(
      issuer: 'https://idp.example.com',
      authorizationEndpoint: 'https://idp.example.com/oauth2/auth',
      tokenEndpoint: 'https://idp.example.com/oauth2/token',
      endSessionEndpoint: 'https://idp.example.com/oauth2/sessions/logout',
    );

void main() {
  setUpAll(() {
    registerFallbackValue(_FakeAuthorizationRequest());
  });

  test('successful authorize returns code + verifier', () async {
    final appAuth = _MockAppAuth();
    when(() => appAuth.authorize(any())).thenAnswer((_) async =>
        const AuthorizationResponse(
          authorizationCode: 'CODE-1',
          codeVerifier: 'VERIF-1',
          nonce: 'N-1',
        ));
    final flow = OAuthFlow(appAuth: appAuth, discoveryFn: _fakeDiscovery);

    final result = await flow.authorize(_cfg());
    expect(result.code, 'CODE-1');
    expect(result.verifier, 'VERIF-1');
    expect(result.nonce, 'N-1');
  });

  test('AuthorizationRequest is built from ResolvedConfig + discovery',
      () async {
    final appAuth = _MockAppAuth();
    AuthorizationRequest? seen;
    when(() => appAuth.authorize(any())).thenAnswer((inv) async {
      seen = inv.positionalArguments.first as AuthorizationRequest;
      return const AuthorizationResponse(
        authorizationCode: 'c',
        codeVerifier: 'v',
      );
    });

    final flow = OAuthFlow(appAuth: appAuth, discoveryFn: _fakeDiscovery);
    await flow.authorize(_cfg());

    expect(seen, isNotNull);
    expect(seen!.clientId, 'c');
    expect(seen!.redirectUrl, 'com.example.app://callback');
    expect(seen!.scopes, contains('openid'));
    expect(seen!.serviceConfiguration?.authorizationEndpoint,
        'https://idp.example.com/oauth2/auth');
    expect(seen!.serviceConfiguration?.tokenEndpoint,
        'https://idp.example.com/oauth2/token');
  });

  test('FlutterAppAuthUserCancelledException maps to oauthUserCanceled',
      () async {
    final appAuth = _MockAppAuth();
    when(() => appAuth.authorize(any())).thenThrow(
      FlutterAppAuthUserCancelledException(
        code: 'cancelled',
        platformErrorDetails:
            FlutterAppAuthPlatformErrorDetails(error: 'user_cancelled'),
      ),
    );

    final flow = OAuthFlow(appAuth: appAuth, discoveryFn: _fakeDiscovery);
    await expectLater(
      flow.authorize(_cfg()),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.oauthUserCanceled,
      )),
    );
  });

  test('other exceptions map to oauthFailed', () async {
    final appAuth = _MockAppAuth();
    when(() => appAuth.authorize(any())).thenThrow(
      Exception('boom'),
    );

    final flow = OAuthFlow(appAuth: appAuth, discoveryFn: _fakeDiscovery);
    await expectLater(
      flow.authorize(_cfg()),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.oauthFailed,
      )),
    );
  });

  test(
      'explicit redirectUri override is forwarded verbatim to flutter_appauth',
      () async {
    final appAuth = _MockAppAuth();
    AuthorizationRequest? seen;
    when(() => appAuth.authorize(any())).thenAnswer((inv) async {
      seen = inv.positionalArguments.first as AuthorizationRequest;
      return const AuthorizationResponse(
        authorizationCode: 'c',
        codeVerifier: 'v',
      );
    });

    final flow = OAuthFlow(appAuth: appAuth, discoveryFn: _fakeDiscovery);
    await flow.authorize(_cfg(redirectUri: 'http://localhost:5173/auth'));

    expect(seen, isNotNull);
    // Explicit redirect URI wins over the convention-driven
    // `{scheme}://callback` fallback.
    expect(seen!.redirectUrl, 'http://localhost:5173/auth');
  });

  test('missing code/verifier raises oauthFailed', () async {
    final appAuth = _MockAppAuth();
    when(() => appAuth.authorize(any())).thenAnswer((_) async =>
        const AuthorizationResponse(authorizationCode: null, codeVerifier: 'v'));

    final flow = OAuthFlow(appAuth: appAuth, discoveryFn: _fakeDiscovery);
    await expectLater(
      flow.authorize(_cfg()),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.oauthFailed,
      )),
    );
  });
}
