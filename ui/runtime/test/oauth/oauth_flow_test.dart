import 'package:antinvestor_auth_runtime/src/config/auth_config.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/oauth/oauth_flow.dart';
import 'package:antinvestor_auth_runtime/src/worker/token_worker.dart';
import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';

ResolvedConfig _cfg({String? redirectUri}) => resolveConfig(AuthConfig(
      clientId: 'c',
      idpBaseUrl: 'https://idp.example.com',
      apiBaseUrl: 'https://api.example.com',
      redirectScheme: 'com.example.app',
      redirectUri: redirectUri,
    ));

AuthorizeRequest _prepared({
  String url = 'https://idp.example.com/oauth2/auth?response_type=code',
  String verifier = 'V',
  String state = 'STATE-123',
  String nonce = 'NONCE-123',
}) =>
    AuthorizeRequest(url: url, verifier: verifier, state: state, nonce: nonce);

class _Recorder {
  String? seenUrl;
  String? seenScheme;
  FlutterWebAuth2Options? seenOptions;
  String? returnCallback;
  Object? throwError;

  Future<String> call({
    required String url,
    required String callbackUrlScheme,
    FlutterWebAuth2Options options = const FlutterWebAuth2Options(),
  }) async {
    seenUrl = url;
    seenScheme = callbackUrlScheme;
    seenOptions = options;
    final err = throwError;
    if (err != null) throw err;
    return returnCallback!;
  }
}

void main() {
  test('opens prepared.url and parses code + state from callback', () async {
    final rec = _Recorder()
      ..returnCallback =
          'com.example.app://callback?code=CODE-1&state=STATE-123';
    final flow = OAuthFlow(webAuth: rec.call);

    final result = await flow.authorize(_cfg(), _prepared());

    expect(result.code, 'CODE-1');
    expect(result.state, 'STATE-123');
    expect(rec.seenUrl,
        'https://idp.example.com/oauth2/auth?response_type=code');
    expect(rec.seenScheme, 'com.example.app');
  });

  test('https redirectUri sets httpsHost + httpsPath', () async {
    final rec = _Recorder()
      ..returnCallback =
          'https://app.example.com/auth?code=C&state=STATE-123';
    final flow = OAuthFlow(webAuth: rec.call);

    await flow.authorize(
      _cfg(redirectUri: 'https://app.example.com/auth'),
      _prepared(),
    );

    expect(rec.seenScheme, 'https');
    expect(rec.seenOptions?.httpsHost, 'app.example.com');
    expect(rec.seenOptions?.httpsPath, '/auth');
  });

  test('PlatformException CANCELED maps to oauthUserCanceled', () async {
    final rec = _Recorder()
      ..throwError = PlatformException(code: 'CANCELED');
    final flow = OAuthFlow(webAuth: rec.call);

    await expectLater(
      flow.authorize(_cfg(), _prepared()),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.oauthUserCanceled,
      )),
    );
  });

  test('PlatformException with non-cancel code maps to oauthFailed', () async {
    final rec = _Recorder()
      ..throwError = PlatformException(code: 'IO_ERROR');
    final flow = OAuthFlow(webAuth: rec.call);

    await expectLater(
      flow.authorize(_cfg(), _prepared()),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.oauthFailed,
      )),
    );
  });

  test('non-platform exception maps to oauthFailed', () async {
    final rec = _Recorder()..throwError = Exception('boom');
    final flow = OAuthFlow(webAuth: rec.call);

    await expectLater(
      flow.authorize(_cfg(), _prepared()),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.oauthFailed,
      )),
    );
  });

  test('callback with error=access_denied → oauthUserCanceled', () async {
    final rec = _Recorder()
      ..returnCallback = 'com.example.app://callback?error=access_denied'
          '&error_description=user%20said%20no';
    final flow = OAuthFlow(webAuth: rec.call);

    await expectLater(
      flow.authorize(_cfg(), _prepared()),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.oauthUserCanceled,
      )),
    );
  });

  test('callback with generic error → oauthFailed', () async {
    final rec = _Recorder()
      ..returnCallback =
          'com.example.app://callback?error=server_error&error_description=boom';
    final flow = OAuthFlow(webAuth: rec.call);

    await expectLater(
      flow.authorize(_cfg(), _prepared()),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.oauthFailed,
      )),
    );
  });

  test('callback missing code → oauthFailed', () async {
    final rec = _Recorder()
      ..returnCallback = 'com.example.app://callback?state=STATE-123';
    final flow = OAuthFlow(webAuth: rec.call);

    await expectLater(
      flow.authorize(_cfg(), _prepared()),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.oauthFailed,
      )),
    );
  });

  test('callback missing state → oauthFailed', () async {
    final rec = _Recorder()
      ..returnCallback = 'com.example.app://callback?code=C';
    final flow = OAuthFlow(webAuth: rec.call);

    await expectLater(
      flow.authorize(_cfg(), _prepared()),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.oauthFailed,
      )),
    );
  });

  test('redirectUri without a scheme raises invalidConfig', () async {
    // Bypass resolveConfig validation (which requires a scheme) by
    // constructing ResolvedConfig directly with a malformed redirect.
    const cfg = ResolvedConfig(
      clientId: 'c',
      idpBaseUrl: 'https://idp.example.com',
      apiBaseUrl: 'https://api.example.com',
      redirectScheme: '',
      redirectUri: '/no-scheme',
      scopes: ['openid'],
      audiences: [],
      installationId: null,
      discoveryTimeout: Duration(seconds: 10),
      tokenTimeout: Duration(seconds: 10),
      apiTimeout: Duration(seconds: 30),
      uploadTimeout: Duration(seconds: 60),
    );
    final rec = _Recorder()..returnCallback = '';
    final flow = OAuthFlow(webAuth: rec.call);

    await expectLater(
      flow.authorize(cfg, _prepared()),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.invalidConfig,
      )),
    );
  });
}
