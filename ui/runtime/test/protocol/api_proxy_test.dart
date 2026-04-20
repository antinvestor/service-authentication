import 'dart:async';
import 'dart:convert';

import 'package:antinvestor_auth_runtime/src/config/auth_config.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/models/token_set.dart';
import 'package:antinvestor_auth_runtime/src/protocol/api_proxy.dart';
import 'package:antinvestor_auth_runtime/src/protocol/dpop.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

ResolvedConfig _cfg() => resolveConfig(const AuthConfig(
      clientId: 'c',
      idpBaseUrl: 'https://idp.example.com',
      apiBaseUrl: 'https://api.example.com',
      redirectScheme: 'com.example.app',
    ));

class _TestTokenProvider implements TokenProvider {
  _TestTokenProvider({
    String initialAccess = 'at-1',
    TokenType type = TokenType.bearer,
    String refreshedAccess = 'at-2',
  })  : _access = initialAccess,
        _type = type,
        _refreshed = refreshedAccess;

  String _access;
  final TokenType _type;
  final String _refreshed;
  int refreshCount = 0;
  int forcedRefreshCount = 0;
  int onRefreshNotifications = 0;

  @override
  Future<TokenSnapshot> ensureFresh({bool force = false}) async {
    if (force) {
      forcedRefreshCount++;
      _access = _refreshed;
    }
    refreshCount++;
    return TokenSnapshot(accessToken: _access, tokenType: _type);
  }

  @override
  void onRefresh() {
    onRefreshNotifications++;
  }
}

void main() {
  group('fetch', () {
    test('attaches Bearer Authorization in bearer mode', () async {
      final cfg = _cfg();
      late http.Request captured;
      final client = MockClient((req) async {
        captured = req;
        return http.Response('{"ok":true}', 200,
            headers: {'content-type': 'application/json'});
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      final response = await proxy.fetch(
        cfg,
        ctx,
        _TestTokenProvider(),
        path: '/v1/ping',
        method: 'GET',
      );
      expect(response.status, 200);
      expect(captured.url.toString(), 'https://api.example.com/v1/ping');
      expect(captured.headers['authorization'], 'Bearer at-1');
      expect(captured.headers.containsKey('dpop'), isFalse);
      expect(utf8.decode(response.body), '{"ok":true}');
    });

    test('attaches DPoP + proof in DPoP mode', () async {
      final cfg = _cfg();
      late http.Request captured;
      final client = MockClient((req) async {
        captured = req;
        return http.Response('{}', 200);
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      await proxy.fetch(
        cfg,
        ctx,
        _TestTokenProvider(type: TokenType.dpop),
        path: '/v1/ping',
        method: 'POST',
        body: '{"x":1}',
      );
      expect(captured.headers['authorization'], 'DPoP at-1');
      expect(captured.headers.containsKey('dpop'), isTrue);
      expect(captured.headers['content-type'], contains('application/json'));
    });

    test('401 triggers a single forced refresh + retry', () async {
      final cfg = _cfg();
      var calls = 0;
      final client = MockClient((req) async {
        calls++;
        final auth = req.headers['authorization'];
        if (calls == 1) {
          expect(auth, 'Bearer at-1');
          return http.Response('{}', 401);
        }
        expect(auth, 'Bearer at-2');
        return http.Response('{"ok":true}', 200);
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      final tp = _TestTokenProvider();
      final res = await proxy.fetch(
        cfg,
        ctx,
        tp,
        path: '/v1/x',
        method: 'GET',
      );
      expect(res.status, 200);
      expect(calls, 2);
      expect(tp.forcedRefreshCount, 1);
      expect(tp.onRefreshNotifications, 1);
    });

    test('dpop-nonce challenge is retried before forcing refresh', () async {
      final cfg = _cfg();
      var calls = 0;
      final client = MockClient((req) async {
        calls++;
        if (calls == 1) {
          return http.Response('{}', 401,
              headers: {'dpop-nonce': 'n-new'});
        }
        return http.Response('{"ok":true}', 200);
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      final tp = _TestTokenProvider(type: TokenType.dpop);
      final res = await proxy.fetch(
        cfg,
        ctx,
        tp,
        path: '/v1/x',
        method: 'GET',
      );
      expect(res.status, 200);
      expect(tp.forcedRefreshCount, 0);
      expect(ctx.nonceByOrigin['https://api.example.com'], 'n-new');
    });

    test('204 returns empty body', () async {
      final cfg = _cfg();
      final client = MockClient((req) async => http.Response('', 204));
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      final res = await proxy.fetch(
        cfg,
        ctx,
        _TestTokenProvider(),
        path: '/v1/x',
        method: 'DELETE',
      );
      expect(res.status, 204);
      expect(res.body, isEmpty);
    });

    test('403 maps to apiForbidden', () async {
      final cfg = _cfg();
      final client = MockClient((req) async => http.Response('nope', 403));
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      await expectLater(
        proxy.fetch(cfg, ctx, _TestTokenProvider(),
            path: '/v1/x', method: 'GET'),
        throwsA(isA<AuthError>()
            .having((e) => e.code, 'code', AuthErrorCode.apiForbidden)),
      );
    });

    test('404 maps to apiNotFound', () async {
      final cfg = _cfg();
      final client = MockClient((req) async => http.Response('nf', 404));
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      await expectLater(
        proxy.fetch(cfg, ctx, _TestTokenProvider(),
            path: '/v1/x', method: 'GET'),
        throwsA(isA<AuthError>()
            .having((e) => e.code, 'code', AuthErrorCode.apiNotFound)),
      );
    });

    test('500 maps to apiServerError with trace id', () async {
      final cfg = _cfg();
      final client = MockClient((req) async => http.Response('boom', 500,
          headers: {'x-trace-id': 'trace-xyz'}));
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      try {
        await proxy.fetch(cfg, ctx, _TestTokenProvider(),
            path: '/v1/x', method: 'GET');
        fail('expected throw');
      } on AuthError catch (e) {
        expect(e.code, AuthErrorCode.apiServerError);
        expect(e.traceId, 'trace-xyz');
      }
    });

    test('persistent 401 after retry maps to apiUnauthorized', () async {
      final cfg = _cfg();
      final client = MockClient((req) async => http.Response('nope', 401));
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      await expectLater(
        proxy.fetch(cfg, ctx, _TestTokenProvider(),
            path: '/v1/x', method: 'GET'),
        throwsA(isA<AuthError>()
            .having((e) => e.code, 'code', AuthErrorCode.apiUnauthorized)),
      );
    });

    test('timeout maps to networkTimeout', () async {
      final cfg = _cfg();
      final client = MockClient((req) async {
        await Future<void>.delayed(const Duration(milliseconds: 100));
        return http.Response('', 200);
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      await expectLater(
        proxy.fetch(cfg, ctx, _TestTokenProvider(),
            path: '/v1/x',
            method: 'GET',
            timeout: const Duration(milliseconds: 20)),
        throwsA(isA<AuthError>()
            .having((e) => e.code, 'code', AuthErrorCode.networkTimeout)),
      );
    });
  });

  group('upload', () {
    test('multipart request attaches auth and propagates response', () async {
      final cfg = _cfg();
      late http.BaseRequest captured;
      final client = MockClient.streaming((req, body) async {
        captured = req;
        return http.StreamedResponse(
          Stream.value(utf8.encode('{"stored":true}')),
          200,
          headers: {'content-type': 'application/json'},
        );
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      final res = await proxy.upload(
        cfg,
        ctx,
        _TestTokenProvider(),
        path: '/v1/file',
        fieldName: 'file',
        filename: 'a.bin',
        contentType: 'application/octet-stream',
        bytes: Stream.value(const [0x01, 0x02, 0x03]),
        length: 3,
      );
      expect(res.status, 200);
      expect(captured.headers['authorization'], 'Bearer at-1');
      expect(captured is http.MultipartRequest, isTrue);
    });
  });

  group('absolute URLs', () {
    test('fetch with https:// URL hits it exactly and skips apiBaseUrl',
        () async {
      final cfg = _cfg();
      late http.Request captured;
      final client = MockClient((req) async {
        captured = req;
        return http.Response('{"ok":true}', 200);
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      await proxy.fetch(
        cfg,
        ctx,
        _TestTokenProvider(),
        path: 'https://other.example.com/api/foo',
        method: 'GET',
      );
      expect(captured.url.toString(), 'https://other.example.com/api/foo');
      // apiBaseUrl must not be prepended.
      expect(captured.url.toString(), isNot(contains('api.example.com')));
    });

    test('fetch with http:// URL is used directly', () async {
      final cfg = _cfg();
      late http.Request captured;
      final client = MockClient((req) async {
        captured = req;
        return http.Response('{}', 200);
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      await proxy.fetch(
        cfg,
        ctx,
        _TestTokenProvider(),
        path: 'http://localhost:8080/v1/x',
        method: 'GET',
      );
      expect(captured.url.toString(), 'http://localhost:8080/v1/x');
    });

    test('fetch with relative path still hits apiBaseUrl + path', () async {
      final cfg = _cfg();
      late http.Request captured;
      final client = MockClient((req) async {
        captured = req;
        return http.Response('{}', 200);
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      await proxy.fetch(
        cfg,
        ctx,
        _TestTokenProvider(),
        path: '/relative/path',
        method: 'GET',
      );
      expect(captured.url.toString(), 'https://api.example.com/relative/path');
    });

    test('upload with https:// URL hits the absolute URL', () async {
      final cfg = _cfg();
      late http.BaseRequest captured;
      final client = MockClient.streaming((req, body) async {
        captured = req;
        return http.StreamedResponse(
          Stream.value(utf8.encode('{}')),
          200,
        );
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      await proxy.upload(
        cfg,
        ctx,
        _TestTokenProvider(),
        path: 'https://upload.example.com/files',
        fieldName: 'file',
        filename: 'a.bin',
        contentType: 'application/octet-stream',
        bytes: Stream.value(const [0x01, 0x02, 0x03]),
        length: 3,
      );
      expect(captured.url.toString(), 'https://upload.example.com/files');
      expect(captured.url.toString(), isNot(contains('api.example.com')));
    });

    test('DPoP proof htu matches the absolute URL actually used', () async {
      final cfg = _cfg();
      late http.Request captured;
      final client = MockClient((req) async {
        captured = req;
        return http.Response('{}', 200);
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final proxy = ApiProxy(client: client);
      await proxy.fetch(
        cfg,
        ctx,
        _TestTokenProvider(type: TokenType.dpop),
        path: 'https://other.example.com/api/foo',
        method: 'POST',
        body: '{}',
      );
      final proof = captured.headers['dpop'];
      expect(proof, isNotNull);
      final parts = proof!.split('.');
      expect(parts.length, 3);
      final payloadJson = utf8.decode(
        base64Url.decode(_padBase64Url(parts[1])),
      );
      final payload = jsonDecode(payloadJson) as Map<String, dynamic>;
      expect(payload['htu'], 'https://other.example.com/api/foo');
      expect(payload['htm'], 'POST');
    });
  });
}

String _padBase64Url(String s) {
  final pad = (4 - s.length % 4) % 4;
  return s + ('=' * pad);
}
