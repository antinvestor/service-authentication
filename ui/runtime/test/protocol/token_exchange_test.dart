import 'dart:convert';

import 'package:antinvestor_auth_runtime/src/config/auth_config.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/models/token_set.dart';
import 'package:antinvestor_auth_runtime/src/protocol/discovery.dart';
import 'package:antinvestor_auth_runtime/src/protocol/dpop.dart';
import 'package:antinvestor_auth_runtime/src/protocol/token_exchange.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

const _timeout = Duration(seconds: 5);

ResolvedConfig _cfg() => resolveConfig(const AuthConfig(
      clientId: 'c',
      idpBaseUrl: 'https://idp.example.com',
      apiBaseUrl: 'https://api.example.com',
      redirectScheme: 'com.example.app',
    ));

Map<String, dynamic> _discoveryDoc({bool dpop = false}) => <String, dynamic>{
      'issuer': 'https://idp.example.com',
      'authorization_endpoint': 'https://idp.example.com/oauth2/auth',
      'token_endpoint': 'https://idp.example.com/oauth2/token',
      if (dpop) 'dpop_signing_alg_values_supported': ['ES256'],
    };

Map<String, dynamic> _tokenResp({
  String accessToken = 'at-1',
  String refreshToken = 'rt-1',
  int expiresIn = 300,
  String tokenType = 'Bearer',
  String? idToken,
}) =>
    <String, dynamic>{
      'access_token': accessToken,
      'refresh_token': refreshToken,
      'expires_in': expiresIn,
      'token_type': tokenType,
      'id_token': ?idToken,
    };

void main() {
  setUp(clearDiscoveryCache);

  group('exchangeCode', () {
    test('bearer-mode exchange posts authorization_code grant', () async {
      final cfg = _cfg();
      final calls = <http.Request>[];
      final client = MockClient((req) async {
        calls.add(req);
        if (req.url.path.endsWith('/.well-known/openid-configuration')) {
          return http.Response(jsonEncode(_discoveryDoc()), 200);
        }
        expect(req.url.toString(), 'https://idp.example.com/oauth2/token');
        expect(req.headers['content-type'],
            startsWith('application/x-www-form-urlencoded'));
        expect(req.headers.containsKey('dpop'), isFalse);
        final form = Uri.splitQueryString(req.body);
        expect(form['grant_type'], 'authorization_code');
        expect(form['client_id'], 'c');
        expect(form['code'], 'code-xyz');
        expect(form['code_verifier'], 'verifier-xyz');
        expect(form['redirect_uri'], 'com.example.app://callback');
        return http.Response(jsonEncode(_tokenResp()), 200,
            headers: {'content-type': 'application/json'});
      });

      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final exchange = TokenExchange(client: client, timeout: _timeout);
      final tokens = await exchange.exchangeCode(
        cfg,
        ctx,
        code: 'code-xyz',
        verifier: 'verifier-xyz',
      );
      expect(tokens.accessToken, 'at-1');
      expect(tokens.refreshToken, 'rt-1');
      expect(tokens.tokenType, TokenType.bearer);
    });

    test('DPoP-mode adds DPoP header and retries on nonce challenge',
        () async {
      final cfg = _cfg();
      var tokenCalls = 0;
      final client = MockClient((req) async {
        if (req.url.path.endsWith('/.well-known/openid-configuration')) {
          return http.Response(jsonEncode(_discoveryDoc(dpop: true)), 200);
        }
        tokenCalls++;
        expect(req.headers.containsKey('dpop'), isTrue);
        if (tokenCalls == 1) {
          return http.Response(
            jsonEncode({'error': 'use_dpop_nonce'}),
            401,
            headers: {'dpop-nonce': 'n-fresh'},
          );
        }
        // On retry the nonce should be present in the proof payload.
        final proof = req.headers['dpop']!;
        final payloadB64 = proof.split('.')[1];
        final padded = payloadB64.padRight(
            payloadB64.length + (4 - payloadB64.length % 4) % 4, '=');
        final payload =
            jsonDecode(utf8.decode(base64Url.decode(padded))) as Map;
        expect(payload['nonce'], 'n-fresh');
        return http.Response(jsonEncode(_tokenResp(tokenType: 'DPoP')), 200);
      });

      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final exchange = TokenExchange(client: client, timeout: _timeout);
      final tokens = await exchange.exchangeCode(
        cfg,
        ctx,
        code: 'c',
        verifier: 'v',
      );
      expect(tokens.tokenType, TokenType.dpop);
      expect(tokenCalls, 2);
    });

    test('clock-skew retry on invalid_dpop_proof', () async {
      final cfg = _cfg();
      var tokenCalls = 0;
      final client = MockClient((req) async {
        if (req.url.path.endsWith('/.well-known/openid-configuration')) {
          return http.Response(jsonEncode(_discoveryDoc(dpop: true)), 200);
        }
        tokenCalls++;
        if (tokenCalls == 1) {
          return http.Response(
            jsonEncode({'error': 'invalid_dpop_proof'}),
            400,
            headers: {'date': 'Thu, 01 Jan 2099 00:00:00 GMT'},
          );
        }
        return http.Response(jsonEncode(_tokenResp(tokenType: 'DPoP')), 200);
      });

      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final exchange = TokenExchange(client: client, timeout: _timeout);
      final tokens = await exchange.exchangeCode(
        cfg,
        ctx,
        code: 'c',
        verifier: 'v',
      );
      expect(tokens.accessToken, 'at-1');
      expect(tokenCalls, 2);
      expect(ctx.clockOffsetMs, greaterThan(0));
    });

    test('non-2xx final response raises tokenExchangeFailed', () async {
      final cfg = _cfg();
      final client = MockClient((req) async {
        if (req.url.path.endsWith('/.well-known/openid-configuration')) {
          return http.Response(jsonEncode(_discoveryDoc()), 200);
        }
        return http.Response('{"error":"invalid_request"}', 400);
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final exchange = TokenExchange(client: client, timeout: _timeout);
      await expectLater(
        exchange.exchangeCode(cfg, ctx, code: 'c', verifier: 'v'),
        throwsA(isA<AuthError>()
            .having((e) => e.code, 'code', AuthErrorCode.tokenExchangeFailed)),
      );
    });
  });

  group('refresh', () {
    test('rotating refresh returns RefreshOutcome.rotated', () async {
      final cfg = _cfg();
      final client = MockClient((req) async {
        if (req.url.path.endsWith('/.well-known/openid-configuration')) {
          return http.Response(jsonEncode(_discoveryDoc()), 200);
        }
        final form = Uri.splitQueryString(req.body);
        expect(form['grant_type'], 'refresh_token');
        expect(form['refresh_token'], 'rt-1');
        return http.Response(
            jsonEncode(_tokenResp(accessToken: 'at-2', refreshToken: 'rt-2')),
            200);
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final exchange = TokenExchange(client: client, timeout: _timeout);
      final outcome = await exchange.refresh(cfg, ctx, 'rt-1');
      expect(outcome, isA<RefreshRotated>());
      final rotated = outcome as RefreshRotated;
      expect(rotated.tokens.accessToken, 'at-2');
      expect(rotated.tokens.refreshToken, 'rt-2');
    });

    test('invalid_grant with reuse mention returns reuseDetected', () async {
      final cfg = _cfg();
      final client = MockClient((req) async {
        if (req.url.path.endsWith('/.well-known/openid-configuration')) {
          return http.Response(jsonEncode(_discoveryDoc()), 200);
        }
        return http.Response(
          jsonEncode({
            'error': 'invalid_grant',
            'error_description': 'refresh token reuse detected',
          }),
          400,
        );
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final exchange = TokenExchange(client: client, timeout: _timeout);
      final outcome = await exchange.refresh(cfg, ctx, 'rt-stale');
      expect(outcome, isA<RefreshReuseDetectedOutcome>());
    });

    test('other server failure wraps as networkError', () async {
      final cfg = _cfg();
      final client = MockClient((req) async {
        if (req.url.path.endsWith('/.well-known/openid-configuration')) {
          return http.Response(jsonEncode(_discoveryDoc()), 200);
        }
        return http.Response('boom', 500);
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final exchange = TokenExchange(client: client, timeout: _timeout);
      final outcome = await exchange.refresh(cfg, ctx, 'rt');
      expect(outcome, isA<RefreshNetworkError>());
      final err = outcome as RefreshNetworkError;
      expect(err.error.code, AuthErrorCode.tokenRefreshFailed);
    });

    test('refresh supports sealed-class pattern matching', () async {
      final cfg = _cfg();
      final client = MockClient((req) async {
        if (req.url.path.endsWith('/.well-known/openid-configuration')) {
          return http.Response(jsonEncode(_discoveryDoc()), 200);
        }
        return http.Response(jsonEncode(_tokenResp()), 200);
      });
      final kp = generateDpopKeyPair();
      final ctx = makeDpopContext(kp);
      final exchange = TokenExchange(client: client, timeout: _timeout);
      final outcome = await exchange.refresh(cfg, ctx, 'rt');
      final label = switch (outcome) {
        RefreshRotated() => 'rotated',
        RefreshReuseDetectedOutcome() => 'reuse',
        RefreshNetworkError() => 'err',
      };
      expect(label, 'rotated');
    });
  });
}
