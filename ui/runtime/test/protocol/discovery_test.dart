import 'dart:convert';

import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/protocol/discovery.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

const _timeout = Duration(seconds: 5);

Map<String, dynamic> _doc({
  String issuer = 'https://i',
  String tokenEndpoint = 'https://i/token',
  String authorizationEndpoint = 'https://i/oauth2/auth',
  List<String>? dpopAlgs,
}) {
  return <String, dynamic>{
    'issuer': issuer,
    'authorization_endpoint': authorizationEndpoint,
    'token_endpoint': tokenEndpoint,
    'dpop_signing_alg_values_supported': ?dpopAlgs,
  };
}

void main() {
  setUp(clearDiscoveryCache);

  test('200 JSON is parsed and cached', () async {
    var calls = 0;
    final client = MockClient((req) async {
      calls++;
      expect(req.method, 'GET');
      expect(req.url.toString(),
          'https://idp.example.com/.well-known/openid-configuration');
      return http.Response(jsonEncode(_doc(issuer: 'https://idp.example.com')),
          200,
          headers: {'content-type': 'application/json'});
    });

    final d1 = await getDiscovery(
      'https://idp.example.com',
      _timeout,
      client: client,
    );
    expect(d1.issuer, 'https://idp.example.com');
    expect(d1.tokenEndpoint, 'https://i/token');

    // Second call should hit the cache and skip HTTP.
    final d2 = await getDiscovery(
      'https://idp.example.com',
      _timeout,
      client: client,
    );
    expect(identical(d1, d2), isTrue);
    expect(calls, 1);
  });

  test('trailing slash is stripped before cache key', () async {
    var calls = 0;
    final client = MockClient((req) async {
      calls++;
      return http.Response(jsonEncode(_doc()), 200,
          headers: {'content-type': 'application/json'});
    });
    await getDiscovery('https://i', _timeout, client: client);
    await getDiscovery('https://i/', _timeout, client: client);
    expect(calls, 1);
  });

  test('404 raises AuthError(discoveryFailed) and does not cache', () async {
    var calls = 0;
    final client = MockClient((req) async {
      calls++;
      return http.Response('not found', 404);
    });
    await expectLater(
      getDiscovery('https://i', _timeout, client: client),
      throwsA(isA<AuthError>()
          .having((e) => e.code, 'code', AuthErrorCode.discoveryFailed)),
    );
    // Second call should retry (failure not cached).
    await expectLater(
      getDiscovery('https://i', _timeout, client: client),
      throwsA(isA<AuthError>()),
    );
    expect(calls, 2);
  });

  test('non-JSON body raises AuthError(discoveryFailed)', () async {
    final client = MockClient((req) async => http.Response('<html/>', 200,
        headers: {'content-type': 'text/html'}));
    await expectLater(
      getDiscovery('https://i', _timeout, client: client),
      throwsA(isA<AuthError>()
          .having((e) => e.code, 'code', AuthErrorCode.discoveryFailed)),
    );
  });

  test('missing required fields raises AuthError(discoveryFailed)', () async {
    final client = MockClient((req) async =>
        http.Response(jsonEncode({'issuer': 'https://i'}), 200));
    await expectLater(
      getDiscovery('https://i', _timeout, client: client),
      throwsA(isA<AuthError>()
          .having((e) => e.code, 'code', AuthErrorCode.discoveryFailed)),
    );
  });

  test('network timeout maps to AuthError(networkTimeout)', () async {
    final client = MockClient((req) async {
      await Future<void>.delayed(const Duration(milliseconds: 200));
      return http.Response(jsonEncode(_doc()), 200);
    });
    await expectLater(
      getDiscovery('https://i', const Duration(milliseconds: 50),
          client: client),
      throwsA(isA<AuthError>()
          .having((e) => e.code, 'code', AuthErrorCode.networkTimeout)),
    );
  });

  test('supportsDpop detects ES256 advertisement', () {
    final withDpop = OidcDiscovery.fromJson(
        _doc(dpopAlgs: ['ES256', 'RS256']));
    final withoutDpop = OidcDiscovery.fromJson(_doc());
    expect(supportsDpop(withDpop), isTrue);
    expect(supportsDpop(withoutDpop), isFalse);
  });

  test('concurrent callers share a single in-flight request', () async {
    var calls = 0;
    final client = MockClient((req) async {
      calls++;
      await Future<void>.delayed(const Duration(milliseconds: 20));
      return http.Response(jsonEncode(_doc()), 200);
    });
    final results = await Future.wait([
      getDiscovery('https://i', _timeout, client: client),
      getDiscovery('https://i', _timeout, client: client),
      getDiscovery('https://i', _timeout, client: client),
    ]);
    expect(calls, 1);
    expect(identical(results[0], results[1]), isTrue);
    expect(identical(results[1], results[2]), isTrue);
  });
}
