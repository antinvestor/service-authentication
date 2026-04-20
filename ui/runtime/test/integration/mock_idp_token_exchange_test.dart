import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

import 'mock_idp.dart';

/// Constructs an unsigned JWT with the given payload. Mirrors the helper
/// used in worker tests — sufficient for MockIdp which does not verify
/// signatures.
String _jwt(Map<String, dynamic> payload) {
  String strip(String s) => s.replaceAll('=', '');
  final header = strip(base64Url.encode(utf8.encode(
    json.encode(const <String, String>{'alg': 'none'}),
  )));
  final body = strip(base64Url.encode(utf8.encode(json.encode(payload))));
  final sig = strip(base64Url.encode(const <int>[1, 2, 3]));
  return '$header.$body.$sig';
}

Future<http.Response> _postTokenExchange(
  String base, {
  required String subjectToken,
  required String subjectIssuer,
  String subjectTokenType = 'urn:ietf:params:oauth:token-type:id_token',
  String clientId = 'antinvestor-mobile',
}) {
  final body = <String, String>{
    'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
    'client_id': clientId,
    'subject_token': subjectToken,
    'subject_token_type': subjectTokenType,
    'subject_issuer': subjectIssuer,
  }
      .entries
      .map((e) =>
          '${Uri.encodeQueryComponent(e.key)}=${Uri.encodeQueryComponent(e.value)}')
      .join('&');
  return http.post(
    Uri.parse('$base/token'),
    headers: const <String, String>{
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body,
  );
}

void main() {
  late MockIdp mock;
  late String base;

  setUp(() async {
    mock = MockIdp();
    base = await mock.start();
  });

  tearDown(() async {
    await mock.stop();
  });

  test('accepts RFC 8693 token-exchange for Apple issuer', () async {
    final idToken = _jwt(<String, dynamic>{
      'iss': 'https://appleid.apple.com',
      'sub': 'apple-sub',
      'aud': 'antinvestor-mobile',
    });
    final res = await _postTokenExchange(
      base,
      subjectToken: idToken,
      subjectIssuer: 'https://appleid.apple.com',
    );
    expect(res.statusCode, 200);
    final body = json.decode(res.body) as Map<String, dynamic>;
    expect(body['access_token'], isA<String>());
    expect(body['refresh_token'], isA<String>());
    expect(body['id_token'], isA<String>());
    expect(mock.tokenRequests, hasLength(1));
    expect(mock.tokenRequests.single.grantType,
        'urn:ietf:params:oauth:grant-type:token-exchange');
  });

  test('accepts RFC 8693 token-exchange for Google issuer', () async {
    final idToken = _jwt(<String, dynamic>{
      'iss': 'https://accounts.google.com',
      'sub': 'google-sub',
      'aud': 'antinvestor-mobile',
    });
    final res = await _postTokenExchange(
      base,
      subjectToken: idToken,
      subjectIssuer: 'https://accounts.google.com',
    );
    expect(res.statusCode, 200);
    final body = json.decode(res.body) as Map<String, dynamic>;
    expect(body['access_token'], isA<String>());
  });

  test('rejects subject_token_type other than id_token', () async {
    final idToken = _jwt(<String, dynamic>{
      'iss': 'https://accounts.google.com',
      'sub': 's',
    });
    final res = await _postTokenExchange(
      base,
      subjectToken: idToken,
      subjectIssuer: 'https://accounts.google.com',
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
    );
    expect(res.statusCode, 400);
    expect(json.decode(res.body)['error'], 'invalid_request');
  });

  test('rejects subject_issuer outside the allowlist', () async {
    final idToken = _jwt(<String, dynamic>{
      'iss': 'https://evil.example.com',
      'sub': 's',
    });
    final res = await _postTokenExchange(
      base,
      subjectToken: idToken,
      subjectIssuer: 'https://evil.example.com',
    );
    expect(res.statusCode, 400);
    expect(json.decode(res.body)['error'], 'invalid_grant');
  });

  test('rejects when subject_token iss does not match subject_issuer',
      () async {
    final idToken = _jwt(<String, dynamic>{
      'iss': 'https://appleid.apple.com',
      'sub': 's',
    });
    final res = await _postTokenExchange(
      base,
      subjectToken: idToken,
      subjectIssuer: 'https://accounts.google.com',
    );
    expect(res.statusCode, 400);
    expect(json.decode(res.body)['error'], 'invalid_grant');
  });

  test('setAllowedIssuers tightens the allowlist', () async {
    mock.setAllowedIssuers(const <String>['https://accounts.google.com']);
    final idToken = _jwt(<String, dynamic>{
      'iss': 'https://appleid.apple.com',
      'sub': 's',
    });
    final res = await _postTokenExchange(
      base,
      subjectToken: idToken,
      subjectIssuer: 'https://appleid.apple.com',
    );
    expect(res.statusCode, 400);
    expect(json.decode(res.body)['error'], 'invalid_grant');
  });

  test('echoes subject claims: sub preserved, aud synthesised from client_id',
      () async {
    final idToken = _jwt(<String, dynamic>{
      'iss': 'https://accounts.google.com',
      'sub': 'user-42',
      'aud': 'ignored',
    });
    final res = await _postTokenExchange(
      base,
      subjectToken: idToken,
      subjectIssuer: 'https://accounts.google.com',
      clientId: 'custom-client',
    );
    expect(res.statusCode, 200);
    final body = json.decode(res.body) as Map<String, dynamic>;

    String decodeJwtPayload(String t) {
      final parts = t.split('.');
      final pad = (4 - parts[1].length % 4) % 4;
      return utf8.decode(base64Url.decode(parts[1] + ('=' * pad)));
    }

    final idBody = json.decode(decodeJwtPayload(body['id_token'] as String))
        as Map<String, dynamic>;
    expect(idBody['sub'], 'user-42');
    expect(idBody['aud'], 'custom-client');
    expect(idBody['exp'], isA<int>());
  });
}
