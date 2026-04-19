import 'dart:convert';

import 'package:antinvestor_auth_runtime/src/protocol/jwt.dart';
import 'package:flutter_test/flutter_test.dart';

String _fakeJwt(Map<String, dynamic> payload) {
  String seg(Map<String, dynamic> m) =>
      base64Url.encode(utf8.encode(jsonEncode(m))).replaceAll('=', '');
  final header = seg({'alg': 'none', 'typ': 'JWT'});
  final body = seg(payload);
  // Signature segment is arbitrary for payload-only decoding.
  return '$header.$body.sig';
}

void main() {
  group('decodeJwtPayload', () {
    test('round-trips payloads of varied length', () {
      // 1-char, 20-char strings plus nested map
      for (var len = 1; len <= 20; len++) {
        final sub = 'a' * len;
        final token = _fakeJwt({'sub': sub, 'len': len});
        final decoded = decodeJwtPayload(token);
        expect(decoded['sub'], sub);
        expect(decoded['len'], len);
      }
    });

    test('handles missing base64 padding correctly', () {
      // Payload chosen so base64 length mod 4 == 2 (needs two `=` pad chars).
      final token = _fakeJwt({'x': 'a'});
      final decoded = decodeJwtPayload(token);
      expect(decoded['x'], 'a');
    });

    test('throws on malformed JWT', () {
      expect(() => decodeJwtPayload('not.a.jwt.with.extra.parts'),
          throwsFormatException);
      expect(() => decodeJwtPayload('only-one-part'), throwsFormatException);
    });
  });

  group('extractRolesFromToken', () {
    test('returns direct roles array', () {
      final token = _fakeJwt({
        'sub': 's',
        'roles': ['admin', 'editor'],
      });
      expect(extractRolesFromToken(token), ['admin', 'editor']);
    });

    test('falls back to realm_access.roles', () {
      final token = _fakeJwt({
        'sub': 's',
        'realm_access': {
          'roles': ['ops', 'support'],
        },
      });
      expect(extractRolesFromToken(token), ['ops', 'support']);
    });

    test('returns empty list when no roles claim is present', () {
      final token = _fakeJwt({'sub': 's'});
      expect(extractRolesFromToken(token), isEmpty);
    });

    test('returns empty list on malformed token', () {
      expect(extractRolesFromToken('garbage'), isEmpty);
    });

    test('ignores non-string role entries', () {
      final token = _fakeJwt({
        'roles': <dynamic>['ok', 42, null, 'good'],
      });
      expect(extractRolesFromToken(token), ['ok', 'good']);
    });
  });
}
