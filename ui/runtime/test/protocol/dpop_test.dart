import 'dart:convert';
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/protocol/dpop.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_test/flutter_test.dart';

Map<String, dynamic> _decodeJson(String b64) {
  final padded = b64.padRight(b64.length + (4 - b64.length % 4) % 4, '=');
  return json.decode(utf8.decode(base64Url.decode(padded)))
      as Map<String, dynamic>;
}

Uint8List _decodeBytes(String b64) {
  final padded = b64.padRight(b64.length + (4 - b64.length % 4) % 4, '=');
  return base64Url.decode(padded);
}

String _b64urlNoPad(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

void main() {
  late DpopKeyPair kp;

  setUp(() {
    kp = generateDpopKeyPair();
  });

  test('buildProof emits a 3-part compact JWT with DPoP header', () async {
    final ctx = makeDpopContext(kp);
    final token = await buildProof(
      ctx,
      htm: 'POST',
      htu: 'https://idp.example.com/token',
    );
    final parts = token.split('.');
    expect(parts.length, 3);

    final header = _decodeJson(parts[0]);
    expect(header['typ'], 'dpop+jwt');
    expect(header['alg'], 'ES256');
    final jwk = header['jwk'] as Map<String, dynamic>;
    expect(jwk['kty'], 'EC');
    expect(jwk['crv'], 'P-256');
    expect(jwk['x'], isA<String>());
    expect(jwk['y'], isA<String>());
    // x/y are 32-byte values — base64url-no-pad length is 43.
    expect((jwk['x'] as String).length, 43);
    expect((jwk['y'] as String).length, 43);

    final payload = _decodeJson(parts[1]);
    expect(payload['htm'], 'POST');
    expect(payload['htu'], 'https://idp.example.com/token');
    expect(payload['iat'], isA<int>());
    expect(payload['jti'], isA<String>());
    // Optional fields absent by default.
    expect(payload.containsKey('ath'), isFalse);
    expect(payload.containsKey('nonce'), isFalse);

    final sigBytes = _decodeBytes(parts[2]);
    expect(sigBytes.length, 64);
  });

  test('htm is uppercased in payload', () async {
    final ctx = makeDpopContext(kp);
    final token = await buildProof(
      ctx,
      htm: 'post',
      htu: 'https://i/token',
    );
    final payload = _decodeJson(token.split('.')[1]);
    expect(payload['htm'], 'POST');
  });

  test('ath is sha256 of access token when provided', () async {
    final ctx = makeDpopContext(kp);
    const accessToken = 'some-access-token';
    final expectedAth = _b64urlNoPad(
        crypto.sha256.convert(utf8.encode(accessToken)).bytes);
    final token = await buildProof(
      ctx,
      htm: 'GET',
      htu: 'https://api.example.com/thing',
      accessToken: accessToken,
    );
    final payload = _decodeJson(token.split('.')[1]);
    expect(payload['ath'], expectedAth);
  });

  test('rememberNonce round-trips into proof payload', () async {
    final ctx = makeDpopContext(kp);
    rememberNonce(ctx, 'https://i/token', {'DPoP-Nonce': 'n-1234'});
    final token = await buildProof(
      ctx,
      htm: 'POST',
      htu: 'https://i/token',
    );
    final payload = _decodeJson(token.split('.')[1]);
    expect(payload['nonce'], 'n-1234');

    // Case-insensitive lookup.
    final ctx2 = makeDpopContext(kp);
    rememberNonce(ctx2, 'https://i/token', {'dpop-nonce': 'n-lower'});
    final token2 = await buildProof(
      ctx2,
      htm: 'POST',
      htu: 'https://i/token',
    );
    expect(_decodeJson(token2.split('.')[1])['nonce'], 'n-lower');
  });

  test('nonce is scoped per origin', () async {
    final ctx = makeDpopContext(kp);
    rememberNonce(ctx, 'https://a.example.com/token', {'DPoP-Nonce': 'a'});
    rememberNonce(ctx, 'https://b.example.com/token', {'DPoP-Nonce': 'b'});
    final proofA = await buildProof(ctx,
        htm: 'POST', htu: 'https://a.example.com/token');
    final proofB = await buildProof(ctx,
        htm: 'POST', htu: 'https://b.example.com/token');
    expect(_decodeJson(proofA.split('.')[1])['nonce'], 'a');
    expect(_decodeJson(proofB.split('.')[1])['nonce'], 'b');
  });

  test('rememberClockOffset adjusts iat using Date header', () async {
    final ctx = makeDpopContext(kp);
    // Pick a far-future server date so the delta is unmistakable.
    final serverTime = DateTime.utc(2099, 1, 1, 0, 0, 0);
    rememberClockOffset(ctx, {
      'Date': 'Thu, 01 Jan 2099 00:00:00 GMT',
    });
    expect(ctx.clockOffsetMs, greaterThan(0));

    final token = await buildProof(ctx, htm: 'POST', htu: 'https://i/token');
    final payload = _decodeJson(token.split('.')[1]);
    final iat = payload['iat'] as int;
    // Tolerate a few seconds for test execution.
    expect(iat, closeTo(serverTime.millisecondsSinceEpoch ~/ 1000, 5));
  });

  test('rememberClockOffset ignores missing or malformed Date header',
      () async {
    final ctx = makeDpopContext(kp);
    rememberClockOffset(ctx, const {});
    expect(ctx.clockOffsetMs, 0);
    rememberClockOffset(ctx, {'Date': 'not-a-date'});
    expect(ctx.clockOffsetMs, 0);
  });

  test('buildProof signature verifies against the embedded public key',
      () async {
    final ctx = makeDpopContext(kp);
    final token = await buildProof(
      ctx,
      htm: 'POST',
      htu: 'https://i/token',
    );
    final parts = token.split('.');
    final signingInput = '${parts[0]}.${parts[1]}';
    final sigBytes = _decodeBytes(parts[2]);
    final ok = verifyEcdsaRaw(
      kp.publicKey,
      Uint8List.fromList(utf8.encode(signingInput)),
      sigBytes,
    );
    expect(ok, isTrue);
  });
}
