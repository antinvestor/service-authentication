import 'dart:convert';
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/crypto/default_key_manager.dart';
import 'package:antinvestor_auth_runtime/src/crypto/key_manager.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/protocol/dpop.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late KeyManager km;

  setUp(() {
    km = DefaultKeyManager();
  });

  group('DPoP key', () {
    test('generateDpopKey produces a usable P-256 pair', () async {
      final kp = await km.generateDpopKey();
      expect(kp.privateKey.d, isNotNull);
      expect(kp.publicKey.Q, isNotNull);
    });

    test('exportDpopPublicJwk has kty/crv/x/y with 32-byte components',
        () async {
      final kp = await km.generateDpopKey();
      final jwk = await km.exportDpopPublicJwk(kp);
      expect(jwk['kty'], 'EC');
      expect(jwk['crv'], 'P-256');
      expect(jwk['x'], isA<String>());
      expect(jwk['y'], isA<String>());
      // base64url-no-pad of 32 bytes is 43 chars.
      expect((jwk['x'] as String).length, 43);
      expect((jwk['y'] as String).length, 43);
    });

    test('signDpopJws produces a 64-byte raw r||s signature that verifies',
        () async {
      final kp = await km.generateDpopKey();
      const input = 'header.payload';
      final sig = await km.signDpopJws(kp, input);
      expect(sig.length, 64);
      // Verify via PointyCastle path exposed by dpop.dart.
      final ok = verifyEcdsaRaw(
        kp.publicKey,
        Uint8List.fromList(utf8.encode(input)),
        sig,
      );
      expect(ok, isTrue);
    });

    test(
        'DpopContext wired with keyManager signs via the injected backend '
        'and still verifies against the embedded public key', () async {
      final kp = await km.generateDpopKey();
      final ctx = await makeDpopContextAsync(kp, keyManager: km);
      final proof = await buildProof(
        ctx,
        htm: 'POST',
        htu: 'https://idp.example.com/token',
      );
      final parts = proof.split('.');
      expect(parts.length, 3);
      final signingInput = '${parts[0]}.${parts[1]}';
      final padded = parts[2]
          .padRight(parts[2].length + (4 - parts[2].length % 4) % 4, '=');
      final sig = base64Url.decode(padded);
      final ok = verifyEcdsaRaw(
        kp.publicKey,
        Uint8List.fromList(utf8.encode(signingInput)),
        sig,
      );
      expect(ok, isTrue);
    });
  });

  group('wrap/unwrap', () {
    test('generateWrapKey produces a 256-bit secret', () async {
      final wk = await km.generateWrapKey();
      final bytes = await wk.secretKey.extractBytes();
      expect(bytes.length, 32);
    });

    test('wrap/unwrap round-trips', () async {
      final wk = await km.generateWrapKey();
      final plaintext = utf8.encode('the-refresh-token-value');
      final blob = await km.wrap(wk, plaintext);
      expect(blob.iv.length, greaterThanOrEqualTo(12));
      expect(blob.ciphertext.length,
          greaterThan(plaintext.length)); // includes MAC
      final back = await km.unwrap(wk, blob);
      expect(utf8.decode(back), 'the-refresh-token-value');
    });

    test('two wrap calls produce different ciphertexts (fresh IV)', () async {
      final wk = await km.generateWrapKey();
      final plaintext = utf8.encode('same-input');
      final a = await km.wrap(wk, plaintext);
      final b = await km.wrap(wk, plaintext);
      expect(a.iv, isNot(equals(b.iv)));
      expect(a.ciphertext, isNot(equals(b.ciphertext)));
    });

    test('unwrap with a different key throws storageCorruption', () async {
      final wk1 = await km.generateWrapKey();
      final wk2 = await km.generateWrapKey();
      final blob = await km.wrap(wk1, utf8.encode('hello'));
      expect(
        () => km.unwrap(wk2, blob),
        throwsA(isA<AuthError>().having(
          (e) => e.code,
          'code',
          AuthErrorCode.storageCorruption,
        )),
      );
    });

    test('tampered ciphertext fails auth and throws storageCorruption',
        () async {
      final wk = await km.generateWrapKey();
      final blob = await km.wrap(wk, utf8.encode('hello'));
      final tampered = Uint8List.fromList(blob.ciphertext);
      tampered[0] ^= 0x01;
      final corrupt = WrappedBlob(iv: blob.iv, ciphertext: tampered);
      expect(
        () => km.unwrap(wk, corrupt),
        throwsA(isA<AuthError>().having(
          (e) => e.code,
          'code',
          AuthErrorCode.storageCorruption,
        )),
      );
    });
  });
}
