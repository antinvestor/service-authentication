import 'dart:convert';
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/crypto/key_manager.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/protocol/dpop.dart' as dpop;
import 'package:cryptography/cryptography.dart'
    show AesGcm, Mac, SecretBox, SecretKey;
import 'package:pointycastle/export.dart' as pc;

/// Default [KeyManager] implementation.
///
/// - **DPoP (ECDSA P-256)**: backed by PointyCastle. The plan originally
///   mandated pure `package:cryptography`, but that package's pure-Dart
///   ECDSA raises [UnimplementedError] (it only wires up the browser
///   `SubtleCrypto` path). PointyCastle signs + verifies end-to-end on
///   every Dart platform, matching F-B.4 behaviour.
/// - **AES-GCM wrap**: backed by `package:cryptography`'s `AesGcm` —
///   fully implemented in pure Dart and what the plan asked for.
class DefaultKeyManager implements KeyManager {
  DefaultKeyManager({AesGcm? aesGcm}) : _aesGcm = aesGcm ?? AesGcm.with256bits();

  final AesGcm _aesGcm;

  @override
  Future<dpop.DpopKeyPair> generateDpopKey() async =>
      dpop.generateDpopKeyPair();

  @override
  Future<Uint8List> signDpopJws(
    dpop.DpopKeyPair key,
    String signingInput,
  ) async {
    final signer = pc.ECDSASigner(
      pc.SHA256Digest(),
      pc.HMac.withDigest(pc.SHA256Digest()),
    )..init(
        true,
        pc.PrivateKeyParameter<pc.ECPrivateKey>(key.privateKey),
      );
    final sig =
        signer.generateSignature(Uint8List.fromList(utf8.encode(signingInput)))
            as pc.ECSignature;
    return Uint8List.fromList([
      ..._bigIntToFixedBytes(sig.r, 32),
      ..._bigIntToFixedBytes(sig.s, 32),
    ]);
  }

  @override
  Future<Map<String, dynamic>> exportDpopPublicJwk(dpop.DpopKeyPair key) async {
    final q = key.publicKey.Q;
    if (q == null) {
      throw AuthError(
        AuthErrorCode.cryptoUnsupported,
        'DPoP public key has no affine point',
      );
    }
    final x = q.x?.toBigInteger();
    final y = q.y?.toBigInteger();
    if (x == null || y == null) {
      throw AuthError(
        AuthErrorCode.cryptoUnsupported,
        'DPoP public key missing x/y coordinates',
      );
    }
    return <String, dynamic>{
      'kty': 'EC',
      'crv': 'P-256',
      'x': _b64urlNoPad(_bigIntToFixedBytes(x, 32)),
      'y': _b64urlNoPad(_bigIntToFixedBytes(y, 32)),
    };
  }

  @override
  Future<Uint8List> exportDpopPrivateKey(dpop.DpopKeyPair key) async {
    final d = key.privateKey.d;
    if (d == null) {
      throw AuthError(
        AuthErrorCode.cryptoUnsupported,
        'DPoP private key missing scalar',
      );
    }
    return _bigIntToFixedBytes(d, 32);
  }

  @override
  Future<dpop.DpopKeyPair> importDpopPrivateKey(Uint8List dScalar) async {
    if (dScalar.length != 32) {
      throw AuthError(
        AuthErrorCode.storageCorruption,
        'DPoP private scalar must be 32 bytes (got ${dScalar.length})',
      );
    }
    final params = pc.ECCurve_secp256r1();
    final d = _bytesToBigInt(dScalar);
    // Q = d * G: required because the on-disk schema only stores the
    // scalar. `multiplier` defaults to `WTNAFMultiplier` which is fine for
    // P-256.
    final q = params.G * d;
    if (q == null) {
      throw AuthError(
        AuthErrorCode.storageCorruption,
        'failed to derive DPoP public point from scalar',
      );
    }
    final priv = pc.ECPrivateKey(d, params);
    final pub = pc.ECPublicKey(q, params);
    return dpop.DpopKeyPair(privateKey: priv, publicKey: pub);
  }

  @override
  Future<WrapKey> generateWrapKey() async {
    final key = await _aesGcm.newSecretKey();
    return WrapKey(key);
  }

  @override
  Future<WrapKey> importWrapKey(Uint8List rawKey) async {
    if (rawKey.length != 32) {
      throw AuthError(
        AuthErrorCode.storageCorruption,
        'wrap key must be 32 bytes (got ${rawKey.length})',
      );
    }
    return WrapKey(SecretKey(List<int>.from(rawKey)));
  }

  @override
  Future<Uint8List> exportWrapKey(WrapKey key) async {
    final bytes = await key.secretKey.extractBytes();
    return Uint8List.fromList(bytes);
  }

  @override
  Future<WrappedBlob> wrap(WrapKey key, List<int> plaintext) async {
    final box = await _aesGcm.encrypt(plaintext, secretKey: key.secretKey);
    // Pack MAC inside the returned ciphertext so [WrappedBlob] stays a
    // 2-tuple `{iv, ciphertext}` matching the plan's interface. On
    // unwrap we slice the trailing MAC back off.
    final cipherText = box.cipherText;
    final macBytes = box.mac.bytes;
    final combined = Uint8List(cipherText.length + macBytes.length)
      ..setRange(0, cipherText.length, cipherText)
      ..setRange(cipherText.length, cipherText.length + macBytes.length,
          macBytes);
    return WrappedBlob(
      iv: Uint8List.fromList(box.nonce),
      ciphertext: combined,
    );
  }

  @override
  Future<Uint8List> unwrap(WrapKey key, WrappedBlob blob) async {
    final macLen = _aesGcm.macAlgorithm.macLength;
    if (blob.ciphertext.length < macLen) {
      throw AuthError(
        AuthErrorCode.storageCorruption,
        'wrapped blob shorter than MAC length',
      );
    }
    final cipherEnd = blob.ciphertext.length - macLen;
    final cipherText = blob.ciphertext.sublist(0, cipherEnd);
    final macBytes = blob.ciphertext.sublist(cipherEnd);
    final box = SecretBox(
      cipherText,
      nonce: blob.iv,
      mac: Mac(macBytes),
    );
    try {
      final plain = await _aesGcm.decrypt(box, secretKey: key.secretKey);
      return Uint8List.fromList(plain);
    } catch (err) {
      throw AuthError(
        AuthErrorCode.storageCorruption,
        'AES-GCM unwrap failed',
        cause: err,
      );
    }
  }
}

Uint8List _bigIntToFixedBytes(BigInt value, int size) {
  final bytes = Uint8List(size);
  var v = value;
  for (var i = size - 1; i >= 0; i--) {
    bytes[i] = (v & BigInt.from(0xff)).toInt();
    v = v >> 8;
  }
  return bytes;
}

BigInt _bytesToBigInt(Uint8List bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

String _b64urlNoPad(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');
