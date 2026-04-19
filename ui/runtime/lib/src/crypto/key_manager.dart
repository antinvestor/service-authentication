import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/protocol/dpop.dart'
    show DpopKeyPair;
import 'package:cryptography/cryptography.dart' show SecretKey;

/// Opaque handle to an AES-GCM wrap key.
///
/// Callers should treat [secretKey] as private — [KeyManager] is the only
/// expected consumer. Kept as a wrapper (rather than exposing [SecretKey]
/// directly) so the backend can change without rippling through call sites.
class WrapKey {
  const WrapKey(this.secretKey);

  final SecretKey secretKey;
}

/// Ciphertext + IV tuple produced by [KeyManager.wrap].
///
/// `ciphertext` includes the AES-GCM authentication tag appended per the
/// `package:cryptography` convention.
class WrappedBlob {
  const WrappedBlob({
    required this.iv,
    required this.ciphertext,
  });

  final Uint8List iv;
  final Uint8List ciphertext;
}

/// Signer + wrapper abstraction used throughout the runtime.
///
/// Exists so the crypto backend (currently PointyCastle for ECDSA,
/// `package:cryptography` for AES-GCM) can be swapped without touching
/// DPoP or storage callers. All methods return `Future` so backends may
/// delegate to platform channels without API churn.
abstract class KeyManager {
  /// Generates a fresh ECDSA P-256 key pair for DPoP proofs.
  Future<DpopKeyPair> generateDpopKey();

  /// Signs [signingInput] with the DPoP private key. Returns raw
  /// `r || s` (64 bytes) matching JWS ES256.
  Future<Uint8List> signDpopJws(DpopKeyPair key, String signingInput);

  /// Exports the public portion of the DPoP key as a JWK suitable for
  /// embedding in the proof header.
  Future<Map<String, dynamic>> exportDpopPublicJwk(DpopKeyPair key);

  /// Exports the DPoP private key's `d` scalar as a fixed 32-byte
  /// big-endian buffer so the runtime can persist it (encrypted) and
  /// reconstruct the key pair on cold start.
  Future<Uint8List> exportDpopPrivateKey(DpopKeyPair key);

  /// Rehydrates a [DpopKeyPair] from a 32-byte `d` scalar previously
  /// produced by [exportDpopPrivateKey]. The matching public point is
  /// recomputed as `Q = d * G` over P-256.
  Future<DpopKeyPair> importDpopPrivateKey(Uint8List dScalar);

  /// Generates a fresh 256-bit AES-GCM wrap key.
  Future<WrapKey> generateWrapKey();

  /// Wraps an arbitrary 32-byte AES-GCM key material buffer (e.g. the
  /// root key persisted by `RootKeyStore`) into a [WrapKey] handle.
  Future<WrapKey> importWrapKey(Uint8List rawKey);

  /// Exports the raw 32-byte key material backing [key]. Intended for
  /// persisting the wrap key encrypted under the root key.
  Future<Uint8List> exportWrapKey(WrapKey key);

  /// Encrypts [plaintext] under [key] with a fresh random IV.
  Future<WrappedBlob> wrap(WrapKey key, List<int> plaintext);

  /// Decrypts a [blob] produced by [wrap]. Throws on auth-tag failure.
  Future<Uint8List> unwrap(WrapKey key, WrappedBlob blob);
}
