import 'dart:convert';
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/crypto/key_manager.dart';

/// Persisted session snapshot for a single namespace.
///
/// Everything sensitive is wrapped or encrypted before it reaches this
/// struct. Concretely:
///
/// - The *wrap key* itself (AES-GCM 256) is encrypted with the root key
///   held by `RootKeyStore` and stored as [wrapKeyCiphertext].
/// - The *DPoP private key* (ECDSA P-256 `d` scalar, 32 bytes) is
///   encrypted under the wrap key and stored as [dpopPrivateKeyCiphertext].
/// - The *refresh token* is encrypted under the wrap key and stored as
///   [refreshTokenCiphertext] (a [WrappedBlob]).
/// - The *ID token* is stored in plaintext because it is short-lived and
///   already public by OIDC design (the client is the intended audience).
///
/// Forward-compatible: older schemas that stored raw `dpopKeyEncrypted` /
/// `wrapKeyEncrypted` bytes without an IV are silently ignored by
/// [tryFromJson], which returns null so the runtime falls back to a fresh
/// sign-in.
class StoredSession {
  const StoredSession({
    required this.wrapKeyCiphertext,
    required this.dpopPrivateKeyCiphertext,
    required this.refreshTokenCiphertext,
    required this.accessToken,
    required this.accessTokenExpiresAt,
    required this.tokenType,
    required this.updatedAt,
    this.idToken,
  });

  /// AES-GCM blob containing the wrap key material (32 bytes), encrypted
  /// with the root key from `RootKeyStore`.
  final WrappedBlob wrapKeyCiphertext;

  /// AES-GCM blob containing the DPoP private key's `d` scalar (raw 32
  /// bytes, big-endian), encrypted with the unwrapped wrap key.
  final WrappedBlob dpopPrivateKeyCiphertext;

  /// AES-GCM blob containing the UTF-8-encoded refresh token, encrypted
  /// with the unwrapped wrap key.
  final WrappedBlob refreshTokenCiphertext;

  /// Access token in plaintext. Short-lived and only useful for the
  /// remaining seconds before [accessTokenExpiresAt]; the refresh token is
  /// what actually lets an attacker maintain access.
  final String accessToken;

  /// Absolute expiry of [accessToken].
  final DateTime accessTokenExpiresAt;

  /// `token_type` negotiated with the IdP. Persisted so reload picks up
  /// DPoP-bound sessions without a discovery round-trip.
  final String tokenType;

  /// Last observed `id_token`. OIDC id tokens are inherently non-secret
  /// (they are intended for the client) so they live in plaintext.
  final String? idToken;

  /// Wall-clock timestamp of the most recent save. Used by UIs that want
  /// to display "last seen" and by integrity checks.
  final DateTime updatedAt;

  /// JSON-encodable representation. Binary fields are base64-encoded.
  Map<String, dynamic> toJson() => <String, dynamic>{
        'v': 2,
        'wrapKey': _blobToJson(wrapKeyCiphertext),
        'dpopKey': _blobToJson(dpopPrivateKeyCiphertext),
        'refreshToken': _blobToJson(refreshTokenCiphertext),
        'accessToken': accessToken,
        'accessExpiresAt':
            accessTokenExpiresAt.toUtc().toIso8601String(),
        'tokenType': tokenType,
        'idToken': idToken,
        'updatedAt': updatedAt.toUtc().toIso8601String(),
      };

  /// Parses a map produced by [toJson]. Returns null on any schema/shape
  /// error — callers treat null as "no session stored".
  static StoredSession? tryFromJson(Map<String, dynamic> json) {
    try {
      if (json['v'] != 2) return null;
      final wrapKey = _blobFromJson(json['wrapKey']);
      final dpopKey = _blobFromJson(json['dpopKey']);
      final refresh = _blobFromJson(json['refreshToken']);
      final access = json['accessToken'];
      final expiresAt = json['accessExpiresAt'];
      final tokenType = json['tokenType'];
      final updated = json['updatedAt'];
      if (wrapKey == null ||
          dpopKey == null ||
          refresh == null ||
          access is! String ||
          expiresAt is! String ||
          tokenType is! String ||
          updated is! String) {
        return null;
      }
      return StoredSession(
        wrapKeyCiphertext: wrapKey,
        dpopPrivateKeyCiphertext: dpopKey,
        refreshTokenCiphertext: refresh,
        accessToken: access,
        accessTokenExpiresAt: DateTime.parse(expiresAt),
        tokenType: tokenType,
        idToken: json['idToken'] is String ? json['idToken'] as String : null,
        updatedAt: DateTime.parse(updated),
      );
    } catch (_) {
      return null;
    }
  }
}

/// Namespaced, durable store for [StoredSession] values.
///
/// Implementations must be safe against corruption: [load] returns `null`
/// rather than throwing when the backing blob is unreadable, and [clear]
/// is idempotent.
abstract class TokenStore {
  /// Loads the session for [namespace]. Returns `null` when absent or
  /// unreadable.
  Future<StoredSession?> load(String namespace);

  /// Persists [session] under [namespace], replacing any prior value.
  Future<void> save(String namespace, StoredSession session);

  /// Removes any session stored under [namespace].
  Future<void> clear(String namespace);
}

Map<String, String> _blobToJson(WrappedBlob blob) => <String, String>{
      'iv': base64.encode(blob.iv),
      'ct': base64.encode(blob.ciphertext),
    };

WrappedBlob? _blobFromJson(Object? raw) {
  if (raw is! Map) return null;
  final iv = raw['iv'];
  final ct = raw['ct'];
  if (iv is! String || ct is! String) return null;
  try {
    return WrappedBlob(
      iv: Uint8List.fromList(base64.decode(iv)),
      ciphertext: Uint8List.fromList(base64.decode(ct)),
    );
  } catch (_) {
    return null;
  }
}
