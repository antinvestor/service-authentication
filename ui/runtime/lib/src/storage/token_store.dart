import 'dart:convert';
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/crypto/key_manager.dart';

/// Persisted session snapshot for a single namespace.
///
/// Everything sensitive is wrapped or encrypted before it reaches this
/// struct. The refresh token is wrapped under an AES-GCM key
/// ([wrappedRefreshToken]); the wrap key itself + DPoP private key are
/// serialised as ciphertext blobs whose encryption layer is chosen by the
/// concrete [TokenStore] implementation (typically the OS keychain via
/// `flutter_secure_storage`).
class StoredSession {
  const StoredSession({
    required this.wrappedRefreshToken,
    required this.dpopKeyEncrypted,
    required this.wrapKeyEncrypted,
    required this.updatedAt,
    this.lastIdToken,
  });

  /// AES-GCM blob whose key is [wrapKeyEncrypted].
  final WrappedBlob wrappedRefreshToken;

  /// Encrypted DPoP private key (format is backend-defined).
  final Uint8List dpopKeyEncrypted;

  /// Encrypted AES-GCM wrap key (format is backend-defined).
  final Uint8List wrapKeyEncrypted;

  /// Last observed `id_token`, stored for quick claim extraction on
  /// cold start. Not required for session continuity.
  final String? lastIdToken;

  /// Wall-clock timestamp of the most recent save. Used by UIs that
  /// want to display "last seen" and by integrity checks.
  final DateTime updatedAt;

  /// JSON-encodable representation. Binary fields are base64-encoded.
  Map<String, dynamic> toJson() => <String, dynamic>{
        'v': 1,
        'wrappedRt': <String, String>{
          'iv': base64.encode(wrappedRefreshToken.iv),
          'ct': base64.encode(wrappedRefreshToken.ciphertext),
        },
        'dpopKeyEnc': base64.encode(dpopKeyEncrypted),
        'wrapKeyEnc': base64.encode(wrapKeyEncrypted),
        'idToken': lastIdToken,
        'updatedAt': updatedAt.toUtc().toIso8601String(),
      };

  /// Parses a map produced by [toJson]. Returns null on any schema/shape
  /// error — callers treat null as "no session stored".
  static StoredSession? tryFromJson(Map<String, dynamic> json) {
    try {
      if (json['v'] != 1) return null;
      final rt = json['wrappedRt'];
      if (rt is! Map) return null;
      final iv = rt['iv'];
      final ct = rt['ct'];
      final dk = json['dpopKeyEnc'];
      final wk = json['wrapKeyEnc'];
      final ua = json['updatedAt'];
      if (iv is! String || ct is! String || dk is! String || wk is! String ||
          ua is! String) {
        return null;
      }
      return StoredSession(
        wrappedRefreshToken: WrappedBlob(
          iv: Uint8List.fromList(base64.decode(iv)),
          ciphertext: Uint8List.fromList(base64.decode(ct)),
        ),
        dpopKeyEncrypted: Uint8List.fromList(base64.decode(dk)),
        wrapKeyEncrypted: Uint8List.fromList(base64.decode(wk)),
        lastIdToken: json['idToken'] is String ? json['idToken'] as String : null,
        updatedAt: DateTime.parse(ua),
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
