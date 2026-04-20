import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/storage/secure_token_store.dart';

/// Persistent per-install root key ("KEK") used to encrypt the wrap key.
///
/// The root key itself lives in a hardware-backed keystore
/// (`flutter_secure_storage`) under the key `"{namespace}::root-key"`.
/// From the runtime's perspective this is simply 32 bytes of AES-GCM key
/// material it can derive a [WrapKey]-equivalent from; security guarantees
/// come from the underlying platform keychain.
///
/// Splitting this out as an interface lets tests substitute a pure
/// in-memory implementation and lets future platform hardening (Android
/// StrongBox / iOS Secure Enclave-bound keys) drop in without touching
/// the rest of the runtime.
abstract class RootKeyStore {
  /// Returns the root key for [namespace], generating + persisting a fresh
  /// one the first time it is requested. Always returns exactly 32 bytes.
  Future<Uint8List> getOrCreate(String namespace);

  /// Forces a rotation: generates a new root key and overwrites the stored
  /// one. Used on security-wipe so any previously-wrapped material becomes
  /// unreadable.
  Future<void> rotate(String namespace);

  /// Deletes the root key for [namespace]. Subsequent reads behave as if
  /// the namespace had never been seen.
  Future<void> clear(String namespace);
}

/// Default [RootKeyStore] that persists 32 bytes of random key material in
/// a [KeyValueStore] (production: `flutter_secure_storage`).
class DefaultRootKeyStore implements RootKeyStore {
  DefaultRootKeyStore({required KeyValueStore kv, Random? random})
      : _kv = kv,
        _random = random ?? Random.secure();

  final KeyValueStore _kv;
  final Random _random;

  String _keyFor(String namespace) => '$namespace::root-key';

  @override
  Future<Uint8List> getOrCreate(String namespace) async {
    final existing = await _kv.read(_keyFor(namespace));
    if (existing != null && existing.isNotEmpty) {
      try {
        final decoded = base64.decode(existing);
        if (decoded.length == 32) {
          return Uint8List.fromList(decoded);
        }
      } catch (_) {
        // Corrupt entry — fall through and overwrite with a fresh key.
      }
    }
    final fresh = _generate();
    await _kv.write(_keyFor(namespace), base64.encode(fresh));
    return fresh;
  }

  @override
  Future<void> rotate(String namespace) async {
    final fresh = _generate();
    await _kv.write(_keyFor(namespace), base64.encode(fresh));
  }

  @override
  Future<void> clear(String namespace) async {
    await _kv.delete(_keyFor(namespace));
  }

  Uint8List _generate() {
    final out = Uint8List(32);
    for (var i = 0; i < out.length; i++) {
      out[i] = _random.nextInt(256);
    }
    return out;
  }
}
