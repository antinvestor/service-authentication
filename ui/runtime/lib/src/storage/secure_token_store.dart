import 'dart:convert';

import 'package:antinvestor_auth_runtime/src/storage/token_store.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Minimal KV contract over opaque strings.
///
/// Introduced so the test harness can inject an in-memory implementation
/// without touching `flutter_secure_storage`'s platform channels.
abstract class KeyValueStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

/// Production-backed [KeyValueStore] using `flutter_secure_storage`.
///
/// The underlying plugin applies OS-specific hardware-backed encryption
/// (iOS Keychain, Android Keystore, macOS Keychain, Linux libsecret).
class SecureStorageKeyValueStore implements KeyValueStore {
  SecureStorageKeyValueStore({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;

  @override
  Future<String?> read(String key) => _storage.read(key: key);

  @override
  Future<void> write(String key, String value) =>
      _storage.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _storage.delete(key: key);
}

/// In-memory [KeyValueStore] for tests. NOT suitable for production —
/// values live only as long as the process.
class InMemoryKeyValueStore implements KeyValueStore {
  final Map<String, String> _store = {};

  @override
  Future<String?> read(String key) async => _store[key];

  @override
  Future<void> write(String key, String value) async {
    _store[key] = value;
  }

  @override
  Future<void> delete(String key) async {
    _store.remove(key);
  }
}

/// [TokenStore] backed by a [KeyValueStore] containing JSON-encoded
/// [StoredSession]s.
///
/// A fixed `auth:` prefix namespaces our entries inside the shared
/// keychain partition.
class SecureTokenStore implements TokenStore {
  SecureTokenStore({KeyValueStore? kv})
      : _kv = kv ?? SecureStorageKeyValueStore();

  final KeyValueStore _kv;

  String _keyFor(String namespace) => 'auth:$namespace';

  @override
  Future<StoredSession?> load(String namespace) async {
    final raw = await _kv.read(_keyFor(namespace));
    if (raw == null || raw.isEmpty) return null;
    try {
      final decoded = json.decode(raw);
      if (decoded is! Map) return null;
      return StoredSession.tryFromJson(decoded.cast<String, dynamic>());
    } catch (_) {
      // Corrupt JSON: surface as "no session" rather than crashing the
      // caller. Higher-level security policy (e.g. wipe-on-corruption)
      // is owned by the runtime layer.
      return null;
    }
  }

  @override
  Future<void> save(String namespace, StoredSession session) async {
    final payload = json.encode(session.toJson());
    await _kv.write(_keyFor(namespace), payload);
  }

  @override
  Future<void> clear(String namespace) async {
    await _kv.delete(_keyFor(namespace));
  }
}
