import 'dart:convert';

import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:antinvestor_auth_runtime/src/crypto/default_key_manager.dart';
import 'package:antinvestor_auth_runtime/src/crypto/root_key_store.dart';
import 'package:antinvestor_auth_runtime/src/storage/secure_token_store.dart';
import 'package:antinvestor_auth_runtime/src/storage/token_store.dart';
import 'package:flutter_test/flutter_test.dart';

import '_helpers.dart';
import 'mock_idp.dart';

void main() {
  late IntegrationHarness h;

  tearDown(() async {
    await h.dispose();
  });

  test(
      'submitting a consumed RT triggers reuse detection, wipes session, '
      'emits RefreshReuseDetected', () async {
    final mock = MockIdp(tokenLifetime: const Duration(seconds: 30));
    h = await buildHarness(mock: mock);

    await h.runtime.ensureAuthenticated();

    final events = <SecurityEvent>[];
    h.runtime.securityEventStream.listen(events.add);

    // Drive one rotation so the mock has consumed rt-1 and issued rt-2.
    try {
      await h.runtime.fetch('/ping');
    } catch (_) {/* 404 ok */}
    expect(
      h.mock.tokenRequests
          .where((r) => r.grantType == 'refresh_token')
          .length,
      1,
    );

    // Persist rt-1 back into storage under the covers to model an attacker
    // replaying a stolen token (or a cloned-device scenario).
    await _rewriteStoredRefreshToken(
      sessionKv: h.sessionKv,
      rootKv: h.rootKv,
      namespace: h.config.namespace,
      replacement: 'rt-1',
    );

    // Force the worker to reload its session from storage so it picks up
    // the rewritten RT.
    final reloadedMock = mock;
    final sessionKv = h.sessionKv;
    final rootKv = h.rootKv;
    await h.runtime.dispose();
    h = await buildHarness(
      mock: reloadedMock,
      sessionKv: sessionKv,
      rootKv: rootKv,
    );
    final events2 = <SecurityEvent>[];
    h.runtime.securityEventStream.listen(events2.add);

    // Next fetch drives a refresh; mock rejects rt-1 with invalid_grant +
    // reuse_detected description.
    try {
      await h.runtime.fetch('/ping');
      fail('expected AuthError(refreshReuseDetected)');
    } on AuthError catch (e) {
      expect(e.code, AuthErrorCode.refreshReuseDetected);
    }

    await Future<void>.delayed(Duration.zero);
    expect(events2.whereType<RefreshReuseDetected>(), isNotEmpty);
    expect(h.runtime.state, AuthState.unauthenticated);
    expect(await h.tokenStore.load(h.config.namespace), isNull);
  });
}

/// Rewrites the stored refresh token ciphertext so that decrypting it
/// yields [replacement].
///
/// Round-trip: read the session, decrypt the wrap key, re-wrap the new
/// plaintext under the same wrap key, put it back.
Future<void> _rewriteStoredRefreshToken({
  required KeyValueStore sessionKv,
  required KeyValueStore rootKv,
  required String namespace,
  required String replacement,
}) async {
  final km = DefaultKeyManager();
  final rootKeyStore = DefaultRootKeyStore(kv: rootKv);
  final tokenStore = SecureTokenStore(kv: sessionKv);

  final stored = await tokenStore.load(namespace);
  if (stored == null) {
    throw StateError('no stored session to rewrite');
  }

  // Decrypt wrap key under root key.
  final rootKeyBytes = await rootKeyStore.getOrCreate(namespace);
  final rootKey = await km.importWrapKey(rootKeyBytes);
  final wrapKeyBytes = await km.unwrap(rootKey, stored.wrapKeyCiphertext);
  final wrapKey = await km.importWrapKey(wrapKeyBytes);

  // Re-wrap the replacement refresh token under the same wrap key.
  final newBlob = await km.wrap(wrapKey, utf8.encode(replacement));

  await tokenStore.save(
    namespace,
    StoredSession(
      wrapKeyCiphertext: stored.wrapKeyCiphertext,
      dpopPrivateKeyCiphertext: stored.dpopPrivateKeyCiphertext,
      refreshTokenCiphertext: newBlob,
      accessToken: stored.accessToken,
      accessTokenExpiresAt: stored.accessTokenExpiresAt,
      tokenType: stored.tokenType,
      idToken: stored.idToken,
      updatedAt: stored.updatedAt,
    ),
  );
}
