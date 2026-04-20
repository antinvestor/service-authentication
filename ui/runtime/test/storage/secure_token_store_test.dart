import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/crypto/key_manager.dart';
import 'package:antinvestor_auth_runtime/src/storage/secure_token_store.dart';
import 'package:antinvestor_auth_runtime/src/storage/token_store.dart';
import 'package:flutter_test/flutter_test.dart';

WrappedBlob _blob(int seed) => WrappedBlob(
      iv: Uint8List.fromList(List<int>.generate(12, (i) => (seed + i) & 0xff)),
      ciphertext: Uint8List.fromList(
        List<int>.generate(48, (i) => (seed * 7 + i) & 0xff),
      ),
    );

StoredSession _session({String? idToken, DateTime? at}) => StoredSession(
      wrapKeyCiphertext: _blob(1),
      dpopPrivateKeyCiphertext: _blob(2),
      refreshTokenCiphertext: _blob(3),
      accessToken: 'at-abc',
      accessTokenExpiresAt: DateTime.utc(2026, 4, 19, 23, 0, 0),
      tokenType: 'Bearer',
      idToken: idToken,
      updatedAt: at ?? DateTime.utc(2026, 4, 19, 22, 35, 0),
    );

void main() {
  late InMemoryKeyValueStore kv;
  late SecureTokenStore store;

  setUp(() {
    kv = InMemoryKeyValueStore();
    store = SecureTokenStore(kv: kv);
  });

  test('save then load round-trips', () async {
    final s = _session(idToken: 'id-abc');
    await store.save('ns1', s);
    final loaded = await store.load('ns1');
    expect(loaded, isNotNull);
    expect(loaded!.wrapKeyCiphertext.iv, s.wrapKeyCiphertext.iv);
    expect(loaded.wrapKeyCiphertext.ciphertext, s.wrapKeyCiphertext.ciphertext);
    expect(loaded.dpopPrivateKeyCiphertext.iv, s.dpopPrivateKeyCiphertext.iv);
    expect(loaded.dpopPrivateKeyCiphertext.ciphertext,
        s.dpopPrivateKeyCiphertext.ciphertext);
    expect(loaded.refreshTokenCiphertext.iv, s.refreshTokenCiphertext.iv);
    expect(loaded.refreshTokenCiphertext.ciphertext,
        s.refreshTokenCiphertext.ciphertext);
    expect(loaded.accessToken, 'at-abc');
    expect(loaded.accessTokenExpiresAt, s.accessTokenExpiresAt);
    expect(loaded.tokenType, 'Bearer');
    expect(loaded.idToken, 'id-abc');
    expect(loaded.updatedAt, s.updatedAt);
  });

  test('load of unknown namespace returns null', () async {
    expect(await store.load('never-saved'), isNull);
  });

  test('namespaces are isolated', () async {
    final a = _session(idToken: 'A');
    final b = _session(idToken: 'B');
    await store.save('nsA', a);
    await store.save('nsB', b);
    expect((await store.load('nsA'))!.idToken, 'A');
    expect((await store.load('nsB'))!.idToken, 'B');
  });

  test('clear removes the stored session', () async {
    await store.save('nsX', _session());
    expect(await store.load('nsX'), isNotNull);
    await store.clear('nsX');
    expect(await store.load('nsX'), isNull);
  });

  test('clear on unknown namespace does not throw', () async {
    await store.clear('does-not-exist');
  });

  test('corrupt JSON on load returns null (no throw)', () async {
    await kv.write('auth:corrupt', 'not-json-at-all');
    expect(await store.load('corrupt'), isNull);
  });

  test('valid JSON with bad shape returns null', () async {
    await kv.write('auth:badshape', '{"v":2,"wrapKey":"wrong-type"}');
    expect(await store.load('badshape'), isNull);
  });

  test('wrong version returns null', () async {
    await kv.write(
      'auth:oldver',
      '{"v":99,"wrapKey":{"iv":"","ct":""},'
          '"dpopKey":{"iv":"","ct":""},'
          '"refreshToken":{"iv":"","ct":""},'
          '"accessToken":"x","accessExpiresAt":"2026-04-19T00:00:00Z",'
          '"tokenType":"Bearer","updatedAt":"2026-04-19T00:00:00Z"}',
    );
    expect(await store.load('oldver'), isNull);
  });

  test('legacy v1 schema is rejected (returns null)', () async {
    // v1 had: wrappedRt/dpopKeyEnc/wrapKeyEnc/idToken/updatedAt.
    // We explicitly don't support forward-migration; callers fall back
    // to a fresh sign-in.
    await kv.write(
      'auth:v1',
      '{"v":1,"wrappedRt":{"iv":"","ct":""},"dpopKeyEnc":"","wrapKeyEnc":"",'
          '"updatedAt":"2026-04-19T00:00:00Z"}',
    );
    expect(await store.load('v1'), isNull);
  });

  test('missing id_token is preserved as null', () async {
    await store.save('ns-no-id', _session());
    final loaded = await store.load('ns-no-id');
    expect(loaded!.idToken, isNull);
  });
}
