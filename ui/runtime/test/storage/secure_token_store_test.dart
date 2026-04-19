import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/crypto/key_manager.dart';
import 'package:antinvestor_auth_runtime/src/storage/secure_token_store.dart';
import 'package:antinvestor_auth_runtime/src/storage/token_store.dart';
import 'package:flutter_test/flutter_test.dart';

StoredSession _session({String? idToken, DateTime? at}) => StoredSession(
      wrappedRefreshToken: WrappedBlob(
        iv: Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
        ciphertext: Uint8List.fromList(List<int>.generate(48, (i) => i)),
      ),
      dpopKeyEncrypted: Uint8List.fromList([0x10, 0x20, 0x30]),
      wrapKeyEncrypted: Uint8List.fromList([0x40, 0x50, 0x60]),
      lastIdToken: idToken,
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
    expect(loaded!.wrappedRefreshToken.iv, s.wrappedRefreshToken.iv);
    expect(loaded.wrappedRefreshToken.ciphertext,
        s.wrappedRefreshToken.ciphertext);
    expect(loaded.dpopKeyEncrypted, s.dpopKeyEncrypted);
    expect(loaded.wrapKeyEncrypted, s.wrapKeyEncrypted);
    expect(loaded.lastIdToken, 'id-abc');
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
    expect((await store.load('nsA'))!.lastIdToken, 'A');
    expect((await store.load('nsB'))!.lastIdToken, 'B');
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
    await kv.write('auth:badshape', '{"v":1,"wrappedRt":"wrong-type"}');
    expect(await store.load('badshape'), isNull);
  });

  test('wrong version returns null', () async {
    await kv.write('auth:oldver',
        '{"v":99,"wrappedRt":{"iv":"","ct":""},"dpopKeyEnc":"","wrapKeyEnc":"","updatedAt":"2026-04-19T00:00:00Z"}');
    expect(await store.load('oldver'), isNull);
  });

  test('missing id_token is preserved as null', () async {
    await store.save('ns-no-id', _session());
    final loaded = await store.load('ns-no-id');
    expect(loaded!.lastIdToken, isNull);
  });
}
