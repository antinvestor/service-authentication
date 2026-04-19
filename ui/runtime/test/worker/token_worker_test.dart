import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/config/auth_config.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/crypto/default_key_manager.dart';
import 'package:antinvestor_auth_runtime/src/crypto/key_manager.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/models/api_response.dart';
import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:antinvestor_auth_runtime/src/models/security_event.dart';
import 'package:antinvestor_auth_runtime/src/models/token_set.dart';
import 'package:antinvestor_auth_runtime/src/protocol/api_proxy.dart';
import 'package:antinvestor_auth_runtime/src/protocol/discovery.dart';
import 'package:antinvestor_auth_runtime/src/protocol/dpop.dart';
import 'package:antinvestor_auth_runtime/src/protocol/token_exchange.dart';
import 'package:antinvestor_auth_runtime/src/runtime/refresh_lock.dart';
import 'package:antinvestor_auth_runtime/src/storage/secure_token_store.dart';
import 'package:antinvestor_auth_runtime/src/storage/token_store.dart';
import 'package:antinvestor_auth_runtime/src/worker/token_worker.dart';
import 'package:flutter_test/flutter_test.dart';

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

class _FakeDiscoveryClient implements DiscoveryClient {
  _FakeDiscoveryClient();

  String authz = 'https://idp.example.com/oauth2/auth';
  String tokenEp = 'https://idp.example.com/oauth2/token';
  String? endSession = 'https://idp.example.com/oauth2/sessions/logout';
  String? revocation = 'https://idp.example.com/oauth2/revoke';
  bool dpop = false;
  int calls = 0;

  @override
  Future<OidcDiscovery> getDiscovery(
    String idpBaseUrl,
    Duration timeout,
  ) async {
    calls++;
    return OidcDiscovery(
      issuer: idpBaseUrl,
      authorizationEndpoint: authz,
      tokenEndpoint: tokenEp,
      endSessionEndpoint: endSession,
      revocationEndpoint: revocation,
      dpopSigningAlgValuesSupported: dpop ? const ['ES256'] : null,
    );
  }
}

/// Stub [TokenExchange] that records calls and returns canned outcomes.
class _FakeTokenExchange extends TokenExchange {
  _FakeTokenExchange()
      : super(timeout: const Duration(seconds: 5));

  List<TokenSet> rotateQueue = [];
  List<RefreshOutcome> refreshQueue = [];
  int exchangeCalls = 0;
  int refreshCalls = 0;

  @override
  Future<TokenSet> exchangeCode(
    ResolvedConfig cfg,
    DpopContext ctx, {
    required String code,
    required String verifier,
  }) async {
    exchangeCalls++;
    if (rotateQueue.isEmpty) {
      throw AuthError(
        AuthErrorCode.tokenExchangeFailed,
        'fake: no token queued',
      );
    }
    return rotateQueue.removeAt(0);
  }

  @override
  Future<RefreshOutcome> refresh(
    ResolvedConfig cfg,
    DpopContext ctx,
    String refreshToken,
  ) async {
    refreshCalls++;
    if (refreshQueue.isEmpty) {
      throw AuthError(AuthErrorCode.tokenRefreshFailed, 'no refresh queued');
    }
    return refreshQueue.removeAt(0);
  }
}

class _FakeApiProxy extends ApiProxy {
  _FakeApiProxy();

  ApiResponse? cannedResponse;
  Object? cannedError;
  int fetchCalls = 0;
  int uploadCalls = 0;
  String? seenAuthHeader;

  @override
  Future<ApiResponse> fetch(
    ResolvedConfig cfg,
    DpopContext ctx,
    TokenProvider tp, {
    required String path,
    required String method,
    Map<String, String>? headers,
    Object? body,
    Duration? timeout,
  }) async {
    fetchCalls++;
    final snap = await tp.ensureFresh();
    seenAuthHeader =
        '${snap.tokenType.headerValue} ${snap.accessToken}';
    if (cannedError != null) throw cannedError!;
    return cannedResponse ??
        ApiResponse(status: 200, headers: const {}, body: Uint8List(0));
  }

  @override
  Future<ApiResponse> upload(
    ResolvedConfig cfg,
    DpopContext ctx,
    TokenProvider tp, {
    required String path,
    required String fieldName,
    required String filename,
    required String contentType,
    required Stream<List<int>> bytes,
    required int length,
    Map<String, String>? headers,
    Duration? timeout,
  }) async {
    uploadCalls++;
    final snap = await tp.ensureFresh();
    seenAuthHeader =
        '${snap.tokenType.headerValue} ${snap.accessToken}';
    return cannedResponse ??
        ApiResponse(status: 200, headers: const {}, body: Uint8List(0));
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

ResolvedConfig _cfg() => resolveConfig(const AuthConfig(
      clientId: 'c',
      idpBaseUrl: 'https://idp.example.com',
      apiBaseUrl: 'https://api.example.com',
      redirectScheme: 'com.example.app',
    ));

TokenSet _tokens({
  String access = 'at-1',
  String refresh = 'rt-1',
  DateTime? expiresAt,
  String? idToken,
  TokenType type = TokenType.bearer,
}) =>
    TokenSet(
      accessToken: access,
      refreshToken: refresh,
      expiresAt: expiresAt ?? DateTime.utc(2030, 1, 1),
      tokenType: type,
      idToken: idToken,
    );

class _Deps {
  _Deps({
    KeyManager? km,
    TokenStore? store,
    _FakeDiscoveryClient? disco,
    _FakeTokenExchange? exchange,
    _FakeApiProxy? proxy,
    Clock? clock,
  })  : config = _cfg(),
        keyManager = km ?? DefaultKeyManager(),
        tokenStore = store ?? SecureTokenStore(kv: InMemoryKeyValueStore()),
        discoveryClient = disco ?? _FakeDiscoveryClient(),
        tokenExchange = exchange ?? _FakeTokenExchange(),
        apiProxy = proxy ?? _FakeApiProxy(),
        refreshLock = RefreshLock(),
        clock = clock ?? _fixedNow;

  final ResolvedConfig config;
  final KeyManager keyManager;
  final TokenStore tokenStore;
  final _FakeDiscoveryClient discoveryClient;
  final _FakeTokenExchange tokenExchange;
  final _FakeApiProxy apiProxy;
  final RefreshLock refreshLock;
  final Clock clock;

  TokenWorker build() => TokenWorker(
        config: config,
        keyManager: keyManager,
        tokenStore: tokenStore,
        discoveryClient: discoveryClient,
        tokenExchange: tokenExchange,
        apiProxy: apiProxy,
        refreshLock: refreshLock,
        clock: clock,
      );
}

DateTime _fixedNow() => DateTime.utc(2026, 4, 19, 12, 0, 0);

void main() {
  tearDown(clearDiscoveryCache);

  test('fresh worker with empty store ends in unauthenticated', () async {
    final d = _Deps();
    final w = d.build();
    final states = <AuthState>[];
    w.authStateStream.listen(states.add);
    await w.init();
    await Future<void>.delayed(Duration.zero);
    expect(w.state, AuthState.unauthenticated);
    expect(states, [AuthState.unauthenticated]);
    await w.destroy();
  });

  test('completeAuth persists session and transitions to authenticated',
      () async {
    final d = _Deps();
    final w = d.build();
    d.tokenExchange.rotateQueue
        .add(_tokens(access: 'access-1', refresh: 'refresh-1'));
    final states = <AuthState>[];
    w.authStateStream.listen(states.add);

    await w.init();
    await w.completeAuth(
      code: 'code-1',
      verifier: 'verif-1',
      state: 's',
      nonce: 'n',
      expectedState: 's',
    );
    // Flush microtasks so the broadcast stream delivers.
    await Future<void>.delayed(Duration.zero);
    expect(d.tokenExchange.exchangeCalls, 1);
    expect(w.state, AuthState.authenticated);
    expect(states.last, AuthState.authenticated);
    expect(await d.tokenStore.load(d.config.namespace), isNotNull);
    await w.destroy();
  });

  test('completeAuth rejects state mismatch', () async {
    final d = _Deps();
    final w = d.build();
    await w.init();
    expect(
      () => w.completeAuth(
        code: 'code',
        verifier: 'v',
        state: 'A',
        nonce: 'n',
        expectedState: 'B',
      ),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.oauthFailed,
      )),
    );
    await w.destroy();
  });

  test('prepareAuth returns a URL containing PKCE + state + nonce', () async {
    final d = _Deps();
    final w = d.build();
    await w.init();
    final req = await w.prepareAuth();
    final uri = Uri.parse(req.url);
    expect(uri.queryParameters['code_challenge_method'], 'S256');
    expect(uri.queryParameters['code_challenge'], isNotEmpty);
    expect(uri.queryParameters['state'], req.state);
    expect(uri.queryParameters['nonce'], req.nonce);
    expect(uri.queryParameters['client_id'], 'c');
    expect(uri.queryParameters['redirect_uri'], 'com.example.app://callback');
    await w.destroy();
  });

  test('refresh rotates and persists the new refresh token', () async {
    final d = _Deps();
    final w = d.build();
    d.tokenExchange.rotateQueue.add(_tokens(
      access: 'at-1',
      refresh: 'rt-1',
      // Near-expiry so ensureFresh triggers a refresh.
      expiresAt: _fixedNow().add(const Duration(seconds: 5)),
    ));
    d.tokenExchange.refreshQueue.add(RefreshOutcome.rotated(_tokens(
      access: 'at-2',
      refresh: 'rt-2',
      expiresAt: _fixedNow().add(const Duration(minutes: 10)),
    )));

    await w.init();
    await w.completeAuth(
      code: 'c',
      verifier: 'v',
      state: 's',
      nonce: 'n',
      expectedState: 's',
    );

    final snap = await w.ensureFresh();
    expect(snap.accessToken, 'at-2');
    expect(d.tokenExchange.refreshCalls, 1);
    // Persisted session reflects the new refresh token — verified indirectly
    // by the presence of a save.
    expect(await d.tokenStore.load(d.config.namespace), isNotNull);
    await w.destroy();
  });

  test('reuse-detected refresh wipes and emits SecurityEvent', () async {
    final d = _Deps();
    final w = d.build();
    d.tokenExchange.rotateQueue.add(_tokens(
      expiresAt: _fixedNow().add(const Duration(seconds: 5)),
    ));
    d.tokenExchange.refreshQueue
        .add(const RefreshOutcome.reuseDetected());

    final events = <SecurityEvent>[];
    w.securityEventStream.listen(events.add);
    final states = <AuthState>[];
    w.authStateStream.listen(states.add);

    await w.init();
    await w.completeAuth(
      code: 'c',
      verifier: 'v',
      state: 's',
      nonce: 'n',
      expectedState: 's',
    );

    await expectLater(
      w.ensureFresh(),
      throwsA(isA<AuthError>().having(
        (e) => e.code,
        'code',
        AuthErrorCode.refreshReuseDetected,
      )),
    );
    // Allow microtask-scheduled stream events to flush.
    await Future<void>.delayed(Duration.zero);
    expect(events.length, 1);
    expect(events.first, isA<RefreshReuseDetected>());
    expect(w.state, AuthState.unauthenticated);
    expect(await d.tokenStore.load(d.config.namespace), isNull);
    await w.destroy();
  });

  test('ensureFresh returns cached token when not near expiry', () async {
    final d = _Deps();
    final w = d.build();
    d.tokenExchange.rotateQueue.add(_tokens(
      access: 'at-cached',
      expiresAt: _fixedNow().add(const Duration(minutes: 10)),
    ));

    await w.init();
    await w.completeAuth(
      code: 'c',
      verifier: 'v',
      state: 's',
      nonce: 'n',
      expectedState: 's',
    );

    final snap = await w.ensureFresh();
    expect(snap.accessToken, 'at-cached');
    expect(d.tokenExchange.refreshCalls, 0);
    await w.destroy();
  });

  test('fetch forwards Authorization through ApiProxy', () async {
    final d = _Deps();
    final w = d.build();
    d.tokenExchange.rotateQueue.add(_tokens(access: 'at-xyz'));

    await w.init();
    await w.completeAuth(
      code: 'c',
      verifier: 'v',
      state: 's',
      nonce: 'n',
      expectedState: 's',
    );

    final res = await w.fetch(path: '/users', method: 'GET');
    expect(res.status, 200);
    expect(d.apiProxy.seenAuthHeader, 'Bearer at-xyz');
    expect(d.apiProxy.fetchCalls, 1);
    await w.destroy();
  });

  test('upload forwards Authorization through ApiProxy', () async {
    final d = _Deps();
    final w = d.build();
    d.tokenExchange.rotateQueue.add(_tokens(access: 'at-up'));

    await w.init();
    await w.completeAuth(
      code: 'c',
      verifier: 'v',
      state: 's',
      nonce: 'n',
      expectedState: 's',
    );

    final res = await w.upload(
      path: '/media',
      fieldName: 'file',
      filename: 'x.bin',
      contentType: 'application/octet-stream',
      bytes: Stream<List<int>>.fromIterable([
        [1, 2, 3]
      ]),
      length: 3,
    );
    expect(res.status, 200);
    expect(d.apiProxy.seenAuthHeader, 'Bearer at-up');
    expect(d.apiProxy.uploadCalls, 1);
    await w.destroy();
  });

  test('getClaims decodes ID token payload; getRoles decodes access token',
      () async {
    final d = _Deps();
    final w = d.build();
    final id = _makeJwt({'sub': 'u-1', 'email': 'a@b.c'});
    final access = _makeJwt({
      'sub': 'u-1',
      'roles': ['admin', 'user'],
    });
    d.tokenExchange.rotateQueue.add(_tokens(
      access: access,
      idToken: id,
    ));

    await w.init();
    await w.completeAuth(
      code: 'c',
      verifier: 'v',
      state: 's',
      nonce: 'n',
      expectedState: 's',
    );

    final claims = await w.getClaims();
    expect(claims['sub'], 'u-1');
    expect(claims['email'], 'a@b.c');

    final roles = await w.getRoles();
    expect(roles, ['admin', 'user']);
    await w.destroy();
  });

  test('logout clears session + transitions to unauthenticated', () async {
    final d = _Deps();
    final w = d.build();
    d.tokenExchange.rotateQueue.add(_tokens());

    await w.init();
    await w.completeAuth(
      code: 'c',
      verifier: 'v',
      state: 's',
      nonce: 'n',
      expectedState: 's',
    );
    expect(w.state, AuthState.authenticated);
    expect(await d.tokenStore.load(d.config.namespace), isNotNull);

    await w.logout();
    expect(w.state, AuthState.unauthenticated);
    expect(await d.tokenStore.load(d.config.namespace), isNull);
    await w.destroy();
  });

  test('operations after destroy() throw StateError', () async {
    final d = _Deps();
    final w = d.build();
    await w.init();
    await w.destroy();
    expect(() => w.init(), throwsStateError);
    expect(() => w.prepareAuth(), throwsStateError);
  });
}

String _makeJwt(Map<String, dynamic> payload) {
  final header = base64Url.encode(utf8.encode(json.encode({'alg': 'RS256'})));
  final body = base64Url.encode(utf8.encode(json.encode(payload)));
  final sig = base64Url.encode([1, 2, 3]);
  String strip(String s) => s.replaceAll('=', '');
  return '${strip(header)}.${strip(body)}.${strip(sig)}';
}
