import 'dart:convert';
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:antinvestor_auth_runtime/src/auth_runtime_impl.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/crypto/default_key_manager.dart';
import 'package:antinvestor_auth_runtime/src/crypto/root_key_store.dart';
import 'package:antinvestor_auth_runtime/src/oauth/oauth_flow.dart';
import 'package:antinvestor_auth_runtime/src/protocol/api_proxy.dart';
import 'package:antinvestor_auth_runtime/src/protocol/discovery.dart';
import 'package:antinvestor_auth_runtime/src/protocol/dpop.dart';
import 'package:antinvestor_auth_runtime/src/protocol/token_exchange.dart';
import 'package:antinvestor_auth_runtime/src/runtime/refresh_lock.dart';
import 'package:antinvestor_auth_runtime/src/storage/secure_token_store.dart';
import 'package:antinvestor_auth_runtime/src/worker/token_worker.dart';
import 'package:flutter_test/flutter_test.dart';

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

class _FakeDiscoveryClient implements DiscoveryClient {
  @override
  Future<OidcDiscovery> getDiscovery(String idpBaseUrl, Duration timeout) async {
    return OidcDiscovery(
      issuer: idpBaseUrl,
      authorizationEndpoint: '$idpBaseUrl/oauth2/auth',
      tokenEndpoint: '$idpBaseUrl/oauth2/token',
      endSessionEndpoint: '$idpBaseUrl/oauth2/sessions/logout',
      revocationEndpoint: '$idpBaseUrl/oauth2/revoke',
    );
  }
}

class _FakeTokenExchange extends TokenExchange {
  _FakeTokenExchange() : super(timeout: const Duration(seconds: 5));

  final List<TokenSet> queue = [];
  int calls = 0;

  @override
  Future<TokenSet> exchangeCode(
    ResolvedConfig cfg,
    DpopContext ctx, {
    required String code,
    required String verifier,
  }) async {
    calls++;
    if (queue.isEmpty) {
      throw AuthError(AuthErrorCode.tokenExchangeFailed, 'no token queued');
    }
    return queue.removeAt(0);
  }
}

class _FakeApiProxy extends ApiProxy {
  _FakeApiProxy();

  int fetchCalls = 0;
  String? seenPath;
  String? seenMethod;

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
    seenPath = path;
    seenMethod = method;
    await tp.ensureFresh();
    return ApiResponse(
      status: 200,
      headers: const {'content-type': 'application/json'},
      body: Uint8List.fromList(utf8.encode('{"ok":true}')),
    );
  }
}

class _FakeOAuthFlow extends OAuthFlow {
  _FakeOAuthFlow({required this.code, required this.verifier});

  final String code;
  final String verifier;
  int authorizeCalls = 0;

  @override
  Future<OAuthResult> authorize(ResolvedConfig cfg) async {
    authorizeCalls++;
    return OAuthResult(
      code: code,
      verifier: verifier,
      state: null,
      nonce: null,
    );
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const _config = AuthConfig(
  clientId: 'runtime-client',
  idpBaseUrl: 'https://idp.example.com',
  apiBaseUrl: 'https://api.example.com',
  redirectScheme: 'com.example.app',
);

TokenSet _tokens({
  String access = 'at-1',
  String refresh = 'rt-1',
  String? id,
  DateTime? expiresAt,
}) =>
    TokenSet(
      accessToken: access,
      refreshToken: refresh,
      expiresAt: expiresAt ?? DateTime.utc(2030, 1, 1),
      tokenType: TokenType.bearer,
      idToken: id,
    );

String _makeJwt(Map<String, dynamic> payload) {
  String strip(String s) => s.replaceAll('=', '');
  final header = strip(base64Url.encode(utf8.encode(json.encode({'alg': 'RS256'}))));
  final body = strip(base64Url.encode(utf8.encode(json.encode(payload))));
  final sig = strip(base64Url.encode([1, 2, 3]));
  return '$header.$body.$sig';
}

class _Harness {
  _Harness({
    TokenSet? initialTokens,
    _FakeOAuthFlow? flow,
    InMemoryKeyValueStore? sessionKv,
    InMemoryKeyValueStore? rootKv,
  })  : sessionKv = sessionKv ?? InMemoryKeyValueStore(),
        rootKv = rootKv ?? InMemoryKeyValueStore(),
        oauthFlow = flow ??
            _FakeOAuthFlow(code: 'code-1', verifier: 'verif-1') {
    exchange = _FakeTokenExchange();
    if (initialTokens != null) exchange.queue.add(initialTokens);
  }

  final _FakeOAuthFlow oauthFlow;
  final InMemoryKeyValueStore sessionKv;
  final InMemoryKeyValueStore rootKv;
  late final _FakeTokenExchange exchange;
  final _FakeApiProxy apiProxy = _FakeApiProxy();

  AuthRuntime build() => createAuthRuntime(
        _config,
        keyManager: DefaultKeyManager(),
        rootKeyStore: DefaultRootKeyStore(kv: rootKv),
        tokenStore: SecureTokenStore(kv: sessionKv),
        discoveryClient: _FakeDiscoveryClient(),
        tokenExchange: exchange,
        apiProxy: apiProxy,
        refreshLock: RefreshLock(),
        oauthFlow: oauthFlow,
      );
}

void main() {
  tearDown(clearDiscoveryCache);

  test('fresh runtime starts in unauthenticated', () async {
    final h = _Harness();
    final rt = h.build();
    // Allow init() to settle.
    await Future<void>.delayed(Duration.zero);
    await Future<void>.delayed(Duration.zero);
    expect(rt.state, AuthState.unauthenticated);
    await rt.dispose();
  });

  test('ensureAuthenticated drives OAuth and transitions to authenticated',
      () async {
    final h = _Harness(initialTokens: _tokens(access: 'at-fresh'));
    final rt = h.build();
    final states = <AuthState>[];
    rt.authStateStream.listen(states.add);

    await rt.ensureAuthenticated();
    await Future<void>.delayed(Duration.zero);

    expect(rt.state, AuthState.authenticated);
    expect(h.oauthFlow.authorizeCalls, 1);
    expect(h.exchange.calls, 1);
    expect(states.last, AuthState.authenticated);
    await rt.dispose();
  });

  test('ensureAuthenticated is a no-op when already authenticated', () async {
    final h = _Harness(initialTokens: _tokens());
    final rt = h.build();
    await rt.ensureAuthenticated();
    expect(h.oauthFlow.authorizeCalls, 1);

    await rt.ensureAuthenticated();
    expect(h.oauthFlow.authorizeCalls, 1,
        reason: 'a second call with live session must not reopen the browser');
    await rt.dispose();
  });

  test('concurrent ensureAuthenticated callers share one OAuth flow',
      () async {
    final h = _Harness(initialTokens: _tokens());
    final rt = h.build();
    final a = rt.ensureAuthenticated();
    final b = rt.ensureAuthenticated();
    await Future.wait([a, b]);
    expect(h.oauthFlow.authorizeCalls, 1);
    await rt.dispose();
  });

  test(
      'second runtime instance over the same storage starts authenticated '
      'without re-doing OAuth', () async {
    final sessionKv = InMemoryKeyValueStore();
    final rootKv = InMemoryKeyValueStore();

    final h1 = _Harness(
      initialTokens: _tokens(access: 'at-persisted'),
      sessionKv: sessionKv,
      rootKv: rootKv,
    );
    final rt1 = h1.build();
    await rt1.ensureAuthenticated();
    expect(rt1.state, AuthState.authenticated);
    await rt1.dispose();

    final h2 = _Harness(sessionKv: sessionKv, rootKv: rootKv);
    final rt2 = h2.build();
    // Allow init() to finish decrypting.
    await Future<void>.delayed(Duration.zero);
    await Future<void>.delayed(Duration.zero);
    expect(rt2.state, AuthState.authenticated);
    // OAuth must NOT have been reopened.
    expect(h2.oauthFlow.authorizeCalls, 0);
    expect(h2.exchange.calls, 0);
    await rt2.dispose();
  });

  test('fetch proxies through to the worker/ApiProxy', () async {
    final h = _Harness(initialTokens: _tokens());
    final rt = h.build();
    await rt.ensureAuthenticated();

    final res = await rt.fetch('/users/me', method: 'GET');
    expect(res.status, 200);
    expect(h.apiProxy.fetchCalls, 1);
    expect(h.apiProxy.seenPath, '/users/me');
    expect(h.apiProxy.seenMethod, 'GET');
    await rt.dispose();
  });

  test('getClaims returns empty map when unauthenticated', () async {
    final h = _Harness();
    final rt = h.build();
    await Future<void>.delayed(Duration.zero);
    final claims = await rt.getClaims();
    expect(claims, isEmpty);
    final roles = await rt.getRoles();
    expect(roles, isEmpty);
    await rt.dispose();
  });

  test('getClaims / getRoles after auth', () async {
    final id = _makeJwt({'sub': 'u-42', 'email': 'alice@example.com'});
    final access = _makeJwt({
      'sub': 'u-42',
      'roles': ['admin', 'staff'],
    });
    final h = _Harness(initialTokens: _tokens(access: access, id: id));
    final rt = h.build();
    await rt.ensureAuthenticated();

    final claims = await rt.getClaims();
    expect(claims['sub'], 'u-42');
    expect(claims['email'], 'alice@example.com');

    final roles = await rt.getRoles();
    expect(roles, ['admin', 'staff']);
    await rt.dispose();
  });

  test('getUserClaims wraps getClaims in a typed UserClaims', () async {
    final id = _makeJwt({
      'sub': 'u-42',
      'email': 'alice@example.com',
      'contact_id': 'contact-abc',
      'tenant_id': 'tenant-xyz',
      'partition_id': 'partition-42',
    });
    final h = _Harness(initialTokens: _tokens(id: id));
    final rt = h.build();
    await rt.ensureAuthenticated();

    final claims = await rt.getUserClaims();
    expect(claims.sub, 'u-42');
    expect(claims.email, 'alice@example.com');
    expect(claims.contactId, 'contact-abc');
    expect(claims.tenantId, 'tenant-xyz');
    expect(claims.partitionId, 'partition-42');
    await rt.dispose();
  });

  test('getUserClaims returns empty UserClaims when unauthenticated',
      () async {
    final h = _Harness();
    final rt = h.build();
    await Future<void>.delayed(Duration.zero);
    final claims = await rt.getUserClaims();
    expect(claims.sub, isNull);
    expect(claims.contactId, isNull);
    await rt.dispose();
  });

  test('logout clears local state and transitions to unauthenticated',
      () async {
    final h = _Harness(initialTokens: _tokens());
    final rt = h.build();
    await rt.ensureAuthenticated();
    expect(rt.state, AuthState.authenticated);

    await rt.logout();
    expect(rt.state, AuthState.unauthenticated);
    await rt.dispose();
  });

  test('dispose is idempotent and subsequent operations throw', () async {
    final h = _Harness();
    final rt = h.build();
    await Future<void>.delayed(Duration.zero);
    await rt.dispose();
    await rt.dispose(); // no throw
    expect(() => rt.fetch('/x'), throwsStateError);
    expect(() => rt.ensureAuthenticated(), throwsStateError);
  });

  test('version exposes authRuntimeVersion constant', () async {
    final rt = _Harness().build();
    expect(rt.version, authRuntimeVersion);
    expect(rt.version, '0.2.0');
    await rt.dispose();
  });

  test('useIsolate: true returns an IsolatedAuthRuntime-backed shell',
      () async {
    // The shell spawns the scaffolding isolate entry point and only
    // implements lifecycle in v0.1; data-plane calls throw
    // UnimplementedError (covered by test/worker/token_isolate_test.dart).
    final rt = createAuthRuntime(_config, useIsolate: true);
    expect(rt.version, authRuntimeVersion);
    await rt.dispose();
  });

  test('concrete type is AuthRuntimeImpl (in-thread baseline)', () async {
    final rt = _Harness().build();
    expect(rt, isA<AuthRuntimeImpl>());
    await rt.dispose();
  });
}
