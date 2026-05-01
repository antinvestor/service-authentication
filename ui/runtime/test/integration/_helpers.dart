import 'dart:async';

import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:antinvestor_auth_runtime/src/auth_runtime_impl.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/crypto/default_key_manager.dart';
import 'package:antinvestor_auth_runtime/src/crypto/root_key_store.dart';
import 'package:antinvestor_auth_runtime/src/oauth/oauth_flow.dart';
import 'package:antinvestor_auth_runtime/src/protocol/api_proxy.dart';
import 'package:antinvestor_auth_runtime/src/protocol/discovery.dart';
import 'package:antinvestor_auth_runtime/src/protocol/token_exchange.dart';
import 'package:antinvestor_auth_runtime/src/runtime/refresh_lock.dart';
import 'package:antinvestor_auth_runtime/src/storage/secure_token_store.dart';
import 'package:antinvestor_auth_runtime/src/storage/token_store.dart';
import 'package:antinvestor_auth_runtime/src/worker/token_worker.dart';

import 'mock_idp.dart';

/// Deterministic controllable clock.
///
/// The integration tests inject this into [TokenWorker] so they can
/// fast-forward across access-token expiry without sleeping for real time.
class TestClock {
  TestClock(this._now);

  DateTime _now;

  DateTime now() => _now;

  void advance(Duration d) {
    _now = _now.add(d);
  }

  void setTo(DateTime t) {
    _now = t;
  }
}

/// Short-circuits the browser leg of OAuth: returns a pre-built
/// `code` and echoes the worker-issued `state` without ever opening a
/// browser. The MockIdp's `/token` handler accepts any code, so we don't
/// even need to hit a real `/authorize` endpoint.
class FakeOAuthFlow implements OAuthFlow {
  FakeOAuthFlow({this.code = 'fake-code'});

  final String code;
  int calls = 0;

  /// The last [AuthorizeRequest] passed to [authorize]. Tests can read
  /// `lastPrepared.verifier` to assert the worker's PKCE verifier flowed
  /// through end-to-end.
  AuthorizeRequest? lastPrepared;

  /// Driven from outside: if set, [authorize] throws this instead of
  /// returning a result. Lets tests exercise the cancellation path.
  Object? pendingError;

  @override
  Future<OAuthResult> authorize(
    ResolvedConfig cfg,
    AuthorizeRequest prepared,
  ) async {
    calls++;
    lastPrepared = prepared;
    final err = pendingError;
    if (err != null) {
      pendingError = null;
      throw err;
    }
    return OAuthResult(code: code, state: prepared.state);
  }
}

/// Bundle returned by [buildHarness] — exposes everything a test needs
/// to assert against without reaching into the factory.
class IntegrationHarness {
  IntegrationHarness({
    required this.runtime,
    required this.worker,
    required this.mock,
    required this.fakeOAuth,
    required this.clock,
    required this.tokenStore,
    required this.sessionKv,
    required this.rootKv,
    required this.config,
  });

  final AuthRuntime runtime;
  final TokenWorker worker;
  final MockIdp mock;
  final FakeOAuthFlow fakeOAuth;
  final TestClock clock;
  final TokenStore tokenStore;
  final KeyValueStore sessionKv;
  final KeyValueStore rootKv;
  final ResolvedConfig config;

  Future<void> dispose() async {
    await runtime.dispose();
    clearDiscoveryCache();
    await mock.stop();
  }
}

/// Builds an end-to-end wired runtime pointed at a running MockIdp.
///
/// The runtime uses the real in-thread [TokenWorker] + real
/// [TokenExchange] + real [ApiProxy] so the HTTP round-trips, DPoP proofs
/// and discovery cache are all exercised exactly as they would be in
/// production. The only seam is the browser leg: a [FakeOAuthFlow] that
/// returns a pre-built [OAuthResult].
///
/// The caller should invoke `await harness.dispose()` in `tearDown`.
Future<IntegrationHarness> buildHarness({
  MockIdp? mock,
  TestClock? clock,
  FakeOAuthFlow? fakeOAuth,
  KeyValueStore? sessionKv,
  KeyValueStore? rootKv,
  List<NativeCredentialProvider> nativeProviders = const [],
}) async {
  final m = mock ?? MockIdp();
  // Idempotent start: if the mock hasn't listened yet, start it. Tests
  // that pre-start the mock (to configure toggles before runtime build)
  // hit the `try` path.
  String base;
  final existing = _tryGetBaseUrl(m);
  if (existing != null) {
    base = existing;
  } else {
    base = await m.start();
  }

  final testClock = clock ?? TestClock(DateTime.now());
  final fake = fakeOAuth ?? FakeOAuthFlow();
  final sKv = sessionKv ?? InMemoryKeyValueStore();
  final rKv = rootKv ?? InMemoryKeyValueStore();

  final cfg = resolveConfig(AuthConfig(
    clientId: 'antinvestor-mobile',
    idpBaseUrl: base,
    apiBaseUrl: base, // Authenticated API calls land on the mock too.
    redirectScheme: 'com.antinvestor.test',
    scopes: const <String>['openid', 'profile', 'email', 'offline_access'],
  ));

  // Clear the module-level discovery cache so each test starts fresh.
  clearDiscoveryCache();

  final tokenStore = SecureTokenStore(kv: sKv);
  final worker = TokenWorker(
    config: cfg,
    keyManager: DefaultKeyManager(),
    rootKeyStore: DefaultRootKeyStore(kv: rKv),
    tokenStore: tokenStore,
    discoveryClient: DefaultDiscoveryClient(),
    tokenExchange: TokenExchange(timeout: cfg.tokenTimeout),
    apiProxy: ApiProxy(),
    refreshLock: RefreshLock(),
    clock: testClock.now,
  );

  final runtime = AuthRuntimeImpl(
    config: cfg,
    worker: worker,
    oauthFlow: fake,
    nativeProviders: nativeProviders,
  );
  await runtime.init();

  return IntegrationHarness(
    runtime: runtime,
    worker: worker,
    mock: m,
    fakeOAuth: fake,
    clock: testClock,
    tokenStore: tokenStore,
    sessionKv: sKv,
    rootKv: rKv,
    config: cfg,
  );
}

String? _tryGetBaseUrl(MockIdp m) {
  try {
    return m.baseUrl;
  } catch (_) {
    return null;
  }
}
