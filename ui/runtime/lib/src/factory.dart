import 'dart:async';

import 'package:antinvestor_auth_runtime/src/auth_runtime.dart';
import 'package:antinvestor_auth_runtime/src/auth_runtime_impl.dart';
import 'package:antinvestor_auth_runtime/src/config/auth_config.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/crypto/default_key_manager.dart';
import 'package:antinvestor_auth_runtime/src/crypto/key_manager.dart';
import 'package:antinvestor_auth_runtime/src/crypto/root_key_store.dart';
import 'package:antinvestor_auth_runtime/src/isolated_auth_runtime.dart';
import 'package:antinvestor_auth_runtime/src/models/api_response.dart';
import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:antinvestor_auth_runtime/src/models/security_event.dart';
import 'package:antinvestor_auth_runtime/src/oauth/oauth_flow.dart';
import 'package:antinvestor_auth_runtime/src/protocol/api_proxy.dart';
import 'package:antinvestor_auth_runtime/src/protocol/token_exchange.dart';
import 'package:antinvestor_auth_runtime/src/runtime/refresh_lock.dart';
import 'package:antinvestor_auth_runtime/src/storage/secure_token_store.dart';
import 'package:antinvestor_auth_runtime/src/storage/token_store.dart';
import 'package:antinvestor_auth_runtime/src/worker/token_worker.dart';

/// Builds a production [AuthRuntime] wired against `flutter_secure_storage`
/// (via [SecureStorageKeyValueStore]) and the default HTTP + crypto
/// stacks.
///
/// The factory is the single public entry point — callers should never
/// construct [AuthRuntimeImpl] directly so future rearchitecture (e.g.
/// swapping to an isolate-backed worker) is opaque to consumers.
///
/// All collaborators are overridable so tests can inject
/// `InMemoryKeyValueStore`, a `MockClient`, or a stubbed [OAuthFlow]
/// without pulling in platform channels.
///
/// `useIsolate` is reserved for F-G.2 — today it must be `false`. When
/// the isolate variant lands the factory starts honouring it.
AuthRuntime createAuthRuntime(
  AuthConfig config, {
  bool useIsolate = false,
  KeyManager? keyManager,
  RootKeyStore? rootKeyStore,
  TokenStore? tokenStore,
  KeyValueStore? sessionKv,
  KeyValueStore? rootKv,
  DiscoveryClient? discoveryClient,
  TokenExchange? tokenExchange,
  ApiProxy? apiProxy,
  RefreshLock? refreshLock,
  OAuthFlow? oauthFlow,
  Clock? clock,
}) {
  final resolved = resolveConfig(config);
  if (useIsolate) {
    // v0.1 ships the isolate path in scaffolding form: lifecycle works
    // end-to-end, data-plane methods throw `UnimplementedError` until the
    // F-J integration pass wires the full transport. Callers who need
    // production-grade access today should stick with the default
    // in-thread runtime.
    //
    // The spawn is fire-and-forget here: `createAuthRuntime` stays
    // synchronous (matching the in-thread path), and the returned shell
    // routes all method calls through a `proxy` that awaits spawn
    // completion transparently via its own `init()`.
    return _LazyIsolatedAuthRuntime(resolved);
  }

  final km = keyManager ?? DefaultKeyManager();
  final rootStore = rootKeyStore ??
      DefaultRootKeyStore(kv: rootKv ?? SecureStorageKeyValueStore());
  final store = tokenStore ??
      SecureTokenStore(kv: sessionKv ?? SecureStorageKeyValueStore());
  final discovery = discoveryClient ?? DefaultDiscoveryClient();
  final exchange = tokenExchange ??
      TokenExchange(timeout: resolved.tokenTimeout);
  final proxy = apiProxy ?? ApiProxy();
  final lock = refreshLock ?? RefreshLock();
  final flow = oauthFlow ?? OAuthFlow();

  final worker = TokenWorker(
    config: resolved,
    keyManager: km,
    rootKeyStore: rootStore,
    tokenStore: store,
    discoveryClient: discovery,
    tokenExchange: exchange,
    apiProxy: proxy,
    refreshLock: lock,
    clock: clock ?? DateTime.now,
  );

  final runtime = AuthRuntimeImpl(
    config: resolved,
    worker: worker,
    oauthFlow: flow,
  );
  // Kick off session reload immediately so apps subscribing to
  // `authStateStream` don't miss the first transition while they're
  // still wiring up.
  unawaited(runtime.init());
  return runtime;
}

/// Async-only variant for callers who can await spawn completion. The
/// returned runtime has its isolate already alive and its lifecycle
/// bootstrapped — useful for tests that want to observe errors during
/// spawn eagerly.
Future<AuthRuntime> createIsolatedAuthRuntime(
  AuthConfig config, {
  Duration readyTimeout = const Duration(seconds: 5),
}) async {
  final resolved = resolveConfig(config);
  return spawnIsolatedAuthRuntime(resolved, readyTimeout: readyTimeout);
}

/// Thin shell that collapses async spawning behind a sync factory.
///
/// Every public method awaits [_ready] before delegating. The isolate is
/// spawned exactly once at construction. [authStateStream] and
/// [securityEventStream] use buffered controllers so early subscribers
/// don't miss events that the spawned runtime emits before they attach.
class _LazyIsolatedAuthRuntime implements AuthRuntime {
  _LazyIsolatedAuthRuntime(this.config) {
    _ready = _spawn();
  }

  final ResolvedConfig config;
  late final Future<IsolatedAuthRuntime> _ready;
  bool _disposed = false;

  Future<IsolatedAuthRuntime> _spawn() =>
      spawnIsolatedAuthRuntime(config);

  @override
  Future<void> ensureAuthenticated() async =>
      (await _ready).ensureAuthenticated();

  @override
  Future<ApiResponse> fetch(
    String path, {
    String method = 'GET',
    Map<String, String>? headers,
    Object? body,
    Duration? timeout,
  }) async =>
      (await _ready).fetch(path,
          method: method, headers: headers, body: body, timeout: timeout);

  @override
  Future<ApiResponse> upload(
    String path, {
    required String fieldName,
    required String filename,
    required String contentType,
    required Stream<List<int>> bytes,
    required int length,
    Map<String, String>? headers,
    Duration? timeout,
  }) async =>
      (await _ready).upload(
        path,
        fieldName: fieldName,
        filename: filename,
        contentType: contentType,
        bytes: bytes,
        length: length,
        headers: headers,
        timeout: timeout,
      );

  @override
  Future<Map<String, dynamic>> getClaims() async =>
      (await _ready).getClaims();

  @override
  Future<List<String>> getRoles() async => (await _ready).getRoles();

  @override
  Future<void> logout() async => (await _ready).logout();

  @override
  Stream<AuthState> get authStateStream async* {
    final rt = await _ready;
    yield* rt.authStateStream;
  }

  @override
  Stream<SecurityEvent> get securityEventStream async* {
    final rt = await _ready;
    yield* rt.securityEventStream;
  }

  @override
  AuthState get state => AuthState.initializing;

  @override
  Future<void> prefetchDiscovery() async =>
      (await _ready).prefetchDiscovery();

  @override
  String get version => authRuntimeVersion;

  @override
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    final rt = await _ready;
    await rt.dispose();
  }
}

