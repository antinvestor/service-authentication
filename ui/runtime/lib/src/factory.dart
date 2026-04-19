import 'dart:async';

import 'package:antinvestor_auth_runtime/src/auth_runtime.dart';
import 'package:antinvestor_auth_runtime/src/auth_runtime_impl.dart';
import 'package:antinvestor_auth_runtime/src/config/auth_config.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/crypto/default_key_manager.dart';
import 'package:antinvestor_auth_runtime/src/crypto/key_manager.dart';
import 'package:antinvestor_auth_runtime/src/crypto/root_key_store.dart';
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
  if (useIsolate) {
    // F-G.2 introduces `IsolatedTokenWorkerProxy`; until then we refuse
    // loudly so callers don't get silently downgraded.
    throw UnsupportedError(
      'useIsolate=true is not yet wired — see plan task F-G.2',
    );
  }
  final resolved = resolveConfig(config);

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

