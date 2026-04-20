import 'dart:async';

import 'package:antinvestor_auth_runtime/src/auth_runtime.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/models/api_response.dart';
import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:antinvestor_auth_runtime/src/models/security_event.dart';
import 'package:antinvestor_auth_runtime/src/oauth/oauth_flow.dart';
import 'package:antinvestor_auth_runtime/src/worker/token_worker.dart';

/// Main-thread [AuthRuntime] — the default `createAuthRuntime` shape.
///
/// Holds a single [TokenWorker] in-process and an [OAuthFlow] that
/// drives the browser leg via `flutter_appauth`. A later task wraps the
/// same public API around an Isolate-backed worker for defense-in-depth
/// token isolation; both implementations share the same public
/// [AuthRuntime] contract so consumers can switch via
/// `createAuthRuntime(..., useIsolate: true)` without touching their
/// widget tree.
///
/// Lifecycle:
///
/// 1. Construction calls [TokenWorker.init] eagerly so the `authStateStream`
///    emits a first transition immediately.
/// 2. [ensureAuthenticated] is a no-op when already authenticated, drives
///    OAuth otherwise.
/// 3. [dispose] closes streams and releases the worker. Safe to call
///    multiple times.
class AuthRuntimeImpl implements AuthRuntime {
  AuthRuntimeImpl({
    required this.config,
    required this.worker,
    required this.oauthFlow,
  });

  final ResolvedConfig config;
  final TokenWorker worker;
  final OAuthFlow oauthFlow;

  bool _disposed = false;
  Future<void>? _initFuture;
  Future<void>? _inflightEnsureAuthenticated;

  /// Kicks off the worker's initial reload. Idempotent: every caller
  /// awaits the same future so first-use races settle correctly.
  Future<void> init() => _initFuture ??= worker.init();

  @override
  Future<void> ensureAuthenticated() async {
    _ensureAlive();
    await init();
    if (worker.state == AuthState.authenticated) return;

    // Collapse concurrent callers onto a single OAuth flow so two
    // simultaneous "ensure" calls don't open two browsers.
    final inflight = _inflightEnsureAuthenticated;
    if (inflight != null) return inflight;

    final future = _startOAuthFlow();
    _inflightEnsureAuthenticated = future;
    try {
      await future;
    } finally {
      _inflightEnsureAuthenticated = null;
    }
  }

  Future<void> _startOAuthFlow() async {
    final prepared = await worker.prepareAuth();
    final result = await oauthFlow.authorize(config);
    await worker.completeAuth(
      code: result.code,
      verifier: result.verifier,
      state: result.state ?? prepared.state,
      nonce: result.nonce ?? prepared.nonce,
      expectedState: result.state ?? prepared.state,
    );
  }

  @override
  Future<ApiResponse> fetch(
    String path, {
    String method = 'GET',
    Map<String, String>? headers,
    Object? body,
    Duration? timeout,
  }) {
    _ensureAlive();
    return worker.fetch(
      path: path,
      method: method,
      headers: headers,
      body: body,
      timeout: timeout,
    );
  }

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
  }) {
    _ensureAlive();
    return worker.upload(
      path: path,
      fieldName: fieldName,
      filename: filename,
      contentType: contentType,
      bytes: bytes,
      length: length,
      headers: headers,
      timeout: timeout,
    );
  }

  @override
  Future<Map<String, dynamic>> getClaims() async {
    _ensureAlive();
    if (worker.state != AuthState.authenticated) {
      return const <String, dynamic>{};
    }
    return worker.getClaims();
  }

  @override
  Future<List<String>> getRoles() async {
    _ensureAlive();
    if (worker.state != AuthState.authenticated) return const <String>[];
    return worker.getRoles();
  }

  @override
  Future<void> logout() async {
    _ensureAlive();
    await worker.logout();
  }

  @override
  Stream<AuthState> get authStateStream => worker.authStateStream;

  @override
  Stream<SecurityEvent> get securityEventStream =>
      worker.securityEventStream;

  @override
  AuthState get state => worker.state;

  @override
  Future<void> prefetchDiscovery() async {
    _ensureAlive();
    // Piggyback on the worker's discovery client — result is cached at
    // the module level so subsequent calls reuse it for free.
    await worker.discoveryClient.getDiscovery(
      config.idpBaseUrl,
      config.discoveryTimeout,
    );
  }

  @override
  String get version => authRuntimeVersion;

  @override
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    await worker.destroy();
  }

  void _ensureAlive() {
    if (_disposed) {
      throw StateError('AuthRuntime has been disposed');
    }
  }
}

