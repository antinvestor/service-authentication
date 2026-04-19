import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:antinvestor_auth_runtime/src/auth_runtime.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/credentials/credential_event.dart';
import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';
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
    List<NativeCredentialProvider> nativeProviders = const [],
    Random? random,
  })  : _nativeProviders = List<NativeCredentialProvider>.unmodifiable(
          nativeProviders,
        ),
        _random = random ?? Random.secure(),
        _credentialController =
            StreamController<CredentialEvent>.broadcast() {
    if (_nativeProviders.isNotEmpty) {
      _authStateSub = worker.authStateStream.listen(_onAuthStateChanged);
    }
  }

  final ResolvedConfig config;
  final TokenWorker worker;
  final OAuthFlow oauthFlow;
  final List<NativeCredentialProvider> _nativeProviders;
  final Random _random;
  final StreamController<CredentialEvent> _credentialController;

  bool _disposed = false;
  bool _proactiveSilentScheduled = false;
  bool _proactiveSilentAttempted = false;
  Future<void>? _initFuture;
  Future<void>? _inflightEnsureAuthenticated;
  StreamSubscription<AuthState>? _authStateSub;

  /// Kicks off the worker's initial reload. Idempotent: every caller
  /// awaits the same future so first-use races settle correctly.
  Future<void> init() => _initFuture ??= _runInit();

  Future<void> _runInit() async {
    // Probe providers in parallel before the worker settles so callers
    // subscribing to [credentialEventStream] receive availability hints
    // without blocking the main init path.
    unawaited(_probeProviders());
    await worker.init();
  }

  Future<void> _probeProviders() async {
    for (final p in _nativeProviders) {
      try {
        final avail = await p.isAvailable();
        _emitCredentialEvent(CredentialEvent.probe(
          kind: p.kind,
          available: avail,
        ));
      } catch (_) {
        _emitCredentialEvent(CredentialEvent.probe(
          kind: p.kind,
          available: false,
        ));
      }
    }
  }

  void _onAuthStateChanged(AuthState next) {
    if (next != AuthState.unauthenticated) return;
    if (_proactiveSilentAttempted) return;
    if (_proactiveSilentScheduled) return;
    _proactiveSilentScheduled = true;
    scheduleMicrotask(_proactiveSilentAttempt);
  }

  Future<void> _proactiveSilentAttempt() async {
    // Mark as attempted before running so a synchronous failure that
    // bounces state back to unauthenticated doesn't re-enter.
    _proactiveSilentAttempted = true;
    try {
      for (final p in _nativeProviders) {
        if (_disposed) return;
        if (worker.state == AuthState.authenticated) return;
        bool available;
        try {
          available = await p.isAvailable();
        } catch (_) {
          available = false;
        }
        if (!available) continue;

        final nonce = generateNonce();
        _emitCredentialEvent(CredentialEvent.silentAttempt(p.kind));
        NativeCredentialOutcome outcome;
        try {
          outcome = await p.attemptSilent(nonce: nonce);
        } catch (_) {
          outcome = const NativeCredentialOutcome.noSession();
        }
        _emitCredentialEvent(CredentialEvent.outcome(p.kind, outcome));

        if (outcome is Ok) {
          try {
            await worker.completeNativeCredential(
              credential: outcome.result,
              expectedNonce: nonce,
            );
            return;
          } catch (_) {
            // Fall through to next provider.
          }
        }
      }
    } finally {
      _proactiveSilentScheduled = false;
    }
  }

  void _emitCredentialEvent(CredentialEvent event) {
    if (!_credentialController.isClosed) {
      _credentialController.add(event);
    }
  }

  /// Generates a 16-byte cryptographically random nonce, base64url-encoded
  /// without padding. Seeded from [Random.secure] unless overridden at
  /// construction — tests inject a deterministic [Random].
  String generateNonce() {
    final bytes = List<int>.generate(16, (_) => _random.nextInt(256));
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  @override
  Future<void> ensureAuthenticated() async {
    _ensureAlive();
    await init();
    if (worker.state == AuthState.authenticated) return;

    // Collapse concurrent callers onto a single OAuth flow so two
    // simultaneous "ensure" calls don't open two browsers.
    final inflight = _inflightEnsureAuthenticated;
    if (inflight != null) return inflight;

    final future = _runWaterfall();
    _inflightEnsureAuthenticated = future;
    try {
      await future;
    } finally {
      _inflightEnsureAuthenticated = null;
    }
  }

  /// Native → OAuth2 waterfall.
  ///
  /// For each configured [NativeCredentialProvider], attempts an
  /// interactive sign-in; on `ok` exchanges the ID token via
  /// [TokenWorker.completeNativeCredential]. All other outcomes (cancel,
  /// noSession, unavailable, error) move on to the next provider. When
  /// every native provider has been exhausted, falls through to the
  /// existing OAuth2 popup path.
  Future<void> _runWaterfall() async {
    for (final p in _nativeProviders) {
      if (worker.state == AuthState.authenticated) return;
      bool available;
      try {
        available = await p.isAvailable();
      } catch (_) {
        available = false;
      }
      if (!available) continue;

      final nonce = generateNonce();
      _emitCredentialEvent(CredentialEvent.interactiveAttempt(p.kind));
      NativeCredentialOutcome outcome;
      try {
        outcome = await p.attemptInteractive(nonce: nonce);
      } catch (_) {
        // Provider threw unexpectedly — treat as unavailable and move on.
        outcome = const NativeCredentialOutcome.unavailable(
          'provider threw unexpectedly',
        );
      }
      _emitCredentialEvent(CredentialEvent.outcome(p.kind, outcome));

      if (outcome is Ok) {
        try {
          await worker.completeNativeCredential(
            credential: outcome.result,
            expectedNonce: nonce,
          );
          return;
        } catch (_) {
          // Exchange failed — fall through to the next provider / OAuth2.
        }
      }
      // Cancelled / NoSession / Unavailable / ErrorOutcome → fall through.
    }

    await _startOAuthFlow();
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
    // Best-effort native sign-out first so the provider's session is
    // cleared even if the subsequent local wipe fails. Errors from any
    // single provider never block the remainder.
    for (final p in _nativeProviders) {
      try {
        await p.signOut();
      } catch (_) {
        // Best-effort only.
      }
      _emitCredentialEvent(CredentialEvent.signOut(p.kind));
    }
    await worker.logout();
  }

  @override
  Future<Set<NativeCredentialProviderKind>> availableNativeProviders() async {
    _ensureAlive();
    final out = <NativeCredentialProviderKind>{};
    for (final p in _nativeProviders) {
      try {
        if (await p.isAvailable()) out.add(p.kind);
      } catch (_) {
        // Skip providers that error out during probe.
      }
    }
    return out;
  }

  @override
  Stream<CredentialEvent> get credentialEventStream =>
      _credentialController.stream;

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
    await _authStateSub?.cancel();
    _authStateSub = null;
    await _credentialController.close();
    await worker.destroy();
  }

  void _ensureAlive() {
    if (_disposed) {
      throw StateError('AuthRuntime has been disposed');
    }
  }
}

