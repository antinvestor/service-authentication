import 'dart:async';

import 'package:antinvestor_auth_runtime/src/auth_runtime.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/credentials/credential_event.dart';
import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/models/api_response.dart';
import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:antinvestor_auth_runtime/src/models/security_event.dart';
import 'package:antinvestor_auth_runtime/src/models/user_claims.dart';
import 'package:antinvestor_auth_runtime/src/worker/messages.dart';
import 'package:antinvestor_auth_runtime/src/worker/token_isolate.dart';

/// Shell [AuthRuntime] that routes to an [IsolatedTokenWorkerProxy].
///
/// v0.1 wires only the lifecycle surface (init, destroy, state/security
/// streams). The data-plane methods (`fetch`, `upload`, `logout`, …)
/// throw `UnimplementedError` until F-J wires real HTTP + DPoP transports
/// across the isolate boundary. Consumers who depend on those methods
/// should stick with the default in-thread runtime via
/// `createAuthRuntime(..., useIsolate: false)`.
///
/// The state + security streams are wired from correlated / broadcast
/// events emitted by the isolate entry point. The default scaffolding
/// entry point only emits a [ReadyEvent] at start-up — but the transport
/// is ready to carry real state changes once a richer worker ships.
class IsolatedAuthRuntime implements AuthRuntime {
  IsolatedAuthRuntime({
    required this.config,
    required this.proxy,
  })  : _stateController = StreamController<AuthState>.broadcast(),
        _securityController = StreamController<SecurityEvent>.broadcast() {
    _eventSubscription = proxy.events.listen(_onEvent);
  }

  final ResolvedConfig config;
  final IsolatedTokenWorkerProxy proxy;

  final StreamController<AuthState> _stateController;
  final StreamController<SecurityEvent> _securityController;
  late final StreamSubscription<WorkerEvent> _eventSubscription;

  AuthState _state = AuthState.initializing;
  bool _disposed = false;
  bool _initialised = false;

  void _onEvent(WorkerEvent ev) {
    if (ev is StateEvent) {
      _state = ev.state;
      if (!_stateController.isClosed) _stateController.add(ev.state);
      return;
    }
    if (ev is SecurityEventWire) {
      if (!_securityController.isClosed) {
        _securityController.add(ev.event);
      }
    }
  }

  Future<void> _ensureInit() async {
    if (_initialised) return;
    _initialised = true;
    await proxy.init();
  }

  @override
  Future<void> ensureAuthenticated() async {
    _ensureAlive();
    await _ensureInit();
    // Full OAuth over the isolate boundary requires F-J's integration
    // transport (platform plugin round-trips don't survive SendPort).
    throw UnimplementedError(
      'ensureAuthenticated via isolate is scheduled for F-J; '
      'use createAuthRuntime(useIsolate: false) in v0.1',
    );
  }

  @override
  Future<ApiResponse> fetch(
    String path, {
    String method = 'GET',
    Map<String, String>? headers,
    Object? body,
    Duration? timeout,
  }) async {
    _ensureAlive();
    throw UnimplementedError(
      'fetch via isolate is scheduled for F-J',
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
  }) async {
    _ensureAlive();
    throw UnimplementedError(
      'upload via isolate is scheduled for F-J',
    );
  }

  @override
  Future<Map<String, dynamic>> getClaims() async {
    _ensureAlive();
    return const <String, dynamic>{};
  }

  @override
  Future<UserClaims> getUserClaims() async {
    _ensureAlive();
    return const UserClaims(<String, dynamic>{});
  }

  @override
  Future<List<String>> getRoles() async {
    _ensureAlive();
    return const <String>[];
  }

  @override
  Future<void> logout() async {
    _ensureAlive();
    throw UnimplementedError(
      'logout via isolate is scheduled for F-J',
    );
  }

  @override
  Stream<AuthState> get authStateStream => _stateController.stream;

  @override
  Stream<SecurityEvent> get securityEventStream =>
      _securityController.stream;

  @override
  AuthState get state => _state;

  @override
  Future<Set<NativeCredentialProviderKind>> availableNativeProviders() async {
    _ensureAlive();
    // Native credential providers run main-isolate-only in v0.2; isolate
    // shell reports an empty set.
    return const <NativeCredentialProviderKind>{};
  }

  @override
  Stream<CredentialEvent> get credentialEventStream =>
      const Stream<CredentialEvent>.empty();

  @override
  Future<void> prefetchDiscovery() async {
    _ensureAlive();
    // No-op for the isolate shell: discovery is owned by the worker, and
    // the scaffolding worker has no real HTTP client.
  }

  @override
  String get version => authRuntimeVersion;

  @override
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    await _eventSubscription.cancel();
    await proxy.destroy();
    await _stateController.close();
    await _securityController.close();
  }

  void _ensureAlive() {
    if (_disposed) {
      throw StateError('AuthRuntime has been disposed');
    }
  }
}

/// Spawns the default scaffolding isolate and wraps it in an
/// [IsolatedAuthRuntime]. Exposed as the factory hook `useIsolate: true`
/// routes through.
Future<IsolatedAuthRuntime> spawnIsolatedAuthRuntime(
  ResolvedConfig config, {
  Duration readyTimeout = const Duration(seconds: 5),
  void Function(dynamic)? entryPoint,
}) async {
  final handle = await TokenIsolateHandle.spawn(
    readyTimeout: readyTimeout,
    entryPoint: entryPoint == null
        ? null
        : (send) => entryPoint(send),
  );
  final proxy = IsolatedTokenWorkerProxy(handle);
  // Propagate isolate-side errors as AuthError for caller ergonomics.
  // ignore: avoid_catching_errors
  try {
    return IsolatedAuthRuntime(config: config, proxy: proxy);
  } catch (err) {
    await proxy.destroy();
    throw AuthError(
      AuthErrorCode.cryptoUnsupported,
      'failed to construct IsolatedAuthRuntime',
      cause: err,
    );
  }
}
