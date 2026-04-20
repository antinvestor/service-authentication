import 'dart:async';

import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';

/// Controllable [AuthRuntime] for widget + provider tests.
///
/// Streams and return values are driven via plain fields / controllers so
/// tests can push arbitrary sequences of [AuthState] transitions and
/// [SecurityEvent]s without spinning up OAuth or HTTP. Method call
/// counters make it easy to assert that the widget layer plumbed user
/// interactions through to the runtime.
class FakeAuthRuntime implements AuthRuntime {
  FakeAuthRuntime({
    AuthState initialState = AuthState.unauthenticated,
    Map<String, dynamic>? claims,
    List<String>? roles,
  })  : _state = initialState,
        _claims = claims ?? const <String, dynamic>{},
        _roles = roles ?? const <String>[];

  final StreamController<AuthState> _stateCtl =
      StreamController<AuthState>.broadcast();
  final StreamController<SecurityEvent> _secCtl =
      StreamController<SecurityEvent>.broadcast();
  final StreamController<CredentialEvent> _credCtl =
      StreamController<CredentialEvent>.broadcast();

  Set<NativeCredentialProviderKind> availableProviders =
      const <NativeCredentialProviderKind>{};

  AuthState _state;
  Map<String, dynamic> _claims;
  List<String> _roles;
  bool _disposed = false;

  int ensureAuthenticatedCalls = 0;
  int logoutCalls = 0;
  int fetchCalls = 0;
  int uploadCalls = 0;
  int prefetchCalls = 0;

  /// When set, [ensureAuthenticated] throws it instead of transitioning.
  Object? ensureAuthenticatedError;

  @override
  AuthState get state => _state;

  @override
  Stream<AuthState> get authStateStream => _stateCtl.stream;

  @override
  Stream<SecurityEvent> get securityEventStream => _secCtl.stream;

  @override
  Future<Set<NativeCredentialProviderKind>> availableNativeProviders() async =>
      availableProviders;

  @override
  Stream<CredentialEvent> get credentialEventStream => _credCtl.stream;

  @override
  String get version => authRuntimeVersion;

  /// Drive an [AuthState] transition into the stream and update [state].
  void emitState(AuthState s) {
    _state = s;
    _stateCtl.add(s);
  }

  /// Emit a [SecurityEvent] to subscribers.
  void emitSecurityEvent(SecurityEvent event) {
    _secCtl.add(event);
  }

  /// Swap the claims returned by [getClaims].
  set claims(Map<String, dynamic> next) => _claims = next;

  /// Swap the roles returned by [getRoles].
  set roles(List<String> next) => _roles = next;

  @override
  Future<void> ensureAuthenticated() async {
    ensureAuthenticatedCalls++;
    final err = ensureAuthenticatedError;
    if (err != null) throw err;
    emitState(AuthState.authenticated);
  }

  @override
  Future<ApiResponse> fetch(
    String path, {
    String method = 'GET',
    Map<String, String>? headers,
    Object? body,
    Duration? timeout,
  }) async {
    fetchCalls++;
    throw UnimplementedError('fetch not stubbed in FakeAuthRuntime');
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
    uploadCalls++;
    throw UnimplementedError('upload not stubbed in FakeAuthRuntime');
  }

  @override
  Future<Map<String, dynamic>> getClaims() async => _claims;

  @override
  Future<UserClaims> getUserClaims() async => UserClaims(_claims);

  @override
  Future<List<String>> getRoles() async => _roles;

  @override
  Future<void> logout() async {
    logoutCalls++;
    emitState(AuthState.unauthenticated);
  }

  @override
  Future<void> prefetchDiscovery() async {
    prefetchCalls++;
  }

  @override
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    await _stateCtl.close();
    await _secCtl.close();
    await _credCtl.close();
  }
}
