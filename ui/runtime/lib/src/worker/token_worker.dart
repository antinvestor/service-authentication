import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/crypto/key_manager.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/models/api_response.dart';
import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:antinvestor_auth_runtime/src/models/security_event.dart';
import 'package:antinvestor_auth_runtime/src/models/token_set.dart';
import 'package:antinvestor_auth_runtime/src/models/user_claims.dart';
import 'package:antinvestor_auth_runtime/src/protocol/api_proxy.dart';
import 'package:antinvestor_auth_runtime/src/protocol/discovery.dart';
import 'package:antinvestor_auth_runtime/src/protocol/dpop.dart';
import 'package:antinvestor_auth_runtime/src/protocol/jwt.dart';
import 'package:antinvestor_auth_runtime/src/protocol/pkce.dart';
import 'package:antinvestor_auth_runtime/src/protocol/token_exchange.dart';
import 'package:antinvestor_auth_runtime/src/runtime/refresh_lock.dart';
import 'package:antinvestor_auth_runtime/src/runtime/state_machine.dart';
import 'package:antinvestor_auth_runtime/src/storage/token_store.dart';
import 'package:http/http.dart' as http;

/// Signature for the injected clock. Default is [DateTime.now].
typedef Clock = DateTime Function();

/// Wraps [getDiscovery] behind an interface so tests can stub the
/// discovery document without exercising the module-level cache.
abstract class DiscoveryClient {
  Future<OidcDiscovery> getDiscovery(
    String idpBaseUrl,
    Duration timeout,
  );
}

/// Production [DiscoveryClient] that delegates to the real
/// [getDiscovery] function. An optional [http.Client] hook is provided
/// so integration tests can inject a [MockClient].
class DefaultDiscoveryClient implements DiscoveryClient {
  DefaultDiscoveryClient({http.Client? client}) : _client = client;

  final http.Client? _client;

  @override
  Future<OidcDiscovery> getDiscovery(String idpBaseUrl, Duration timeout) =>
      // ignore: invalid_use_of_internal_member
      // `getDiscovery` is a top-level function in protocol/discovery.dart.
      _fetch(idpBaseUrl, timeout);

  Future<OidcDiscovery> _fetch(String url, Duration t) {
    return (_client == null)
        ? getDiscoveryCompat(url, t)
        : getDiscoveryCompat(url, t, client: _client);
  }
}

/// Thin alias so the (top-level) function name doesn't collide with the
/// `DiscoveryClient.getDiscovery` method.
Future<OidcDiscovery> getDiscoveryCompat(
  String idpBaseUrl,
  Duration timeout, {
  http.Client? client,
}) =>
    getDiscovery(idpBaseUrl, timeout, client: client);

/// Pure, testable core of the token worker.
///
/// Owns the session state-machine, refresh serialisation, crypto, storage
/// and API proxy. All dependencies are injected via constructor so every
/// edge can be stubbed in a unit test. Not yet bound to an Isolate — the
/// Isolate harness is added in F-E.3.
class TokenWorker implements TokenProvider {
  TokenWorker({
    required this.config,
    required this.keyManager,
    required this.tokenStore,
    required this.discoveryClient,
    required this.tokenExchange,
    required this.apiProxy,
    required this.refreshLock,
    this.clock = _defaultClock,
    this.accessTokenRefreshBuffer = const Duration(seconds: 60),
  })  : _stateController = StreamController<AuthState>.broadcast(),
        _securityController =
            StreamController<SecurityEvent>.broadcast();

  final ResolvedConfig config;
  final KeyManager keyManager;
  final TokenStore tokenStore;
  final DiscoveryClient discoveryClient;
  final TokenExchange tokenExchange;
  final ApiProxy apiProxy;
  final RefreshLock refreshLock;
  final Clock clock;

  /// How close to [TokenSet.expiresAt] we proactively refresh. Set to 60s
  /// to cover typical 2xx latency + any clock skew within our tolerance.
  final Duration accessTokenRefreshBuffer;

  final StreamController<AuthState> _stateController;
  final StreamController<SecurityEvent> _securityController;

  AuthState _state = AuthState.initializing;
  TokenSet? _tokens;
  DpopContext? _dpop;
  WrapKey? _wrapKey;
  bool _destroyed = false;

  Stream<AuthState> get authStateStream => _stateController.stream;
  Stream<SecurityEvent> get securityEventStream => _securityController.stream;
  AuthState get state => _state;

  /// Initializes the worker: loads and decrypts any stored session, then
  /// settles into `authenticated` or `unauthenticated`. Safe to call
  /// once per instance.
  Future<void> init() async {
    _ensureAlive();
    try {
      final stored = await tokenStore.load(config.namespace);
      if (stored == null) {
        _transition(const StateInput.initDone(hasTokens: false));
        return;
      }
      // Storage is present but the DPoP/wrap layer is stubbed for a
      // later task. Without the ability to decrypt the wrap key, treat
      // this as an empty session rather than failing hard.
      // TODO(F-E.3 hardening): decrypt wrapKeyEncrypted + dpopKeyEncrypted
      //   via hardware-backed keystore and unwrap the refresh token.
      //   Until that lands, initializing from persisted storage lands in
      //   `unauthenticated` so the worker falls back to a fresh sign-in.
      _transition(const StateInput.initDone(hasTokens: false));
    } catch (err) {
      // Corrupt storage: wipe + fall through to unauthenticated.
      await tokenStore.clear(config.namespace);
      _emitSecurity(SecurityEvent.storageCorruption(clock()));
      _transition(const StateInput.initDone(hasTokens: false));
    }
  }

  /// Builds a PKCE/state/nonce triple and the authorization URL the UI
  /// layer should open in a browser. Returns an opaque [AuthorizeRequest]
  /// bundle so callers pass the same `verifier` back into [completeAuth].
  Future<AuthorizeRequest> prepareAuth() async {
    _ensureAlive();
    final pkce = await generatePkcePair();
    final state = _b64urlNoPad(randomBytes(16));
    final nonce = _b64urlNoPad(randomBytes(16));

    final discovery = await discoveryClient.getDiscovery(
      config.idpBaseUrl,
      config.discoveryTimeout,
    );
    final params = <String, String>{
      'response_type': 'code',
      'client_id': config.clientId,
      'redirect_uri': config.redirectUri,
      'scope': config.scopes.join(' '),
      'code_challenge': pkce.challenge,
      'code_challenge_method': 'S256',
      'state': state,
      'nonce': nonce,
    };
    final sep = discovery.authorizationEndpoint.contains('?') ? '&' : '?';
    final qs = params.entries
        .map((e) =>
            '${Uri.encodeQueryComponent(e.key)}=${Uri.encodeQueryComponent(e.value)}')
        .join('&');
    final url = '${discovery.authorizationEndpoint}$sep$qs';

    return AuthorizeRequest(
      url: url,
      verifier: pkce.verifier,
      state: state,
      nonce: nonce,
    );
  }

  /// Exchanges an OAuth [code] for tokens and persists the session.
  ///
  /// The [state] returned by the OAuth callback must match what
  /// [prepareAuth] issued. [nonce] is recorded for a future id-token
  /// check (skipped in this revision — see the plan).
  Future<void> completeAuth({
    required String code,
    required String verifier,
    required String state,
    required String nonce,
    required String expectedState,
  }) async {
    _ensureAlive();
    if (state != expectedState) {
      throw AuthError(
        AuthErrorCode.oauthFailed,
        'OAuth state mismatch',
      );
    }

    // Build (or reuse) the DPoP context used for the exchange.
    final ctx = await _ensureDpop();
    // A completeAuth call implies the UI has already driven the
    // browser leg, so transition through `initializing` to satisfy the
    // spec §8 path `unauthenticated -> initializing -> authenticated`.
    _transition(const StateInput.signInStart());
    try {
      final tokens = await tokenExchange.exchangeCode(
        config,
        ctx,
        code: code,
        verifier: verifier,
      );
      _tokens = tokens;

      await _persistSession(tokens);
      _transition(const StateInput.signInDone());
    } catch (err) {
      final ae = err is AuthError
          ? err
          : AuthError(AuthErrorCode.tokenExchangeFailed, 'sign-in failed',
              cause: err);
      _transition(StateInput.signInFail(ae));
      rethrow;
    }
  }

  /// Returns a fresh access token snapshot, triggering a refresh when the
  /// current token is absent, near-expiry, or [force] is true.
  @override
  Future<TokenSnapshot> ensureFresh({bool force = false}) async {
    _ensureAlive();
    final current = _tokens;
    if (current == null) {
      throw AuthError(AuthErrorCode.tokenExpired, 'no session');
    }
    final now = clock();
    final needs =
        force || !now.isBefore(current.expiresAt.subtract(accessTokenRefreshBuffer));
    if (!needs) {
      return TokenSnapshot(
        accessToken: current.accessToken,
        tokenType: current.tokenType,
      );
    }
    await refreshLock.withLock<void>(config.namespace, () async {
      // Re-check under the lock: another task might have refreshed while
      // we were waiting for acquisition.
      final snap = _tokens;
      if (snap != null &&
          !force &&
          now.isBefore(snap.expiresAt.subtract(accessTokenRefreshBuffer))) {
        return;
      }
      await _doRefreshLocked();
    });
    final after = _tokens;
    if (after == null) {
      throw AuthError(
        AuthErrorCode.tokenRefreshFailed,
        'refresh did not produce a token',
      );
    }
    return TokenSnapshot(
      accessToken: after.accessToken,
      tokenType: after.tokenType,
    );
  }

  @override
  void onRefresh() {
    // Hook — downstream telemetry wires up in a later task.
  }

  /// Authenticated GET/POST/PUT/etc.
  Future<ApiResponse> fetch({
    required String path,
    required String method,
    Map<String, String>? headers,
    Object? body,
    Duration? timeout,
  }) async {
    _ensureAlive();
    final ctx = await _ensureDpop();
    return apiProxy.fetch(
      config,
      ctx,
      this,
      path: path,
      method: method,
      headers: headers,
      body: body,
      timeout: timeout,
    );
  }

  /// Authenticated multipart upload.
  Future<ApiResponse> upload({
    required String path,
    required String fieldName,
    required String filename,
    required String contentType,
    required Stream<List<int>> bytes,
    required int length,
    Map<String, String>? headers,
    Duration? timeout,
  }) async {
    _ensureAlive();
    final ctx = await _ensureDpop();
    return apiProxy.upload(
      config,
      ctx,
      this,
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

  /// Returns the decoded ID-token claims. Returns an empty map when no
  /// ID token is known (e.g. sign-in used scopes without `openid`).
  Future<Map<String, dynamic>> getClaims() async {
    _ensureAlive();
    final t = _tokens;
    final id = t?.idToken;
    if (id == null) return const <String, dynamic>{};
    try {
      return decodeJwtPayload(id);
    } catch (_) {
      return const <String, dynamic>{};
    }
  }

  /// Role list extracted from the access token (Hydra-style).
  Future<List<String>> getRoles() async {
    _ensureAlive();
    final t = _tokens;
    if (t == null) return const <String>[];
    return extractRolesFromToken(t.accessToken);
  }

  /// Best-effort logout: revoke refresh token + hit end_session, then
  /// wipe all local state regardless of network outcome.
  Future<void> logout() async {
    _ensureAlive();
    final t = _tokens;
    OidcDiscovery? discovery;
    try {
      discovery = await discoveryClient.getDiscovery(
        config.idpBaseUrl,
        config.discoveryTimeout,
      );
    } catch (_) {
      discovery = null;
    }

    if (t != null && discovery?.revocationEndpoint != null) {
      try {
        final body = _encodeForm(<String, String>{
          'token': t.refreshToken,
          'token_type_hint': 'refresh_token',
          'client_id': config.clientId,
        });
        await http
            .post(
              Uri.parse(discovery!.revocationEndpoint!),
              headers: const {
                'Content-Type': 'application/x-www-form-urlencoded',
              },
              body: body,
            )
            .timeout(config.tokenTimeout);
      } catch (_) {
        // Best-effort only.
      }
    }

    if (discovery?.endSessionEndpoint != null) {
      try {
        final uri = Uri.parse(discovery!.endSessionEndpoint!);
        await http.get(uri).timeout(config.tokenTimeout);
      } catch (_) {
        // Best-effort only.
      }
    }

    await tokenStore.clear(config.namespace);
    _tokens = null;
    _dpop = null;
    _wrapKey = null;
    _transition(const StateInput.logout());
  }

  /// Stops the worker: closes streams and releases ephemeral state.
  Future<void> destroy() async {
    if (_destroyed) return;
    _destroyed = true;
    _tokens = null;
    _dpop = null;
    _wrapKey = null;
    await _stateController.close();
    await _securityController.close();
  }

  // ---- internal helpers ---------------------------------------------------

  Future<void> _doRefreshLocked() async {
    final refresh = _tokens?.refreshToken;
    if (refresh == null) {
      throw AuthError(AuthErrorCode.tokenExpired, 'no refresh token');
    }
    _transition(const StateInput.refreshStart());
    final ctx = await _ensureDpop();
    final outcome = await tokenExchange.refresh(config, ctx, refresh);
    switch (outcome) {
      case RefreshRotated(:final tokens):
        _tokens = tokens;
        await _persistSession(tokens);
        _transition(const StateInput.refreshDone());
      case RefreshReuseDetectedOutcome():
        await _securityWipe('refresh-reuse');
        throw AuthError(
          AuthErrorCode.refreshReuseDetected,
          'refresh token reuse detected',
        );
      case RefreshNetworkError(:final error):
        _transition(StateInput.refreshFail(error: error, wipe: false));
        throw error;
    }
  }

  Future<void> _persistSession(TokenSet tokens) async {
    final wrapKey = _wrapKey ??= await keyManager.generateWrapKey();
    final dpop = await _ensureDpop();
    final wrappedRt = await keyManager.wrap(
      wrapKey,
      utf8.encode(tokens.refreshToken),
    );
    // NOTE: proper wrapKey / DPoP private-key encryption is wired in a
    // later task (requires a keychain-backed KEK). For now we persist
    // empty placeholders so the schema is forward-compatible without
    // leaking plaintext key material.
    await tokenStore.save(
      config.namespace,
      StoredSession(
        wrappedRefreshToken: wrappedRt,
        dpopKeyEncrypted: Uint8List(0),
        wrapKeyEncrypted: Uint8List(0),
        lastIdToken: tokens.idToken,
        updatedAt: clock(),
      ),
    );
    // Touch `dpop` so the analyzer doesn't flag it — the real
    // serialisation of the DPoP key lives in the next task.
    assert(dpop.keyPair.privateKey.d != null);
  }

  Future<DpopContext> _ensureDpop() async {
    final existing = _dpop;
    if (existing != null) return existing;
    final kp = await keyManager.generateDpopKey();
    final ctx = await makeDpopContextAsync(kp, keyManager: keyManager);
    _dpop = ctx;
    return ctx;
  }

  Future<void> _securityWipe(String reason) async {
    await tokenStore.clear(config.namespace);
    _tokens = null;
    _dpop = null;
    _wrapKey = null;
    _emitSecurity(SecurityEvent.refreshReuseDetected(clock()));
    _transition(StateInput.securityWipe(reason));
  }

  void _transition(StateInput input) {
    final next = reduce(_state, input);
    if (next != _state) {
      _state = next;
      if (!_stateController.isClosed) {
        _stateController.add(next);
      }
    }
  }

  void _emitSecurity(SecurityEvent ev) {
    if (!_securityController.isClosed) {
      _securityController.add(ev);
    }
  }

  void _ensureAlive() {
    if (_destroyed) {
      throw StateError('TokenWorker has been destroyed');
    }
  }
}

/// Opaque bundle returned by [TokenWorker.prepareAuth].
class AuthorizeRequest {
  const AuthorizeRequest({
    required this.url,
    required this.verifier,
    required this.state,
    required this.nonce,
  });

  final String url;
  final String verifier;
  final String state;
  final String nonce;
}

/// Used while a UserClaims-returning API stays in flux.
UserClaims userClaimsFrom(Map<String, dynamic> raw) => UserClaims(raw);

DateTime _defaultClock() => DateTime.now();

String _b64urlNoPad(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

String _encodeForm(Map<String, String> form) => form.entries
    .map((e) =>
        '${Uri.encodeQueryComponent(e.key)}=${Uri.encodeQueryComponent(e.value)}')
    .join('&');
