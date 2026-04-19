import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';
import 'package:antinvestor_auth_runtime/src/crypto/key_manager.dart';
import 'package:antinvestor_auth_runtime/src/crypto/root_key_store.dart';
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
import 'package:crypto/crypto.dart' as crypto;
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
    required this.rootKeyStore,
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
  final RootKeyStore rootKeyStore;
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
  ///
  /// Decryption chain on cold start:
  ///
  /// 1. Pull the root key from [rootKeyStore] — lives in the OS keychain.
  /// 2. Decrypt [StoredSession.wrapKeyCiphertext] under the root key to
  ///    recover the AES-GCM wrap key.
  /// 3. Decrypt [StoredSession.dpopPrivateKeyCiphertext] and
  ///    [StoredSession.refreshTokenCiphertext] under the wrap key.
  /// 4. Rehydrate the [DpopContext] from the `d` scalar.
  ///
  /// Any failure along the way is treated as storage corruption: the
  /// session is wiped, a [SecurityEvent.storageCorruption] is emitted,
  /// and the runtime settles in `unauthenticated` so the caller can
  /// prompt a fresh sign-in.
  Future<void> init() async {
    _ensureAlive();
    try {
      final stored = await tokenStore.load(config.namespace);
      if (stored == null) {
        _transition(const StateInput.initDone(hasTokens: false));
        return;
      }
      final restored = await _rehydrate(stored);
      if (restored == null) {
        await _wipeCorruptSession();
        return;
      }
      _tokens = restored.tokens;
      _wrapKey = restored.wrapKey;
      final kp = restored.dpopKeyPair;
      _dpop = await makeDpopContextAsync(kp, keyManager: keyManager);
      _transition(const StateInput.initDone(hasTokens: true));
    } catch (_) {
      await _wipeCorruptSession();
    }
  }

  Future<_RehydratedSession?> _rehydrate(StoredSession stored) async {
    final rootKey = await rootKeyStore.getOrCreate(config.namespace);
    final rootKeyAsWrap = await keyManager.importWrapKey(rootKey);
    Uint8List wrapKeyBytes;
    try {
      wrapKeyBytes =
          await keyManager.unwrap(rootKeyAsWrap, stored.wrapKeyCiphertext);
    } catch (_) {
      return null;
    }
    if (wrapKeyBytes.length != 32) return null;
    final wrapKey = await keyManager.importWrapKey(wrapKeyBytes);

    final Uint8List dScalar;
    final Uint8List refreshBytes;
    try {
      dScalar =
          await keyManager.unwrap(wrapKey, stored.dpopPrivateKeyCiphertext);
      refreshBytes =
          await keyManager.unwrap(wrapKey, stored.refreshTokenCiphertext);
    } catch (_) {
      return null;
    }
    if (dScalar.length != 32) return null;

    final DpopKeyPair kp;
    try {
      kp = await keyManager.importDpopPrivateKey(dScalar);
    } catch (_) {
      return null;
    }
    final refreshToken = utf8.decode(refreshBytes, allowMalformed: false);
    final tokens = TokenSet(
      accessToken: stored.accessToken,
      refreshToken: refreshToken,
      expiresAt: stored.accessTokenExpiresAt,
      tokenType: TokenType.fromString(stored.tokenType),
      idToken: stored.idToken,
    );
    return _RehydratedSession(
      tokens: tokens,
      wrapKey: wrapKey,
      dpopKeyPair: kp,
    );
  }

  Future<void> _wipeCorruptSession() async {
    try {
      await tokenStore.clear(config.namespace);
    } catch (_) {/* best-effort */}
    _tokens = null;
    _dpop = null;
    _wrapKey = null;
    _emitSecurity(SecurityEvent.storageCorruption(clock()));
    _transition(const StateInput.initDone(hasTokens: false));
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

  /// Completes sign-in from a native credential (Apple / Google) by
  /// exchanging the provider ID token for a Hydra session via RFC 8693
  /// token-exchange grant.
  ///
  /// Pre-exchange guards (see spec §14):
  ///
  /// 1. `iss` claim must match the expected issuer for
  ///    [NativeCredentialResult.provider].
  /// 2. When the provider surfaced a nonce, the ID token's `nonce` claim
  ///    must match either [expectedNonce] directly (Google) or
  ///    `sha256Hex(expectedNonce)` (Apple hashes the nonce before minting).
  ///
  /// Guard failures never touch the state machine except to mark a
  /// failed sign-in; the worker stays `unauthenticated`.
  Future<void> completeNativeCredential({
    required NativeCredentialResult credential,
    required String expectedNonce,
  }) async {
    _ensureAlive();
    _transition(const StateInput.signInStart());

    try {
      final Map<String, dynamic> claims;
      try {
        claims = decodeJwtPayload(credential.idToken);
      } on FormatException catch (e) {
        throw AuthError(
          AuthErrorCode.nativeCredentialExchangeFailed,
          'native credential id-token is malformed',
          cause: e,
        );
      }

      final expectedIssuer = _expectedIssuer(credential.provider);
      final actualIssuer = claims['iss'];
      if (actualIssuer is! String || actualIssuer != expectedIssuer) {
        throw AuthError(
          AuthErrorCode.nativeCredentialIssuerMismatch,
          'iss $actualIssuer does not match expected for '
          '${credential.provider.name}',
        );
      }

      // Nonce binding check. Apple hashes the nonce platform-side so the
      // token's `nonce` claim is the sha256-hex of the raw value; Google
      // echoes the raw nonce. Accept either.
      if (credential.nonce != null) {
        final actualNonce = claims['nonce'];
        if (actualNonce is! String ||
            !_nonceMatches(actualNonce, expectedNonce)) {
          throw AuthError(
            AuthErrorCode.nativeCredentialExchangeFailed,
            'native credential nonce mismatch',
          );
        }
      }

      final ctx = await _ensureDpop();
      final tokens = await tokenExchange.exchangeIdToken(
        config,
        ctx,
        subjectToken: credential.idToken,
        subjectIssuer: actualIssuer,
      );
      _tokens = tokens;
      await _persistSession(tokens);
      _transition(const StateInput.signInDone());
    } catch (err) {
      final ae = err is AuthError
          ? err
          : AuthError(
              AuthErrorCode.nativeCredentialExchangeFailed,
              'native credential exchange failed',
              cause: err,
            );
      _transition(StateInput.signInFail(ae));
      throw ae;
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

    // Wrap key: encrypt its raw bytes under the root key (persistent,
    // keychain-backed).
    final rootKeyBytes = await rootKeyStore.getOrCreate(config.namespace);
    final rootKey = await keyManager.importWrapKey(rootKeyBytes);
    final wrapKeyBytes = await keyManager.exportWrapKey(wrapKey);
    final wrapKeyBlob = await keyManager.wrap(rootKey, wrapKeyBytes);

    // DPoP private key: encrypt the 32-byte `d` scalar under the wrap key.
    final dScalar = await keyManager.exportDpopPrivateKey(dpop.keyPair);
    final dpopBlob = await keyManager.wrap(wrapKey, dScalar);

    // Refresh token: encrypt UTF-8 bytes under the wrap key.
    final refreshBlob = await keyManager.wrap(
      wrapKey,
      utf8.encode(tokens.refreshToken),
    );

    await tokenStore.save(
      config.namespace,
      StoredSession(
        wrapKeyCiphertext: wrapKeyBlob,
        dpopPrivateKeyCiphertext: dpopBlob,
        refreshTokenCiphertext: refreshBlob,
        accessToken: tokens.accessToken,
        accessTokenExpiresAt: tokens.expiresAt,
        tokenType: tokens.tokenType.headerValue,
        idToken: tokens.idToken,
        updatedAt: clock(),
      ),
    );
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
    // Rotate the persistent root key so any leaked on-disk ciphertext is
    // now undecryptable — even if the caller somehow bypasses
    // [tokenStore.clear].
    try {
      await rootKeyStore.rotate(config.namespace);
    } catch (_) {
      // Best-effort: a failure here shouldn't block the wipe.
    }
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

class _RehydratedSession {
  const _RehydratedSession({
    required this.tokens,
    required this.wrapKey,
    required this.dpopKeyPair,
  });

  final TokenSet tokens;
  final WrapKey wrapKey;
  final DpopKeyPair dpopKeyPair;
}

DateTime _defaultClock() => DateTime.now();

String _b64urlNoPad(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

String _encodeForm(Map<String, String> form) => form.entries
    .map((e) =>
        '${Uri.encodeQueryComponent(e.key)}=${Uri.encodeQueryComponent(e.value)}')
    .join('&');

String _expectedIssuer(NativeCredentialProviderKind kind) {
  switch (kind) {
    case NativeCredentialProviderKind.apple:
      return 'https://appleid.apple.com';
    case NativeCredentialProviderKind.google:
      return 'https://accounts.google.com';
  }
}

bool _nonceMatches(String actual, String expected) {
  if (actual == expected) return true;
  final hashed = crypto.sha256.convert(utf8.encode(expected)).toString();
  return actual == hashed;
}
