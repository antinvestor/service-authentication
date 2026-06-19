import 'dart:async';
import 'dart:convert';

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
// Fakes — copied in spirit from token_worker_test but tuned for
// AuthRuntimeImpl level scenarios.
// ---------------------------------------------------------------------------

class _FakeDiscoveryClient implements DiscoveryClient {
  @override
  Future<OidcDiscovery> getDiscovery(
    String idpBaseUrl,
    Duration timeout,
  ) async => OidcDiscovery(
    issuer: idpBaseUrl,
    authorizationEndpoint: '$idpBaseUrl/oauth2/auth',
    tokenEndpoint: '$idpBaseUrl/oauth2/token',
    endSessionEndpoint: '$idpBaseUrl/oauth2/sessions/logout',
    revocationEndpoint: '$idpBaseUrl/oauth2/revoke',
  );
}

class _FakeTokenExchange extends TokenExchange {
  _FakeTokenExchange() : super(timeout: const Duration(seconds: 5));

  List<TokenSet> codeQueue = <TokenSet>[];
  List<TokenSet> idTokenQueue = <TokenSet>[];
  AuthError? idTokenError;
  int idTokenCalls = 0;
  int codeCalls = 0;

  @override
  Future<TokenSet> exchangeCode(
    ResolvedConfig cfg,
    DpopContext ctx, {
    required String code,
    required String verifier,
  }) async {
    codeCalls++;
    if (codeQueue.isEmpty) {
      throw AuthError(AuthErrorCode.tokenExchangeFailed, 'no code queued');
    }
    return codeQueue.removeAt(0);
  }

  @override
  Future<TokenSet> exchangeIdToken(
    ResolvedConfig cfg,
    DpopContext ctx, {
    required String subjectToken,
    required String subjectIssuer,
    String? platform,
    String? deviceName,
  }) async {
    idTokenCalls++;
    if (idTokenError != null) throw idTokenError!;
    if (idTokenQueue.isEmpty) {
      throw AuthError(AuthErrorCode.tokenExchangeFailed, 'no id-token queued');
    }
    return idTokenQueue.removeAt(0);
  }
}

class _FakeOAuthFlow implements OAuthFlow {
  _FakeOAuthFlow();

  int calls = 0;

  @override
  Future<OAuthResult> authorize(
    ResolvedConfig cfg,
    AuthorizeRequest prepared,
  ) async {
    calls++;
    return OAuthResult(code: 'fake-code', state: prepared.state);
  }
}

class _StubProvider implements NativeCredentialProvider {
  _StubProvider({
    required this.kind,
    required this.availability,
    List<NativeCredentialOutcome> interactiveOutcomes =
        const <NativeCredentialOutcome>[],
    this.throwOnAvailable = false,
  }) : interactiveOutcomes = List<NativeCredentialOutcome>.of(
         interactiveOutcomes,
       );

  @override
  final NativeCredentialProviderKind kind;
  final bool availability;
  final bool throwOnAvailable;
  List<NativeCredentialOutcome> interactiveOutcomes;

  int availableCalls = 0;
  int silentCalls = 0;
  int interactiveCalls = 0;
  int signOutCalls = 0;

  @override
  Future<bool> isAvailable() async {
    availableCalls++;
    if (throwOnAvailable) throw StateError('boom');
    return availability;
  }

  @override
  Future<NativeCredentialOutcome> attemptSilent({required String nonce}) async {
    silentCalls++;
    return const NativeCredentialOutcome.noSession();
  }

  @override
  Future<NativeCredentialOutcome> attemptInteractive({
    required String nonce,
  }) async {
    interactiveCalls++;
    if (interactiveOutcomes.isEmpty) {
      return const NativeCredentialOutcome.cancelled();
    }
    return interactiveOutcomes.removeAt(0);
  }

  @override
  Future<void> signOut() async {
    signOutCalls++;
  }
}

TokenSet _tokenSet({
  String access = 'access-tok',
  String refresh = 'refresh-tok',
  String? idToken,
}) => TokenSet(
  accessToken: access,
  refreshToken: refresh,
  expiresAt: DateTime.now().add(const Duration(minutes: 5)),
  tokenType: TokenType.bearer,
  idToken: idToken,
);

String _makeJwt(Map<String, dynamic> payload) {
  String strip(String s) => s.replaceAll('=', '');
  final header = strip(
    base64Url.encode(utf8.encode(json.encode(<String, String>{'alg': 'none'}))),
  );
  final body = strip(base64Url.encode(utf8.encode(json.encode(payload))));
  final sig = strip(base64Url.encode(const <int>[1, 2, 3]));
  return '$header.$body.$sig';
}

class _Harness {
  _Harness({
    required this.runtime,
    required this.worker,
    required this.exchange,
    required this.oauth,
  });

  final AuthRuntimeImpl runtime;
  final TokenWorker worker;
  final _FakeTokenExchange exchange;
  final _FakeOAuthFlow oauth;
}

_Harness _build({
  required List<NativeCredentialProvider> providers,
  bool preferNativeCredentialSilentAttempt = true,
}) {
  final cfg = resolveConfig(
    const AuthConfig(
      clientId: 'c',
      idpBaseUrl: 'https://idp.example.com',
      apiBaseUrl: 'https://api.example.com',
      redirectScheme: 'com.example.app',
    ),
  );
  final exchange = _FakeTokenExchange();
  final worker = TokenWorker(
    config: cfg,
    keyManager: DefaultKeyManager(),
    rootKeyStore: DefaultRootKeyStore(kv: InMemoryKeyValueStore()),
    tokenStore: SecureTokenStore(kv: InMemoryKeyValueStore()),
    discoveryClient: _FakeDiscoveryClient(),
    tokenExchange: exchange,
    apiProxy: ApiProxy(),
    refreshLock: RefreshLock(),
  );
  final oauth = _FakeOAuthFlow();
  final runtime = AuthRuntimeImpl(
    config: cfg,
    worker: worker,
    oauthFlow: oauth,
    nativeProviders: providers,
    preferNativeCredentialSilentAttempt: preferNativeCredentialSilentAttempt,
  );
  return _Harness(
    runtime: runtime,
    worker: worker,
    exchange: exchange,
    oauth: oauth,
  );
}

void main() {
  tearDown(clearDiscoveryCache);

  group('AuthRuntimeImpl native credential waterfall', () {
    test('availableNativeProviders reports only available providers', () async {
      final h = _build(
        providers: [
          _StubProvider(
            kind: NativeCredentialProviderKind.apple,
            availability: false,
          ),
          _StubProvider(
            kind: NativeCredentialProviderKind.google,
            availability: true,
          ),
        ],
      );
      await h.runtime.init();
      final avail = await h.runtime.availableNativeProviders();
      expect(avail, {NativeCredentialProviderKind.google});
      await h.runtime.dispose();
    });

    test(
      'proactive silent attempt: ok → authenticated; no OAuth fallback',
      () async {
        final provider = _NonceEchoingProvider(
          kind: NativeCredentialProviderKind.google,
        );
        final h = _build(providers: [provider]);
        h.exchange.idTokenQueue.add(_tokenSet(access: 'native-at'));

        final credEvents = <CredentialEvent>[];
        final credSub = h.runtime.credentialEventStream.listen(credEvents.add);

        await h.runtime.init();
        // Let init flush + proactive silent microtask + worker completion settle.
        for (var i = 0; i < 20; i++) {
          await Future<void>.delayed(Duration.zero);
        }

        expect(h.worker.state, AuthState.authenticated);
        expect(provider.silentCalls, 1);
        expect(h.exchange.idTokenCalls, 1);
        expect(h.oauth.calls, 0);
        expect(credEvents.whereType<CredentialSilentAttemptEvent>().length, 1);
        expect(credEvents.whereType<CredentialOutcomeEvent>().length, 1);
        await credSub.cancel();
        await h.runtime.dispose();
      },
    );

    test('preferSilent=false skips app-start silent attempt', () async {
      final provider = _NonceEchoingProvider(
        kind: NativeCredentialProviderKind.google,
      );
      final h = _build(
        providers: [provider],
        preferNativeCredentialSilentAttempt: false,
      );
      h.exchange.idTokenQueue.add(_tokenSet(access: 'native-at'));

      await h.runtime.init();
      for (var i = 0; i < 20; i++) {
        await Future<void>.delayed(Duration.zero);
      }

      expect(h.worker.state, AuthState.unauthenticated);
      expect(provider.silentCalls, 0);
      expect(h.exchange.idTokenCalls, 0);
      await h.runtime.ensureAuthenticated();
      expect(provider.interactiveCalls, 1);
      expect(h.worker.state, AuthState.authenticated);
      await h.runtime.dispose();
    });

    test(
      'silent-noSession + interactive-success → authenticated; no OAuth fallback',
      () async {
        final provider = _NonceEchoingProvider(
          kind: NativeCredentialProviderKind.google,
          silentOutcome: const NativeCredentialOutcome.noSession(),
          // Interactive will yield ok-with-matching-nonce.
        );
        final h = _build(providers: [provider]);
        // Queue two token-exchange responses: one for the (absent) silent,
        // one for the interactive attempt.
        h.exchange.idTokenQueue.add(_tokenSet(access: 'native-at'));
        await h.runtime.init();

        for (var i = 0; i < 5; i++) {
          await Future<void>.delayed(Duration.zero);
        }
        // Silent consumed: no worker exchange happened.
        expect(h.worker.state, AuthState.unauthenticated);
        expect(h.exchange.idTokenCalls, 0);

        await h.runtime.ensureAuthenticated();
        expect(h.worker.state, AuthState.authenticated);
        expect(provider.interactiveCalls, 1);
        expect(h.oauth.calls, 0);
        expect(h.exchange.idTokenCalls, 1);
        await h.runtime.dispose();
      },
    );

    test('all providers decline → OAuth2 fallback', () async {
      final provider = _StubProvider(
        kind: NativeCredentialProviderKind.apple,
        availability: true,
        interactiveOutcomes: const [NativeCredentialOutcome.cancelled()],
      );
      final h = _build(providers: [provider]);
      h.exchange.codeQueue.add(_tokenSet(access: 'oauth-at'));
      await h.runtime.init();

      for (var i = 0; i < 5; i++) {
        await Future<void>.delayed(Duration.zero);
      }
      // Proactive silent attempt ran; noSession → no authentication.
      expect(h.worker.state, AuthState.unauthenticated);

      await h.runtime.ensureAuthenticated();
      expect(h.worker.state, AuthState.authenticated);
      expect(provider.interactiveCalls, 1);
      expect(h.oauth.calls, 1);
      expect(h.exchange.codeCalls, 1);
      await h.runtime.dispose();
    });

    test(
      'worker exchange failure after interactive-ok does not open OAuth2',
      () async {
        final provider = _NonceEchoingProvider(
          kind: NativeCredentialProviderKind.google,
          silentOutcome: const NativeCredentialOutcome.noSession(),
        );
        final h = _build(providers: [provider]);
        h.exchange.idTokenError = AuthError(
          AuthErrorCode.tokenExchangeFailed,
          'boom',
        );
        await h.runtime.init();

        for (var i = 0; i < 5; i++) {
          await Future<void>.delayed(Duration.zero);
        }
        await expectLater(
          h.runtime.ensureAuthenticated(),
          throwsA(
            isA<AuthError>().having(
              (e) => e.code,
              'code',
              AuthErrorCode.tokenExchangeFailed,
            ),
          ),
        );
        expect(h.worker.state, AuthState.unauthenticated);
        expect(h.oauth.calls, 0);
        expect(h.exchange.codeCalls, 0);
        expect(h.exchange.idTokenCalls, 1);
        await h.runtime.dispose();
      },
    );

    test('silent id-token with bogus iss is rejected by the worker; '
        'proactive attempt leaves state unauthenticated', () async {
      final provider = _BadIssuerProvider();
      final h = _build(providers: [provider]);
      await h.runtime.init();

      for (var i = 0; i < 5; i++) {
        await Future<void>.delayed(Duration.zero);
      }
      expect(h.worker.state, AuthState.unauthenticated);
      // The worker rejected the token before any exchange call went out.
      expect(h.exchange.idTokenCalls, 0);
      await h.runtime.dispose();
    });

    test('logout calls signOut on all providers', () async {
      final apple = _StubProvider(
        kind: NativeCredentialProviderKind.apple,
        availability: true,
      );
      final google = _StubProvider(
        kind: NativeCredentialProviderKind.google,
        availability: true,
      );
      final h = _build(providers: [apple, google]);
      await h.runtime.init();
      final events = <CredentialEvent>[];
      final sub = h.runtime.credentialEventStream.listen(events.add);
      await h.runtime.logout();
      expect(apple.signOutCalls, 1);
      expect(google.signOutCalls, 1);
      final signOuts = events.whereType<CredentialSignOutEvent>().toList();
      expect(signOuts.length, 2);
      expect(signOuts.map((e) => e.kind).toSet(), {
        NativeCredentialProviderKind.apple,
        NativeCredentialProviderKind.google,
      });
      await sub.cancel();
      await h.runtime.dispose();
    });

    test('ensureAuthenticated called immediately after construction runs '
        'OAuth exactly once (no proactive-silent race)', () async {
      // Provider reports unavailable so the waterfall falls straight
      // through to OAuth. If the proactive-silent microtask were
      // permitted to race an explicit ensureAuthenticated(), we would
      // see the OAuth flow invoked more than once or the worker state
      // thrash; neither should happen.
      final provider = _StubProvider(
        kind: NativeCredentialProviderKind.google,
        availability: false,
      );
      final h = _build(providers: [provider]);
      h.exchange.codeQueue.add(_tokenSet(access: 'oauth-at'));

      // Do NOT await init(); call ensureAuthenticated() straight away.
      final ensuring = h.runtime.ensureAuthenticated();
      // Let microtasks settle so any would-be proactive-silent attempt
      // has a chance to run alongside the in-flight waterfall.
      for (var i = 0; i < 20; i++) {
        await Future<void>.delayed(Duration.zero);
      }
      await ensuring;

      expect(h.worker.state, AuthState.authenticated);
      expect(h.oauth.calls, 1);
      expect(h.exchange.codeCalls, 1);
      await h.runtime.dispose();
    });

    test('dispose() while proactive silent is mid-flight does not raise '
        'unhandled errors', () async {
      final provider = _BlockingSilentProvider();
      final h = _build(providers: [provider]);

      await h.runtime.init();
      // Let the proactive silent microtask spin up and park on the
      // pending Future inside attemptSilent().
      for (var i = 0; i < 5; i++) {
        await Future<void>.delayed(Duration.zero);
      }
      expect(provider.silentCalls, 1);

      // Capture any unhandled zone errors.
      final unhandled = <Object>[];
      await runZonedGuarded<Future<void>>(() async {
        await h.runtime.dispose();
        // Release the provider's pending Future so the microtask
        // resumes post-dispose. It must exit cleanly.
        provider.releaseSilent(const NativeCredentialOutcome.noSession());
        for (var i = 0; i < 20; i++) {
          await Future<void>.delayed(Duration.zero);
        }
      }, (err, _) => unhandled.add(err));

      expect(unhandled, isEmpty, reason: 'dispose should be clean');
    });

    test(
      'provider throwing in isAvailable does not crash the waterfall',
      () async {
        final bad = _StubProvider(
          kind: NativeCredentialProviderKind.apple,
          availability: true,
          throwOnAvailable: true,
        );
        final h = _build(providers: [bad]);
        h.exchange.codeQueue.add(_tokenSet(access: 'oauth-at'));
        await h.runtime.init();
        // Runtime can still recover via OAuth2.
        await h.runtime.ensureAuthenticated();
        expect(h.worker.state, AuthState.authenticated);
        expect(h.oauth.calls, 1);
        await h.runtime.dispose();
      },
    );
  });
}

/// Provider whose silent attempt returns an OK outcome with an iss that
/// is NOT the expected issuer for the declared provider kind. The worker
/// should reject this before any token-exchange is attempted.
class _BadIssuerProvider implements NativeCredentialProvider {
  _BadIssuerProvider();

  @override
  NativeCredentialProviderKind get kind => NativeCredentialProviderKind.google;

  int silentCalls = 0;

  @override
  Future<bool> isAvailable() async => true;

  @override
  Future<NativeCredentialOutcome> attemptSilent({required String nonce}) async {
    silentCalls++;
    return NativeCredentialOutcome.ok(
      NativeCredentialResult(
        provider: NativeCredentialProviderKind.google,
        idToken: _makeJwt(<String, dynamic>{
          'iss': 'https://evil.example.com',
          'sub': 'u',
          'nonce': nonce,
        }),
        autoSelected: true,
        nonce: nonce,
      ),
    );
  }

  @override
  Future<NativeCredentialOutcome> attemptInteractive({
    required String nonce,
  }) async => const NativeCredentialOutcome.cancelled();

  @override
  Future<void> signOut() async {}
}

/// Provider that synthesises a matching-nonce ID token from whatever the
/// runtime passes to [attemptSilent] / [attemptInteractive]. Keeps tests
/// decoupled from the randomness of the runtime's nonce generator.
class _NonceEchoingProvider implements NativeCredentialProvider {
  _NonceEchoingProvider({required this.kind, this.silentOutcome});

  @override
  final NativeCredentialProviderKind kind;
  final NativeCredentialOutcome? silentOutcome;

  int silentCalls = 0;
  int interactiveCalls = 0;
  int signOutCalls = 0;

  @override
  Future<bool> isAvailable() async => true;

  NativeCredentialOutcome _okFor(String nonce) {
    final issuer = kind == NativeCredentialProviderKind.apple
        ? 'https://appleid.apple.com'
        : 'https://accounts.google.com';
    return NativeCredentialOutcome.ok(
      NativeCredentialResult(
        provider: kind,
        idToken: _makeJwt(<String, dynamic>{
          'iss': issuer,
          'sub': 'u',
          'aud': 'c',
          'nonce': nonce,
        }),
        autoSelected: true,
        nonce: nonce,
      ),
    );
  }

  @override
  Future<NativeCredentialOutcome> attemptSilent({required String nonce}) async {
    silentCalls++;
    return silentOutcome ?? _okFor(nonce);
  }

  @override
  Future<NativeCredentialOutcome> attemptInteractive({
    required String nonce,
  }) async {
    interactiveCalls++;
    return _okFor(nonce);
  }

  @override
  Future<void> signOut() async {
    signOutCalls++;
  }
}

/// Provider whose [attemptSilent] blocks on a manually-released Completer,
/// so tests can inject a dispose() call while the runtime is parked
/// inside the proactive-silent microtask.
class _BlockingSilentProvider implements NativeCredentialProvider {
  final Completer<NativeCredentialOutcome> _gate =
      Completer<NativeCredentialOutcome>();

  int silentCalls = 0;

  @override
  NativeCredentialProviderKind get kind => NativeCredentialProviderKind.google;

  @override
  Future<bool> isAvailable() async => true;

  @override
  Future<NativeCredentialOutcome> attemptSilent({required String nonce}) {
    silentCalls++;
    return _gate.future;
  }

  @override
  Future<NativeCredentialOutcome> attemptInteractive({
    required String nonce,
  }) async => const NativeCredentialOutcome.cancelled();

  @override
  Future<void> signOut() async {}

  void releaseSilent(NativeCredentialOutcome outcome) {
    if (!_gate.isCompleted) _gate.complete(outcome);
  }
}
