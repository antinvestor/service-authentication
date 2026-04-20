import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/protocol/discovery.dart';
import 'package:flutter_appauth/flutter_appauth.dart';

/// Result returned from a completed OAuth leg.
///
/// Callers hand this back to [TokenWorker.completeAuth] for the
/// `authorization_code` grant. [verifier] is the PKCE verifier
/// flutter_appauth generated and tracked end-to-end.
class OAuthResult {
  const OAuthResult({
    required this.code,
    required this.verifier,
    this.state,
    this.nonce,
  });

  final String code;
  final String verifier;
  final String? state;
  final String? nonce;
}

/// Wraps `flutter_appauth` into the runtime's error model.
///
/// **Deviation from plan**: the plan originally sketched `authorize`
/// taking the verifier + state from the runtime. `flutter_appauth`
/// 8.0.0's `AuthorizationRequest` does not expose a `codeVerifier`
/// parameter — it generates its own and returns it on the response. We
/// therefore let the plugin own PKCE for the browser leg and surface the
/// verifier via [OAuthResult.verifier]. The rest of the pipeline
/// (TokenWorker.completeAuth) consumes that verifier verbatim.
class OAuthFlow {
  OAuthFlow({
    FlutterAppAuth? appAuth,
    DiscoveryClientFn? discoveryFn,
  })  : _appAuth = appAuth ?? const FlutterAppAuth(),
        _discoveryFn = discoveryFn ?? _defaultDiscoveryFn;

  final FlutterAppAuth _appAuth;
  final DiscoveryClientFn _discoveryFn;

  /// Drives the browser leg: opens a system browser or authentication
  /// session, returns the authorisation code + PKCE verifier.
  ///
  /// Maps `FlutterAppAuth` exceptions to runtime [AuthError]s:
  /// - [FlutterAppAuthUserCancelledException] → `oauthUserCanceled`
  /// - everything else → `oauthFailed`
  Future<OAuthResult> authorize(ResolvedConfig cfg) async {
    final discovery = await _discoveryFn(cfg);

    final request = AuthorizationRequest(
      cfg.clientId,
      cfg.redirectUri,
      serviceConfiguration: AuthorizationServiceConfiguration(
        authorizationEndpoint: discovery.authorizationEndpoint,
        tokenEndpoint: discovery.tokenEndpoint,
        endSessionEndpoint: discovery.endSessionEndpoint,
      ),
      scopes: cfg.scopes,
      allowInsecureConnections: false,
    );

    AuthorizationResponse response;
    try {
      response = await _appAuth.authorize(request);
    } on FlutterAppAuthUserCancelledException catch (err) {
      throw AuthError(
        AuthErrorCode.oauthUserCanceled,
        'user cancelled OAuth flow',
        cause: err,
      );
    } catch (err) {
      throw AuthError(
        AuthErrorCode.oauthFailed,
        'OAuth authorize failed',
        cause: err,
      );
    }

    final code = response.authorizationCode;
    final verifier = response.codeVerifier;
    if (code == null || verifier == null) {
      throw AuthError(
        AuthErrorCode.oauthFailed,
        'OAuth response missing code or verifier',
      );
    }
    return OAuthResult(
      code: code,
      verifier: verifier,
      nonce: response.nonce,
    );
  }
}

/// Hook for injecting a discovery call in tests. Default implementation
/// goes through the cached top-level [getDiscovery].
typedef DiscoveryClientFn = Future<OidcDiscovery> Function(
  ResolvedConfig cfg,
);

Future<OidcDiscovery> _defaultDiscoveryFn(ResolvedConfig cfg) =>
    getDiscovery(cfg.idpBaseUrl, cfg.discoveryTimeout);
