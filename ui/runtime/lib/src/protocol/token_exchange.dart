import 'dart:async';
import 'dart:convert';

import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/models/token_set.dart';
import 'package:antinvestor_auth_runtime/src/protocol/discovery.dart';
import 'package:antinvestor_auth_runtime/src/protocol/dpop.dart';
import 'package:http/http.dart' as http;

/// Sealed outcome of a refresh-token call. Callers should pattern-match.
sealed class RefreshOutcome {
  const RefreshOutcome();

  const factory RefreshOutcome.rotated(TokenSet tokens) = RefreshRotated;
  const factory RefreshOutcome.reuseDetected() = RefreshReuseDetectedOutcome;
  const factory RefreshOutcome.networkError(AuthError error) =
      RefreshNetworkError;
}

final class RefreshRotated extends RefreshOutcome {
  const RefreshRotated(this.tokens);

  final TokenSet tokens;
}

final class RefreshReuseDetectedOutcome extends RefreshOutcome {
  const RefreshReuseDetectedOutcome();
}

final class RefreshNetworkError extends RefreshOutcome {
  const RefreshNetworkError(this.error);

  final AuthError error;
}

/// Wraps the IdP `/token` endpoint.
///
/// An injectable [http.Client] is the seam for unit tests — `MockClient`
/// from `package:http/testing.dart` handles both discovery and token
/// roundtrips. [timeout] is applied to every underlying request.
class TokenExchange {
  TokenExchange({
    http.Client? client,
    required this.timeout,
  }) : _client = client ?? http.Client();

  final http.Client _client;
  final Duration timeout;

  /// `authorization_code` grant after a successful OAuth leg.
  Future<TokenSet> exchangeCode(
    ResolvedConfig cfg,
    DpopContext ctx, {
    required String code,
    required String verifier,
  }) async {
    final form = <String, String>{
      'grant_type': 'authorization_code',
      'client_id': cfg.clientId,
      'code': code,
      'redirect_uri': cfg.redirectUri,
      'code_verifier': verifier,
    };
    final res = await _postForm(cfg, ctx, form);
    if (res.statusCode < 200 || res.statusCode >= 300) {
      throw AuthError(
        AuthErrorCode.tokenExchangeFailed,
        'token exchange failed ${res.statusCode} ${_truncate(res.body)}',
      );
    }
    return _parseTokenBody(res.body);
  }

  /// `urn:ietf:params:oauth:grant-type:token-exchange` grant for native
  /// credentials (RFC 8693).
  ///
  /// The runtime presents a provider-issued ID token (Apple / Google)
  /// with `subject_token_type: id_token`; the IdP verifies the upstream
  /// signature + audience and mints a Hydra session in exchange. DPoP is
  /// attached on the same terms as [exchangeCode] so the bound session is
  /// consistent with every other grant path.
  Future<TokenSet> exchangeIdToken(
    ResolvedConfig cfg,
    DpopContext ctx, {
    required String subjectToken,
    required String subjectIssuer,
  }) async {
    final form = <String, String>{
      'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
      'client_id': cfg.clientId,
      'subject_token': subjectToken,
      'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
      'subject_issuer': subjectIssuer,
    };
    final res = await _postForm(cfg, ctx, form);
    if (res.statusCode < 200 || res.statusCode >= 300) {
      throw AuthError(
        AuthErrorCode.tokenExchangeFailed,
        'id-token exchange failed ${res.statusCode} ${_truncate(res.body)}',
      );
    }
    return _parseTokenBody(res.body);
  }

  /// `refresh_token` grant with rotation + reuse-detection semantics.
  Future<RefreshOutcome> refresh(
    ResolvedConfig cfg,
    DpopContext ctx,
    String refreshToken,
  ) async {
    try {
      final form = <String, String>{
        'grant_type': 'refresh_token',
        'client_id': cfg.clientId,
        'refresh_token': refreshToken,
      };
      final res = await _postForm(cfg, ctx, form);
      if (res.statusCode >= 200 && res.statusCode < 300) {
        return RefreshOutcome.rotated(_parseTokenBody(res.body));
      }
      if (res.statusCode == 400 && _mentionsReuse(res.body)) {
        return const RefreshOutcome.reuseDetected();
      }
      return RefreshOutcome.networkError(AuthError(
        AuthErrorCode.tokenRefreshFailed,
        'refresh failed ${res.statusCode} ${_truncate(res.body)}',
      ));
    } on AuthError catch (e) {
      return RefreshOutcome.networkError(e);
    } catch (e) {
      return RefreshOutcome.networkError(AuthError(
        AuthErrorCode.tokenRefreshFailed,
        'refresh failed',
        cause: e,
      ));
    }
  }

  /// Posts [form] to the IdP token endpoint. Applies DPoP when the IdP
  /// advertises support; implements the nonce-challenge and clock-skew
  /// retries described in spec §6.
  Future<http.Response> _postForm(
    ResolvedConfig cfg,
    DpopContext ctx,
    Map<String, String> form,
  ) async {
    final discovery = await getDiscovery(
      cfg.idpBaseUrl,
      cfg.discoveryTimeout,
      client: _client,
    );
    final useDpop = supportsDpop(discovery);
    final tokenUri = Uri.parse(discovery.tokenEndpoint);

    final body = _encodeForm(form);
    Map<String, String> headers() => {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
        };

    Future<http.Response> send({String? dpopProof}) async {
      final h = headers();
      if (dpopProof != null) h['DPoP'] = dpopProof;
      return _client
          .post(tokenUri, headers: h, body: body)
          .timeout(timeout);
    }

    http.Response res;
    try {
      final initialProof = useDpop
          ? await buildProof(ctx, htm: 'POST', htu: discovery.tokenEndpoint)
          : null;
      res = await send(dpopProof: initialProof);

      if (useDpop && res.statusCode == 401 &&
          _headerIgnoreCase(res.headers, 'dpop-nonce') != null) {
        rememberNonce(ctx, discovery.tokenEndpoint, res.headers);
        final retryProof = await buildProof(
          ctx,
          htm: 'POST',
          htu: discovery.tokenEndpoint,
        );
        res = await send(dpopProof: retryProof);
      }

      if (useDpop && res.statusCode == 400 &&
          _mentionsInvalidDpopProof(res.body)) {
        rememberClockOffset(ctx, res.headers);
        final retryProof = await buildProof(
          ctx,
          htm: 'POST',
          htu: discovery.tokenEndpoint,
        );
        res = await send(dpopProof: retryProof);
      }

      rememberNonce(ctx, discovery.tokenEndpoint, res.headers);
      return res;
    } on TimeoutException catch (err) {
      throw AuthError(
        AuthErrorCode.networkTimeout,
        'token endpoint timeout',
        cause: err,
      );
    } on AuthError {
      rethrow;
    } catch (err) {
      throw AuthError(
        AuthErrorCode.tokenExchangeFailed,
        'token endpoint error',
        cause: err,
      );
    }
  }
}

TokenSet _parseTokenBody(String body) {
  final Map<String, dynamic> data;
  try {
    final decoded = json.decode(body);
    if (decoded is! Map) {
      throw AuthError(
        AuthErrorCode.tokenExchangeFailed,
        'token response is not a JSON object',
      );
    }
    data = decoded.cast<String, dynamic>();
  } on FormatException catch (e) {
    throw AuthError(
      AuthErrorCode.tokenExchangeFailed,
      'token response is not JSON',
      cause: e,
    );
  }
  final accessToken = data['access_token'];
  final refreshToken = data['refresh_token'];
  if (accessToken is! String || refreshToken is! String) {
    throw AuthError(
      AuthErrorCode.tokenExchangeFailed,
      'missing access_token or refresh_token',
    );
  }
  final expiresIn =
      data['expires_in'] is int ? data['expires_in'] as int : 300;
  final tokenType = TokenType.fromString(data['token_type'] as String?);
  final idToken = data['id_token'] is String ? data['id_token'] as String : null;
  return TokenSet(
    accessToken: accessToken,
    refreshToken: refreshToken,
    expiresAt: DateTime.now().add(Duration(seconds: expiresIn)),
    tokenType: tokenType,
    idToken: idToken,
  );
}

bool _mentionsReuse(String body) {
  return RegExp(r'invalid_grant|reuse', caseSensitive: false).hasMatch(body);
}

bool _mentionsInvalidDpopProof(String body) {
  return RegExp(r'invalid_dpop_proof', caseSensitive: false).hasMatch(body);
}

String _encodeForm(Map<String, String> form) => form.entries
    .map((e) =>
        '${Uri.encodeQueryComponent(e.key)}=${Uri.encodeQueryComponent(e.value)}')
    .join('&');

String _truncate(String s) => s.length > 200 ? s.substring(0, 200) : s;

String? _headerIgnoreCase(Map<String, String> headers, String name) {
  final lower = name.toLowerCase();
  for (final e in headers.entries) {
    if (e.key.toLowerCase() == lower) return e.value;
  }
  return null;
}
