import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_router/shelf_router.dart';

/// Minimal IdP surface the runtime exercises end-to-end.
///
/// Listens on `127.0.0.1:<kernel-picked>` so multiple tests can run in
/// parallel without port collisions. Every handler is deterministic and
/// synchronous so assertion counts are stable.
///
/// Toggles live on the instance so a single test can, for example, enable
/// the nonce challenge for one call and then turn it off again to verify
/// the happy-path retry.
class MockIdp {
  MockIdp({this.tokenLifetime = const Duration(seconds: 300)});

  /// How long `expires_in` claims for minted access tokens.
  final Duration tokenLifetime;

  HttpServer? _server;
  String? _baseUrl;

  /// List of every `/token` request observed, in order. Useful for
  /// assertions about DPoP proof content and retries.
  final List<RecordedTokenRequest> tokenRequests = <RecordedTokenRequest>[];

  /// List of every `/revocation` POST observed.
  final List<RecordedRequest> revocationRequests = <RecordedRequest>[];

  /// List of every `/end_session` hit observed.
  final List<RecordedRequest> endSessionRequests = <RecordedRequest>[];

  /// When true, the first `/token` hit without a `nonce` claim in the DPoP
  /// proof returns 401 + a `DPoP-Nonce` header; subsequent hits accept any
  /// `nonce` claim at all (we don't verify signatures).
  bool nonceChallengeArmed = false;

  /// When true, the first `/token` hit whose DPoP `iat` is further from
  /// server time than [_clockSkewTolerance] returns 400
  /// `invalid_dpop_proof` + a `Date` header 5 minutes in the future.
  bool clockSkewChallengeArmed = false;

  /// The `DPoP-Nonce` value handed back during a nonce challenge.
  String currentNonce = 'nonce-from-idp';

  /// Used RTs and their issuing JTI — re-submitting a consumed RT triggers
  /// reuse detection. Map value is the RT family id.
  final Map<String, String> _consumedRefreshTokens = <String, String>{};
  final Set<String> _liveRefreshTokens = <String>{};

  /// Monotonic counter feeding access / refresh token ids so tests can
  /// reason about which tokens came from which rotation.
  int _rotationCounter = 0;

  /// Allowlist of issuers accepted by the `token-exchange` grant path.
  /// Defaults to Apple + Google; tests can widen or tighten via
  /// [setAllowedIssuers].
  List<String> _allowedExchangeIssuers = const <String>[
    'https://appleid.apple.com',
    'https://accounts.google.com',
  ];

  /// The issuer URL advertised in discovery + ID tokens. Populated at
  /// `start` time.
  String get baseUrl => _baseUrl!;

  /// Convenience: the token endpoint a DPoP proof's `htu` claim must match.
  String get tokenEndpoint => '$baseUrl/token';

  /// Starts listening on an ephemeral loopback port.
  Future<String> start() async {
    final router = Router();

    router.get('/.well-known/openid-configuration', _discovery);
    router.post('/token', _token);
    router.post('/revocation', _revocation);
    // The runtime issues a GET for end_session per RFC 7662 (client-driven
    // redirect), so we respond to both verbs.
    router.get('/end_session', _endSession);
    router.post('/end_session', _endSession);

    _server = await shelf_io.serve(router.call, '127.0.0.1', 0);
    _baseUrl = 'http://127.0.0.1:${_server!.port}';
    return _baseUrl!;
  }

  /// Shuts the server down. Safe to call even if not running.
  Future<void> stop() async {
    final s = _server;
    _server = null;
    _baseUrl = null;
    await s?.close(force: true);
  }

  // Public toggles ----------------------------------------------------------

  void enableNonceChallenge({String nonce = 'nonce-from-idp'}) {
    nonceChallengeArmed = true;
    currentNonce = nonce;
  }

  void enableClockSkewChallenge() {
    clockSkewChallengeArmed = true;
  }

  /// Replace the allowlist of issuers accepted by the `token-exchange`
  /// grant path. Useful for tests that want to verify enforcement.
  void setAllowedIssuers(List<String> issuers) {
    _allowedExchangeIssuers = List<String>.unmodifiable(issuers);
  }

  /// Resets the counters / recorded requests so a single MockIdp can be
  /// reused across scenarios.
  void reset() {
    tokenRequests.clear();
    revocationRequests.clear();
    endSessionRequests.clear();
    nonceChallengeArmed = false;
    clockSkewChallengeArmed = false;
    _consumedRefreshTokens.clear();
    _liveRefreshTokens.clear();
    _rotationCounter = 0;
    _allowedExchangeIssuers = const <String>[
      'https://appleid.apple.com',
      'https://accounts.google.com',
    ];
  }

  // Handlers ----------------------------------------------------------------

  Response _discovery(Request _) {
    final body = <String, dynamic>{
      'issuer': baseUrl,
      'authorization_endpoint': '$baseUrl/authorize',
      'token_endpoint': tokenEndpoint,
      'end_session_endpoint': '$baseUrl/end_session',
      'revocation_endpoint': '$baseUrl/revocation',
      'userinfo_endpoint': '$baseUrl/userinfo',
      'jwks_uri': '$baseUrl/jwks',
      'dpop_signing_alg_values_supported': <String>['ES256'],
    };
    return Response.ok(
      json.encode(body),
      headers: <String, String>{'Content-Type': 'application/json'},
    );
  }

  Future<Response> _token(Request req) async {
    final bodyStr = await req.readAsString();
    final form = Uri.splitQueryString(bodyStr);
    final dpopHeader = _headerIgnoreCase(req.headers, 'DPoP');

    DpopProofClaims? dpop;
    if (dpopHeader != null) {
      dpop = _parseDpopProof(dpopHeader);
    }

    tokenRequests.add(RecordedTokenRequest(
      grantType: form['grant_type'] ?? '',
      form: form,
      dpopHeader: dpopHeader,
      dpopClaims: dpop,
    ));

    // Nonce challenge: first call without nonce claim in proof → 401 +
    // DPoP-Nonce header. Arm-once semantics: once consumed, the challenge
    // stands down so the retry succeeds.
    if (nonceChallengeArmed) {
      if (dpop == null || dpop.nonce == null) {
        nonceChallengeArmed = false;
        return Response(
          401,
          headers: <String, String>{
            'DPoP-Nonce': currentNonce,
            'Content-Type': 'application/json',
          },
          body: json.encode(<String, String>{'error': 'use_dpop_nonce'}),
        );
      }
    }

    // Clock-skew challenge: first hit unconditionally returns 400
    // invalid_dpop_proof + a Date header 5 minutes in the future. The
    // runtime is expected to read the Date header, compensate its
    // clockOffsetMs, and retry. Arm-once.
    if (clockSkewChallengeArmed && dpop != null) {
      clockSkewChallengeArmed = false;
      final future = DateTime.now().add(const Duration(minutes: 5));
      return Response(
        400,
        headers: <String, String>{
          'Date': HttpDate.format(future),
          'Content-Type': 'application/json',
        },
        body: json.encode(<String, String>{'error': 'invalid_dpop_proof'}),
      );
    }

    final grant = form['grant_type'];
    switch (grant) {
      case 'authorization_code':
        return _issueTokens(newFamily: true);
      case 'urn:ietf:params:oauth:grant-type:token-exchange':
        return _handleTokenExchange(form);
      case 'refresh_token':
        final rt = form['refresh_token'];
        if (rt == null || rt.isEmpty) {
          return Response(
            400,
            headers: <String, String>{'Content-Type': 'application/json'},
            body: json.encode(<String, String>{'error': 'invalid_grant'}),
          );
        }
        if (_consumedRefreshTokens.containsKey(rt)) {
          // Reuse detection: the RT has already been rotated away.
          return Response(
            400,
            headers: <String, String>{'Content-Type': 'application/json'},
            body: json.encode(<String, String>{
              'error': 'invalid_grant',
              'error_description': 'refresh token reuse detected',
            }),
          );
        }
        if (!_liveRefreshTokens.contains(rt)) {
          // Unknown RT — never issued.
          return Response(
            400,
            headers: <String, String>{'Content-Type': 'application/json'},
            body: json.encode(<String, String>{'error': 'invalid_grant'}),
          );
        }
        // Rotation: consume the presented RT, mint a new pair.
        _liveRefreshTokens.remove(rt);
        _consumedRefreshTokens[rt] = 'family';
        return _issueTokens(newFamily: false);
      default:
        return Response(
          400,
          headers: <String, String>{'Content-Type': 'application/json'},
          body: json.encode(<String, String>{'error': 'unsupported_grant_type'}),
        );
    }
  }

  Response _issueTokens({
    required bool newFamily,
    String sub = 'user-1',
    String aud = 'antinvestor-mobile',
  }) {
    _rotationCounter += 1;
    final n = _rotationCounter;
    final accessToken = _makeUnsignedJwt(<String, dynamic>{
      'iss': baseUrl,
      'sub': sub,
      'aud': aud,
      'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
      'exp': DateTime.now()
              .add(tokenLifetime)
              .millisecondsSinceEpoch ~/
          1000,
      'roles': <String>['user', 'admin'],
      'jti': 'at-$n',
    });
    final idToken = _makeUnsignedJwt(<String, dynamic>{
      'iss': baseUrl,
      'sub': sub,
      'aud': aud,
      'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
      'exp': DateTime.now()
              .add(tokenLifetime)
              .millisecondsSinceEpoch ~/
          1000,
      'email': 'user@example.com',
      'name': 'Test User',
      'picture': 'https://example.com/avatar.png',
    });
    final refreshToken = 'rt-$n';
    _liveRefreshTokens.add(refreshToken);

    final body = <String, dynamic>{
      'access_token': accessToken,
      'refresh_token': refreshToken,
      'id_token': idToken,
      'token_type': 'DPoP',
      'expires_in': tokenLifetime.inSeconds,
    };
    return Response.ok(
      json.encode(body),
      headers: <String, String>{'Content-Type': 'application/json'},
    );
  }

  /// Handles RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange`.
  ///
  /// Validates `subject_token_type`, `subject_issuer`, parses the subject
  /// token without signature verification (this is a mock), asserts that
  /// `iss` matches the declared `subject_issuer`, then mints a fresh
  /// session tied to the subject's `sub` claim. `aud` is synthesised from
  /// the request `client_id` so callers can verify audience mapping.
  Response _handleTokenExchange(Map<String, String> form) {
    const expectedTokenType = 'urn:ietf:params:oauth:token-type:id_token';
    final subjectTokenType = form['subject_token_type'];
    if (subjectTokenType != expectedTokenType) {
      return Response(
        400,
        headers: <String, String>{'Content-Type': 'application/json'},
        body: json.encode(<String, String>{
          'error': 'invalid_request',
          'error_description':
              'subject_token_type must be $expectedTokenType',
        }),
      );
    }

    final subjectIssuer = form['subject_issuer'];
    if (subjectIssuer == null ||
        !_allowedExchangeIssuers.contains(subjectIssuer)) {
      return Response(
        400,
        headers: <String, String>{'Content-Type': 'application/json'},
        body: json.encode(<String, String>{
          'error': 'invalid_grant',
          'error_description': 'subject_issuer not in allowlist',
        }),
      );
    }

    final subjectToken = form['subject_token'];
    if (subjectToken == null || subjectToken.isEmpty) {
      return Response(
        400,
        headers: <String, String>{'Content-Type': 'application/json'},
        body: json.encode(<String, String>{
          'error': 'invalid_request',
          'error_description': 'missing subject_token',
        }),
      );
    }

    Map<String, dynamic>? claims;
    final parts = subjectToken.split('.');
    if (parts.length >= 2) {
      try {
        final decoded = json.decode(
          utf8.decode(_b64urlDecode(parts[1])),
        );
        if (decoded is Map<String, dynamic>) claims = decoded;
      } catch (_) {
        claims = null;
      }
    }
    if (claims == null) {
      return Response(
        400,
        headers: <String, String>{'Content-Type': 'application/json'},
        body: json.encode(<String, String>{
          'error': 'invalid_grant',
          'error_description': 'subject_token is not a parseable JWT',
        }),
      );
    }
    if (claims['iss'] != subjectIssuer) {
      return Response(
        400,
        headers: <String, String>{'Content-Type': 'application/json'},
        body: json.encode(<String, String>{
          'error': 'invalid_grant',
          'error_description':
              'subject_token iss does not match subject_issuer',
        }),
      );
    }

    final sub = claims['sub'] is String
        ? claims['sub'] as String
        : 'exchange-user';
    final aud = form['client_id'] ?? 'antinvestor-mobile';
    return _issueTokens(newFamily: true, sub: sub, aud: aud);
  }

  Future<Response> _revocation(Request req) async {
    final body = await req.readAsString();
    revocationRequests.add(RecordedRequest(body: body, headers: req.headers));
    return Response(204);
  }

  Future<Response> _endSession(Request req) async {
    final body =
        req.method == 'POST' ? await req.readAsString() : '';
    endSessionRequests.add(RecordedRequest(body: body, headers: req.headers));
    return Response(204);
  }
}

/// Captured state of a `/token` hit.
class RecordedTokenRequest {
  RecordedTokenRequest({
    required this.grantType,
    required this.form,
    required this.dpopHeader,
    required this.dpopClaims,
  });

  final String grantType;
  final Map<String, String> form;
  final String? dpopHeader;
  final DpopProofClaims? dpopClaims;
}

/// Minimal capture of a non-token request (revocation / end-session).
class RecordedRequest {
  RecordedRequest({required this.body, required this.headers});

  final String body;
  final Map<String, String> headers;
}

/// Parsed-but-not-verified DPoP proof payload.
class DpopProofClaims {
  DpopProofClaims({
    required this.htm,
    required this.htu,
    required this.iat,
    required this.jti,
    this.nonce,
    this.ath,
  });

  final String htm;
  final String htu;
  final int iat;
  final String jti;
  final String? nonce;
  final String? ath;
}

/// Best-effort parser: splits the JWS, base64url-decodes the payload, and
/// pulls the claims the runtime ships. Returns null on any structural
/// failure so the caller can decide how strict to be.
DpopProofClaims? _parseDpopProof(String proof) {
  final parts = proof.split('.');
  if (parts.length != 3) return null;
  try {
    final payload = json.decode(utf8.decode(_b64urlDecode(parts[1])));
    if (payload is! Map) return null;
    final htm = payload['htm'];
    final htu = payload['htu'];
    final iat = payload['iat'];
    final jti = payload['jti'];
    if (htm is! String || htu is! String || iat is! int || jti is! String) {
      return null;
    }
    return DpopProofClaims(
      htm: htm,
      htu: htu,
      iat: iat,
      jti: jti,
      nonce: payload['nonce'] is String ? payload['nonce'] as String : null,
      ath: payload['ath'] is String ? payload['ath'] as String : null,
    );
  } catch (_) {
    return null;
  }
}

List<int> _b64urlDecode(String s) {
  final padded = s.padRight((s.length + 3) & ~3, '=');
  return base64Url.decode(padded);
}

String? _headerIgnoreCase(Map<String, String> headers, String name) {
  final lower = name.toLowerCase();
  for (final e in headers.entries) {
    if (e.key.toLowerCase() == lower) return e.value;
  }
  return null;
}

String _makeUnsignedJwt(Map<String, dynamic> payload) {
  final header = base64Url
      .encode(utf8.encode(json.encode(<String, String>{'alg': 'none'})))
      .replaceAll('=', '');
  final body = base64Url
      .encode(utf8.encode(json.encode(payload)))
      .replaceAll('=', '');
  // Deliberately empty signature so this stays visibly a test fixture.
  return '$header.$body.';
}
