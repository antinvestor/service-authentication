import 'dart:async';
import 'dart:convert';

import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:http/http.dart' as http;

/// OIDC discovery document — only the fields the runtime consumes.
class OidcDiscovery {
  const OidcDiscovery({
    required this.issuer,
    required this.authorizationEndpoint,
    required this.tokenEndpoint,
    this.endSessionEndpoint,
    this.revocationEndpoint,
    this.userinfoEndpoint,
    this.jwksUri,
    this.dpopSigningAlgValuesSupported,
  });

  final String issuer;
  final String authorizationEndpoint;
  final String tokenEndpoint;
  final String? endSessionEndpoint;
  final String? revocationEndpoint;
  final String? userinfoEndpoint;
  final String? jwksUri;
  final List<String>? dpopSigningAlgValuesSupported;

  /// Parses a discovery JSON map. Returns null if a required field is
  /// missing or of the wrong type.
  static OidcDiscovery? tryFromJson(Map<String, dynamic> json) {
    final issuer = json['issuer'];
    final authz = json['authorization_endpoint'];
    final tokenEp = json['token_endpoint'];
    if (issuer is! String || authz is! String || tokenEp is! String) {
      return null;
    }
    final dpop = json['dpop_signing_alg_values_supported'];
    return OidcDiscovery(
      issuer: issuer,
      authorizationEndpoint: authz,
      tokenEndpoint: tokenEp,
      endSessionEndpoint: _asString(json['end_session_endpoint']),
      revocationEndpoint: _asString(json['revocation_endpoint']),
      userinfoEndpoint: _asString(json['userinfo_endpoint']),
      jwksUri: _asString(json['jwks_uri']),
      dpopSigningAlgValuesSupported:
          dpop is List ? dpop.whereType<String>().toList() : null,
    );
  }

  /// Throws on malformed input — use [tryFromJson] for soft parsing.
  static OidcDiscovery fromJson(Map<String, dynamic> json) {
    final d = tryFromJson(json);
    if (d == null) {
      throw const FormatException('discovery document missing required fields');
    }
    return d;
  }

  static String? _asString(Object? v) => v is String ? v : null;
}

/// Returns true iff the IdP advertises ES256 support for DPoP.
bool supportsDpop(OidcDiscovery d) =>
    (d.dpopSigningAlgValuesSupported ?? const []).contains('ES256');

final Map<String, OidcDiscovery> _cache = {};
final Map<String, Future<OidcDiscovery>> _inflight = {};

/// Visible for testing — wipes module-level cache + in-flight map.
void clearDiscoveryCache() {
  _cache.clear();
  _inflight.clear();
}

/// Fetches (and caches) the OIDC discovery document for [idpBaseUrl].
///
/// Concurrent callers for the same URL share one in-flight HTTP request.
/// Failures are NOT cached. Pass a [http.Client] (typically
/// `MockClient`) under test — production code uses `http.Client()`.
Future<OidcDiscovery> getDiscovery(
  String idpBaseUrl,
  Duration timeout, {
  http.Client? client,
}) {
  final key = _stripTrailingSlash(idpBaseUrl);
  final cached = _cache[key];
  if (cached != null) return Future.value(cached);
  final pending = _inflight[key];
  if (pending != null) return pending;

  final future = _doFetch(key, timeout, client ?? http.Client())
      .then<OidcDiscovery>((doc) {
    _cache[key] = doc;
    return doc;
  }).whenComplete(() {
    _inflight.remove(key);
  });
  _inflight[key] = future;
  return future;
}

Future<OidcDiscovery> _doFetch(
  String idp,
  Duration timeout,
  http.Client client,
) async {
  final url = Uri.parse('$idp/.well-known/openid-configuration');
  http.Response res;
  try {
    res = await client.get(url).timeout(timeout);
  } on TimeoutException catch (err) {
    throw AuthError(
      AuthErrorCode.networkTimeout,
      'discovery timeout $url',
      cause: err,
    );
  } catch (err) {
    throw AuthError(
      AuthErrorCode.discoveryFailed,
      'discovery fetch failed $url',
      cause: err,
    );
  }
  if (res.statusCode < 200 || res.statusCode >= 300) {
    throw AuthError(
      AuthErrorCode.discoveryFailed,
      'discovery HTTP ${res.statusCode} $url',
    );
  }
  Map<String, dynamic> body;
  try {
    final decoded = json.decode(res.body);
    if (decoded is! Map) {
      throw const FormatException('discovery body is not a JSON object');
    }
    body = decoded.cast<String, dynamic>();
  } catch (err) {
    throw AuthError(
      AuthErrorCode.discoveryFailed,
      'discovery non-JSON $url',
      cause: err,
    );
  }
  final parsed = OidcDiscovery.tryFromJson(body);
  if (parsed == null) {
    throw AuthError(
      AuthErrorCode.discoveryFailed,
      'discovery missing fields $url',
    );
  }
  return parsed;
}

String _stripTrailingSlash(String s) {
  var end = s.length;
  while (end > 0 && s.codeUnitAt(end - 1) == 0x2F) {
    end--;
  }
  return s.substring(0, end);
}
