import 'dart:async';
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/models/api_response.dart';
import 'package:antinvestor_auth_runtime/src/models/token_set.dart';
import 'package:antinvestor_auth_runtime/src/protocol/dpop.dart';
import 'package:http/http.dart' as http;
import 'package:http_parser/http_parser.dart' show MediaType;

/// Snapshot returned by [TokenProvider.ensureFresh].
class TokenSnapshot {
  const TokenSnapshot({
    required this.accessToken,
    required this.tokenType,
  });

  final String accessToken;
  final TokenType tokenType;
}

/// Interface implemented by the runtime's session-holder.
///
/// The proxy never sees the full [TokenSet] — only the access token and
/// type. `onRefresh` is fired once per forced refresh so the runtime
/// can emit telemetry.
abstract class TokenProvider {
  Future<TokenSnapshot> ensureFresh({bool force = false});

  void onRefresh();
}

/// Authenticated HTTP client wrapper for JS parity.
///
/// Behaviour matches `@stawi/auth-runtime`'s `api-proxy.ts`:
/// 1. Attach `Authorization: Bearer <token>` or `DPoP <token>` + `DPoP`
///    proof header depending on [TokenSnapshot.tokenType].
/// 2. On 401 with `DPoP-Nonce`, retry once using the refreshed nonce.
/// 3. On persistent 401, force a token refresh and retry once.
/// 4. Map HTTP status to `AuthError(apiXxx)` codes on failure.
class ApiProxy {
  ApiProxy({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;

  /// Performs an authenticated HTTP call. Returns an [ApiResponse] on
  /// success; throws [AuthError] otherwise.
  Future<ApiResponse> fetch(
    ResolvedConfig cfg,
    DpopContext ctx,
    TokenProvider tp, {
    required String path,
    required String method,
    Map<String, String>? headers,
    Object? body,
    Duration? timeout,
  }) async {
    final url = '${cfg.apiBaseUrl}$path';
    final uri = Uri.parse(url);
    final effectiveTimeout = timeout ?? cfg.apiTimeout;
    final methodUpper = method.toUpperCase();

    Future<http.Response> doCall(TokenSnapshot snapshot) async {
      final h = <String, String>{...?headers};
      h['Authorization'] = '${snapshot.tokenType.headerValue} '
          '${snapshot.accessToken}';
      h.putIfAbsent('Accept', () => 'application/json');
      if (snapshot.tokenType == TokenType.dpop) {
        h['DPoP'] = await buildProof(
          ctx,
          htm: methodUpper,
          htu: url,
          accessToken: snapshot.accessToken,
        );
      }
      if (body is String && !_hasContentType(h)) {
        h['Content-Type'] = 'application/json';
      }
      final bodyBytes = _normalizeBody(body);
      return _sendRequest(
        method: methodUpper,
        uri: uri,
        headers: h,
        body: bodyBytes,
        timeout: effectiveTimeout,
      );
    }

    try {
      final initial = await tp.ensureFresh();
      var res = await doCall(initial);
      rememberNonce(ctx, url, res.headers);

      if (res.statusCode == 401 &&
          _headerIgnoreCase(res.headers, 'dpop-nonce') != null) {
        res = await doCall(initial);
        rememberNonce(ctx, url, res.headers);
      }

      if (res.statusCode == 401) {
        final fresh = await tp.ensureFresh(force: true);
        tp.onRefresh();
        res = await doCall(fresh);
        rememberNonce(ctx, url, res.headers);
      }

      return _mapResponse(res);
    } on TimeoutException catch (err) {
      throw AuthError(
        AuthErrorCode.networkTimeout,
        'API timeout $url',
        cause: err,
      );
    } on AuthError {
      rethrow;
    } catch (err) {
      throw AuthError(
        AuthErrorCode.networkError,
        'API network error $url',
        cause: err,
      );
    }
  }

  /// Performs an authenticated multipart upload. Returns the same
  /// [ApiResponse] contract as [fetch].
  Future<ApiResponse> upload(
    ResolvedConfig cfg,
    DpopContext ctx,
    TokenProvider tp, {
    required String path,
    required String fieldName,
    required String filename,
    required String contentType,
    required Stream<List<int>> bytes,
    required int length,
    Map<String, String>? headers,
    Duration? timeout,
  }) async {
    final url = '${cfg.apiBaseUrl}$path';
    final uri = Uri.parse(url);
    final effectiveTimeout = timeout ?? cfg.uploadTimeout;

    // A stream can only be consumed once; buffer into memory so we can
    // retry on 401. Production callers that need to avoid buffering
    // large files should retry at a higher layer.
    final buffered = await _drain(bytes, length);

    Future<http.StreamedResponse> doCall(TokenSnapshot snapshot) async {
      final req = http.MultipartRequest('POST', uri);
      req.headers.addAll(headers ?? const {});
      req.headers['Authorization'] = '${snapshot.tokenType.headerValue} '
          '${snapshot.accessToken}';
      if (snapshot.tokenType == TokenType.dpop) {
        req.headers['DPoP'] = await buildProof(
          ctx,
          htm: 'POST',
          htu: url,
          accessToken: snapshot.accessToken,
        );
      }
      req.files.add(http.MultipartFile.fromBytes(
        fieldName,
        buffered,
        filename: filename,
        contentType: _parseMediaType(contentType),
      ));
      return _client.send(req).timeout(effectiveTimeout);
    }

    try {
      final initial = await tp.ensureFresh();
      var streamed = await doCall(initial);
      if (streamed.statusCode == 401) {
        final fresh = await tp.ensureFresh(force: true);
        tp.onRefresh();
        streamed = await doCall(fresh);
      }
      final res = await http.Response.fromStream(streamed);
      rememberNonce(ctx, url, res.headers);
      return _mapResponse(res);
    } on TimeoutException catch (err) {
      throw AuthError(
        AuthErrorCode.networkTimeout,
        'upload timeout $url',
        cause: err,
      );
    } on AuthError {
      rethrow;
    } catch (err) {
      throw AuthError(
        AuthErrorCode.networkError,
        'upload network error $url',
        cause: err,
      );
    }
  }

  Future<http.Response> _sendRequest({
    required String method,
    required Uri uri,
    required Map<String, String> headers,
    required List<int>? body,
    required Duration timeout,
  }) {
    switch (method) {
      case 'GET':
        return _client.get(uri, headers: headers).timeout(timeout);
      case 'DELETE':
        return _client.delete(uri, headers: headers, body: body).timeout(timeout);
      case 'HEAD':
        return _client.head(uri, headers: headers).timeout(timeout);
      case 'POST':
        return _client.post(uri, headers: headers, body: body).timeout(timeout);
      case 'PUT':
        return _client.put(uri, headers: headers, body: body).timeout(timeout);
      case 'PATCH':
        return _client
            .patch(uri, headers: headers, body: body)
            .timeout(timeout);
      default:
        final req = http.Request(method, uri);
        req.headers.addAll(headers);
        if (body != null) req.bodyBytes = Uint8List.fromList(body);
        return _client
            .send(req)
            .timeout(timeout)
            .then(http.Response.fromStream);
    }
  }

  ApiResponse _mapResponse(http.Response res) {
    if (res.statusCode == 204) {
      return ApiResponse(
        status: 204,
        headers: res.headers,
        body: Uint8List(0),
      );
    }
    if (res.statusCode >= 200 && res.statusCode < 300) {
      return ApiResponse(
        status: res.statusCode,
        headers: res.headers,
        body: Uint8List.fromList(res.bodyBytes),
      );
    }
    final code = _mapErrorCode(res.statusCode);
    throw AuthError(
      code,
      'API ${res.statusCode}: ${_truncate(res.body)}',
      traceId: _headerIgnoreCase(res.headers, 'x-trace-id'),
    );
  }

  AuthErrorCode _mapErrorCode(int status) {
    if (status == 401) return AuthErrorCode.apiUnauthorized;
    if (status == 403) return AuthErrorCode.apiForbidden;
    if (status == 404) return AuthErrorCode.apiNotFound;
    if (status >= 500) return AuthErrorCode.apiServerError;
    return AuthErrorCode.apiValidation;
  }
}

Future<Uint8List> _drain(Stream<List<int>> stream, int length) async {
  final out = Uint8List(length);
  var offset = 0;
  await for (final chunk in stream) {
    if (offset + chunk.length > length) {
      throw AuthError(
        AuthErrorCode.apiValidation,
        'upload stream exceeded declared length',
      );
    }
    out.setRange(offset, offset + chunk.length, chunk);
    offset += chunk.length;
  }
  if (offset != length) {
    throw AuthError(
      AuthErrorCode.apiValidation,
      'upload stream shorter than declared length',
    );
  }
  return out;
}

List<int>? _normalizeBody(Object? body) {
  if (body == null) return null;
  if (body is String) return utf8.encode(body);
  if (body is List<int>) return body;
  if (body is Uint8List) return body;
  throw AuthError(
    AuthErrorCode.apiValidation,
    'unsupported body type: ${body.runtimeType}',
  );
}

bool _hasContentType(Map<String, String> headers) {
  for (final key in headers.keys) {
    if (key.toLowerCase() == 'content-type') return true;
  }
  return false;
}

String? _headerIgnoreCase(Map<String, String> headers, String name) {
  final lower = name.toLowerCase();
  for (final e in headers.entries) {
    if (e.key.toLowerCase() == lower) return e.value;
  }
  return null;
}

String _truncate(String s) => s.length > 200 ? s.substring(0, 200) : s;

MediaType? _parseMediaType(String raw) {
  try {
    return MediaType.parse(raw);
  } catch (_) {
    return null;
  }
}
