import 'package:antinvestor_auth_runtime/src/config/auth_config.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';

/// Default OAuth scopes requested when caller supplies none.
///
/// Mirrors the JS runtime — `offline_access` is required for refresh
/// token issuance under our Hydra setup.
const List<String> defaultScopes = [
  'openid',
  'profile',
  'email',
  'offline_access',
];

const Duration _defaultDiscoveryTimeout = Duration(seconds: 10);
const Duration _defaultTokenTimeout = Duration(seconds: 10);
const Duration _defaultApiTimeout = Duration(seconds: 30);
const Duration _defaultUploadTimeout = Duration(seconds: 60);

/// Fully-resolved, normalized configuration.
///
/// Unlike [AuthConfig], every field has a concrete value. URLs are
/// trimmed of trailing slashes so that paths we concatenate don't
/// double-slash.
class ResolvedConfig {
  const ResolvedConfig({
    required this.clientId,
    required this.idpBaseUrl,
    required this.apiBaseUrl,
    required this.redirectScheme,
    required this.scopes,
    required this.audiences,
    required this.installationId,
    required this.discoveryTimeout,
    required this.tokenTimeout,
    required this.apiTimeout,
    required this.uploadTimeout,
  });

  final String clientId;
  final String idpBaseUrl;
  final String apiBaseUrl;
  final String redirectScheme;
  final List<String> scopes;

  /// Resource audience hints forwarded to the IdP's authorize and
  /// token-exchange endpoints as a comma-joined `audience` parameter.
  /// Defaults to an empty list when the caller omits [AuthConfig.audiences].
  final List<String> audiences;

  final String? installationId;
  final Duration discoveryTimeout;
  final Duration tokenTimeout;
  final Duration apiTimeout;
  final Duration uploadTimeout;

  /// `"{clientId}::{idpBaseUrl}"` — cache and storage key suffix.
  String get namespace => '$clientId::$idpBaseUrl';

  /// Convention-driven redirect URI: `{scheme}://callback`.
  String get redirectUri => '$redirectScheme://callback';
}

/// Normalizes an [AuthConfig] into a fully-populated [ResolvedConfig].
///
/// Throws `AuthError(invalidConfig)` if any required string is blank.
ResolvedConfig resolveConfig(AuthConfig cfg) {
  if (cfg.clientId.isEmpty) {
    throw AuthError(AuthErrorCode.invalidConfig, 'clientId is required');
  }
  if (cfg.idpBaseUrl.isEmpty) {
    throw AuthError(AuthErrorCode.invalidConfig, 'idpBaseUrl is required');
  }
  if (cfg.apiBaseUrl.isEmpty) {
    throw AuthError(AuthErrorCode.invalidConfig, 'apiBaseUrl is required');
  }
  if (cfg.redirectScheme.isEmpty) {
    throw AuthError(AuthErrorCode.invalidConfig, 'redirectScheme is required');
  }

  return ResolvedConfig(
    clientId: cfg.clientId,
    idpBaseUrl: _stripTrailingSlash(cfg.idpBaseUrl),
    apiBaseUrl: _stripTrailingSlash(cfg.apiBaseUrl),
    redirectScheme: cfg.redirectScheme,
    scopes: List<String>.unmodifiable(cfg.scopes ?? defaultScopes),
    audiences: List<String>.unmodifiable(cfg.audiences ?? const <String>[]),
    installationId: cfg.installationId,
    discoveryTimeout: cfg.discoveryTimeout ?? _defaultDiscoveryTimeout,
    tokenTimeout: cfg.tokenTimeout ?? _defaultTokenTimeout,
    apiTimeout: cfg.apiTimeout ?? _defaultApiTimeout,
    uploadTimeout: cfg.uploadTimeout ?? _defaultUploadTimeout,
  );
}

String _stripTrailingSlash(String s) {
  var end = s.length;
  while (end > 0 && s.codeUnitAt(end - 1) == 0x2F /* '/' */) {
    end--;
  }
  return s.substring(0, end);
}
