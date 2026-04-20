import 'package:equatable/equatable.dart';

/// Configuration for the auth runtime. Immutable value.
///
/// Fields are deliberately permissive so callers can pass raw values
/// (trailing slashes, omitted timeouts) — [resolveConfig] normalizes
/// them into a [ResolvedConfig].
class AuthConfig extends Equatable {
  const AuthConfig({
    required this.clientId,
    required this.idpBaseUrl,
    required this.apiBaseUrl,
    required this.redirectScheme,
    this.scopes,
    this.audiences,
    this.redirectUri,
    this.installationId,
    this.discoveryTimeout,
    this.tokenTimeout,
    this.apiTimeout,
    this.uploadTimeout,
  });

  final String clientId;
  final String idpBaseUrl;
  final String apiBaseUrl;
  final String redirectScheme;
  final List<String>? scopes;

  /// Optional resource audience hints passed to the authorize endpoint via
  /// `audience=<comma-joined>`. Hydra accepts comma-separated values per
  /// its docs. Omit when null (default).
  final List<String>? audiences;

  /// Explicit redirect URI; takes precedence over [redirectScheme] when
  /// set. Use for desktop loopback (`http://localhost:5173/auth`) or when
  /// a specific URI is required by the IdP.
  final String? redirectUri;

  final String? installationId;
  final Duration? discoveryTimeout;
  final Duration? tokenTimeout;
  final Duration? apiTimeout;
  final Duration? uploadTimeout;

  @override
  List<Object?> get props => [
        clientId,
        idpBaseUrl,
        apiBaseUrl,
        redirectScheme,
        scopes,
        audiences,
        redirectUri,
        installationId,
        discoveryTimeout,
        tokenTimeout,
        apiTimeout,
        uploadTimeout,
      ];
}
