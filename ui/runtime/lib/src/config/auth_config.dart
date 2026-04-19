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
        installationId,
        discoveryTimeout,
        tokenTimeout,
        apiTimeout,
        uploadTimeout,
      ];
}
