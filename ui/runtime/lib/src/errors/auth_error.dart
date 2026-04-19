/// Flat error taxonomy used by the auth runtime.
///
/// Mirrors the JS `@stawi/auth-runtime` codes with mobile-specific
/// additions (see spec §4). Codes are grouped below for readability
/// but are all peers in one enum.
enum AuthErrorCode {
  invalidConfig,

  // Network / discovery
  discoveryFailed,
  networkTimeout,
  networkError,
  offline,

  // OAuth
  oauthFailed,
  oauthUserCanceled,
  oauthBrowserUnavailable,

  // Token lifecycle
  tokenExchangeFailed,
  tokenRefreshFailed,
  tokenExpired,

  // DPoP
  dpopNonceRequired,
  dpopInvalidProof,

  // Security
  refreshReuseDetected,

  // Storage / crypto
  storageCorruption,
  storageUnavailable,
  cryptoUnsupported,

  // Session invariants
  loggedOutElsewhere,
  securityWipe,

  // API surface mapping
  apiUnauthorized,
  apiForbidden,
  apiNotFound,
  apiValidation,
  apiServerError,

  // Mobile specifics
  deepLinkMismatch,
  biometricRequired,
  biometricUnavailable,
}

const Set<AuthErrorCode> _nonRetryable = {
  AuthErrorCode.invalidConfig,
  AuthErrorCode.refreshReuseDetected,
  AuthErrorCode.cryptoUnsupported,
  AuthErrorCode.deepLinkMismatch,
  AuthErrorCode.securityWipe,
};

/// Non-fatal, structured error raised throughout the runtime.
///
/// `retryable` is derived from [code] so callers can implement uniform
/// backoff/wipe policy without switching on every variant.
class AuthError extends Error {
  AuthError(
    this.code,
    this.message, {
    this.cause,
    this.traceId,
  });

  final AuthErrorCode code;
  final String message;
  final Object? cause;
  final String? traceId;

  bool get retryable => !_nonRetryable.contains(code);

  @override
  String toString() {
    final trace = traceId == null ? '' : ' (trace=$traceId)';
    return 'AuthError(${code.name}): $message$trace';
  }
}
