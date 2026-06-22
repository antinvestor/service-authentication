import 'package:antinvestor_auth_runtime/src/credentials/credential_event.dart';
import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';
import 'package:antinvestor_auth_runtime/src/models/api_response.dart';
import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:antinvestor_auth_runtime/src/models/security_event.dart';
import 'package:antinvestor_auth_runtime/src/models/user_claims.dart';

/// Public, isolate-agnostic contract consumed by Flutter apps.
///
/// Both the in-thread ([AuthRuntimeImpl]) and Isolate-backed variants
/// implement this interface; consumers should never depend on a concrete
/// type so they can swap between the two via `createAuthRuntime`.
abstract class AuthRuntime {
  /// Begins or resumes an authenticated session.
  ///
  /// This is the interactive sign-in entry point. On fresh installs it
  /// may open a native credential sheet or the OAuth flow in the system
  /// browser via `flutter_web_auth_2`; callers should invoke it only
  /// from an explicit user action such as a login button tap. On
  /// subsequent launches a stored refresh token short-circuits straight
  /// to the authenticated state without any browser round-trip.
  ///
  /// Completes when the runtime transitions to [AuthState.authenticated].
  /// Throws [AuthError] on any fatal failure.
  Future<void> ensureAuthenticated();

  /// Performs an authenticated HTTP call.
  ///
  /// The access token never crosses back to the caller — only status,
  /// headers, and opaque bytes in [ApiResponse]. [body] may be a `String`,
  /// a `List<int>`, or a `Stream<List<int>>` (non-multipart — use [upload]
  /// for multipart).
  Future<ApiResponse> fetch(
    String path, {
    String method = 'GET',
    Map<String, String>? headers,
    Object? body,
    Duration? timeout,
  });

  /// Multipart upload of a single file field.
  Future<ApiResponse> upload(
    String path, {
    required String fieldName,
    required String filename,
    required String contentType,
    required Stream<List<int>> bytes,
    required int length,
    Map<String, String>? headers,
    Duration? timeout,
  });

  /// Claims decoded from the current ID token. Returns `{}` when no
  /// session is active or no ID token was issued.
  Future<Map<String, dynamic>> getClaims();

  /// Typed-getter wrapper around [getClaims]. Returns an empty
  /// [UserClaims] when no session is active.
  Future<UserClaims> getUserClaims();

  /// Roles extracted from the current access token. Returns `[]` when
  /// unauthenticated. Supports both top-level `roles` and
  /// `realm_access.roles` (Hydra / Keycloak compatibility).
  Future<List<String>> getRoles();

  /// Clears local state and best-effort server logout (`end_session` +
  /// `revocation`). Network failures do not block the local wipe.
  Future<void> logout();

  /// Stream of auth state transitions. Never errors — see
  /// [securityEventStream] for fatal signals instead.
  Stream<AuthState> get authStateStream;

  /// Stream of security-relevant events (refresh reuse detected, storage
  /// corruption, logged-out-elsewhere, …). Callers should surface these
  /// prominently — see `AuthEventListener` for a ready-made widget.
  Stream<SecurityEvent> get securityEventStream;

  /// Synchronous snapshot of [authStateStream]'s latest value.
  AuthState get state;

  /// Synchronous convenience for `state == AuthState.authenticated`.
  ///
  /// Useful in background-task contexts (e.g. Android WorkManager callbacks)
  /// where the caller wants to bail out early without spinning up the
  /// runtime's async surface.
  bool get isAuthenticated;

  /// Set of native credential providers advertised as currently available
  /// on this platform. Callers use this to decide whether to render a
  /// "Continue with Apple/Google" button. This probe is passive and must
  /// not open native credential UI.
  Future<Set<NativeCredentialProviderKind>> availableNativeProviders();

  /// Fine-grained stream of native-credential lifecycle events (probe,
  /// interactive attempt, outcome, sign-out). Independent of
  /// [authStateStream] — useful for telemetry and debug UIs.
  Stream<CredentialEvent> get credentialEventStream;

  /// Warms the OIDC discovery cache. Optional — but reduces perceived
  /// latency on the first sign-in when called from app startup.
  Future<void> prefetchDiscovery();

  /// Build-time version string. Surfaced for telemetry + support flows.
  String get version;

  /// Tears down isolates, stream controllers, and secure-storage handles.
  /// Idempotent — safe to call multiple times.
  Future<void> dispose();
}

/// Version of the runtime. Callers include this in telemetry / bug
/// reports. Kept as a bare constant for now; wired through
/// `--dart-define=AUTH_RUNTIME_VERSION=...` in a follow-up task.
const String authRuntimeVersion = '0.4.4';
