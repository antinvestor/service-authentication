/// Auth runtime for Antinvestor Flutter apps.
///
/// Implements the Stawi auth protocol (OAuth2 + PKCE, adaptive DPoP,
/// rotating refresh tokens with reuse detection) with isolate-isolated
/// tokens, hardware-backed storage, Riverpod providers and Material
/// widgets.
library;

export 'src/auth_runtime.dart' show AuthRuntime, authRuntimeVersion;
export 'src/config/auth_config.dart' show AuthConfig;
export 'src/credentials/apple_credential_provider.dart'
    show AppleCredentialProvider, SignInWithAppleAdapter;
export 'src/credentials/credential_event.dart'
    show
        CredentialEvent,
        CredentialInteractiveAttemptEvent,
        CredentialOutcomeEvent,
        CredentialProbeEvent,
        CredentialSignOutEvent,
        CredentialSilentAttemptEvent;
export 'src/credentials/google_credential_provider.dart'
    show GoogleCredentialProvider, GoogleSignInAdapter;
export 'src/credentials/native_credential_config.dart'
    show NativeCredentialConfig;
export 'src/credentials/native_credential.dart'
    show
        Cancelled,
        ErrorOutcome,
        NativeCredentialOutcome,
        NativeCredentialProvider,
        NativeCredentialProviderKind,
        NativeCredentialResult,
        NoSession,
        Ok,
        Unavailable;
export 'src/errors/auth_error.dart' show AuthError, AuthErrorCode;
export 'src/factory.dart' show createAuthRuntime;
export 'src/models/api_response.dart' show ApiResponse;
export 'src/models/auth_state.dart' show AuthState;
export 'src/models/security_event.dart'
    show
        BindingInvalidated,
        LoggedOutElsewhere,
        RefreshReuseDetected,
        SecurityEvent,
        StorageCorruption;
export 'src/models/token_set.dart' show TokenSet, TokenType;
export 'src/models/user_claims.dart' show UserClaims;
export 'src/providers/auth_providers.dart'
    show
        authNativeProvidersProvider,
        authRuntimeProvider,
        authStateProvider,
        isAuthenticatedProvider,
        rolesProvider,
        securityEventsProvider,
        userClaimsProvider;
export 'src/providers/auth_runtime_scope.dart' show AuthRuntimeScope;
export 'src/widgets/auth_event_listener.dart' show AuthEventListener;
export 'src/widgets/auth_gate.dart' show AuthGate;
export 'src/widgets/auth_state_builder.dart' show AuthStateBuilder;
export 'src/widgets/profile_avatar.dart' show ProfileAvatar;
export 'src/widgets/sign_in_button.dart' show SignInButton;
export 'src/widgets/sign_out_button.dart' show SignOutButton;
