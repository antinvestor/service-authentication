import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';

/// Runtime-level signal surfaced on [AuthRuntime.credentialEventStream].
///
/// Lets apps observe the native-credential waterfall (probe → silent
/// attempt → interactive attempt → outcome → sign-out) for telemetry and
/// lifecycle hooks, independent of the coarser [AuthState] stream.
sealed class CredentialEvent {
  const CredentialEvent();

  const factory CredentialEvent.probe({
    required NativeCredentialProviderKind kind,
    required bool available,
  }) = CredentialProbeEvent;

  const factory CredentialEvent.silentAttempt(
    NativeCredentialProviderKind kind,
  ) = CredentialSilentAttemptEvent;

  const factory CredentialEvent.interactiveAttempt(
    NativeCredentialProviderKind kind,
  ) = CredentialInteractiveAttemptEvent;

  const factory CredentialEvent.outcome(
    NativeCredentialProviderKind kind,
    NativeCredentialOutcome outcome,
  ) = CredentialOutcomeEvent;

  const factory CredentialEvent.signOut(
    NativeCredentialProviderKind kind,
  ) = CredentialSignOutEvent;

  /// Which provider this event concerns.
  NativeCredentialProviderKind get kind;
}

final class CredentialProbeEvent extends CredentialEvent {
  const CredentialProbeEvent({required this.kind, required this.available});

  @override
  final NativeCredentialProviderKind kind;
  final bool available;
}

final class CredentialSilentAttemptEvent extends CredentialEvent {
  const CredentialSilentAttemptEvent(this.kind);

  @override
  final NativeCredentialProviderKind kind;
}

final class CredentialInteractiveAttemptEvent extends CredentialEvent {
  const CredentialInteractiveAttemptEvent(this.kind);

  @override
  final NativeCredentialProviderKind kind;
}

final class CredentialOutcomeEvent extends CredentialEvent {
  const CredentialOutcomeEvent(this.kind, this.outcome);

  @override
  final NativeCredentialProviderKind kind;
  final NativeCredentialOutcome outcome;
}

final class CredentialSignOutEvent extends CredentialEvent {
  const CredentialSignOutEvent(this.kind);

  @override
  final NativeCredentialProviderKind kind;
}
