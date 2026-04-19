/// Security signals emitted by the runtime.
///
/// Sealed hierarchy rather than enum so callers can exhaustively switch
/// while remaining forward-compatible with future variants.
sealed class SecurityEvent {
  const SecurityEvent(this.at);

  final DateTime at;

  // ignore: prefer_const_constructors_in_immutables
  factory SecurityEvent.refreshReuseDetected(DateTime at) =
      RefreshReuseDetected;
  // ignore: prefer_const_constructors_in_immutables
  factory SecurityEvent.storageCorruption(DateTime at) = StorageCorruption;
  // ignore: prefer_const_constructors_in_immutables
  factory SecurityEvent.bindingInvalidated(DateTime at) = BindingInvalidated;
  // ignore: prefer_const_constructors_in_immutables
  factory SecurityEvent.loggedOutElsewhere(DateTime at) = LoggedOutElsewhere;

  @override
  bool operator ==(Object other) =>
      other.runtimeType == runtimeType &&
      other is SecurityEvent &&
      other.at == at;

  @override
  int get hashCode => Object.hash(runtimeType, at);

  @override
  String toString() => '$runtimeType(at=$at)';
}

final class RefreshReuseDetected extends SecurityEvent {
  const RefreshReuseDetected(super.at);
}

final class StorageCorruption extends SecurityEvent {
  const StorageCorruption(super.at);
}

final class BindingInvalidated extends SecurityEvent {
  const BindingInvalidated(super.at);
}

final class LoggedOutElsewhere extends SecurityEvent {
  const LoggedOutElsewhere(super.at);
}
