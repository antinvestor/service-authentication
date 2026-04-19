/// Lifecycle state of an [AuthRuntime].
///
/// Transitions are driven by the pure reducer in
/// `lib/src/runtime/state_machine.dart` (Group F-D).
enum AuthState {
  initializing,
  authenticated,
  unauthenticated,
  refreshing,
  error,
}
