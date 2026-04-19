import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('AuthState enum exposes all expected variants', () {
    expect(AuthState.values, containsAll(const [
      AuthState.initializing,
      AuthState.authenticated,
      AuthState.unauthenticated,
      AuthState.refreshing,
      AuthState.error,
    ]));
    expect(AuthState.values.length, 5);
  });
}
