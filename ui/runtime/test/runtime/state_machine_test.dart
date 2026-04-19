import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:antinvestor_auth_runtime/src/runtime/state_machine.dart';
import 'package:flutter_test/flutter_test.dart';

final _dummyError =
    AuthError(AuthErrorCode.tokenRefreshFailed, 'test');

void main() {
  group('initializing', () {
    test('init_done hasTokens=true -> authenticated', () {
      expect(
        reduce(AuthState.initializing, const StateInput.initDone(hasTokens: true)),
        AuthState.authenticated,
      );
    });

    test('init_done hasTokens=false -> unauthenticated', () {
      expect(
        reduce(AuthState.initializing,
            const StateInput.initDone(hasTokens: false)),
        AuthState.unauthenticated,
      );
    });

    test('sign_in_done -> authenticated', () {
      expect(reduce(AuthState.initializing, const StateInput.signInDone()),
          AuthState.authenticated);
    });

    test('sign_in_fail -> unauthenticated', () {
      expect(reduce(AuthState.initializing, StateInput.signInFail(_dummyError)),
          AuthState.unauthenticated);
    });

    test('unrelated input is a no-op', () {
      expect(reduce(AuthState.initializing, const StateInput.refreshDone()),
          AuthState.initializing);
    });
  });

  group('unauthenticated', () {
    test('sign_in_start -> initializing', () {
      expect(reduce(AuthState.unauthenticated, const StateInput.signInStart()),
          AuthState.initializing);
    });

    test('logout is a no-op', () {
      expect(reduce(AuthState.unauthenticated, const StateInput.logout()),
          AuthState.unauthenticated);
    });

    test('refresh_start is a no-op (guards against races)', () {
      expect(reduce(AuthState.unauthenticated, const StateInput.refreshStart()),
          AuthState.unauthenticated);
    });
  });

  group('authenticated', () {
    test('refresh_start -> refreshing', () {
      expect(reduce(AuthState.authenticated, const StateInput.refreshStart()),
          AuthState.refreshing);
    });

    test('logout -> unauthenticated', () {
      expect(reduce(AuthState.authenticated, const StateInput.logout()),
          AuthState.unauthenticated);
    });

    test('sign_in_done is a no-op', () {
      expect(reduce(AuthState.authenticated, const StateInput.signInDone()),
          AuthState.authenticated);
    });
  });

  group('refreshing', () {
    test('refresh_done -> authenticated', () {
      expect(reduce(AuthState.refreshing, const StateInput.refreshDone()),
          AuthState.authenticated);
    });

    test('refresh_fail without wipe -> unauthenticated', () {
      expect(
        reduce(
          AuthState.refreshing,
          StateInput.refreshFail(error: _dummyError, wipe: false),
        ),
        AuthState.unauthenticated,
      );
    });

    test('refresh_fail with wipe -> unauthenticated', () {
      expect(
        reduce(
          AuthState.refreshing,
          StateInput.refreshFail(error: _dummyError, wipe: true),
        ),
        AuthState.unauthenticated,
      );
    });

    test('logout mid-refresh -> unauthenticated', () {
      expect(reduce(AuthState.refreshing, const StateInput.logout()),
          AuthState.unauthenticated);
    });
  });

  group('security_wipe', () {
    test('from initializing -> unauthenticated', () {
      expect(
          reduce(AuthState.initializing, const StateInput.securityWipe('r')),
          AuthState.unauthenticated);
    });

    test('from authenticated -> unauthenticated', () {
      expect(reduce(AuthState.authenticated, const StateInput.securityWipe('r')),
          AuthState.unauthenticated);
    });

    test('from refreshing -> unauthenticated', () {
      expect(reduce(AuthState.refreshing, const StateInput.securityWipe('r')),
          AuthState.unauthenticated);
    });

    test('from unauthenticated -> unauthenticated', () {
      expect(
          reduce(AuthState.unauthenticated, const StateInput.securityWipe('r')),
          AuthState.unauthenticated);
    });

    test('from error -> unauthenticated', () {
      expect(reduce(AuthState.error, const StateInput.securityWipe('r')),
          AuthState.unauthenticated);
    });
  });

  group('error', () {
    test('sign_in_start -> initializing', () {
      expect(reduce(AuthState.error, const StateInput.signInStart()),
          AuthState.initializing);
    });

    test('refresh_done is a no-op', () {
      expect(reduce(AuthState.error, const StateInput.refreshDone()),
          AuthState.error);
    });
  });
}
