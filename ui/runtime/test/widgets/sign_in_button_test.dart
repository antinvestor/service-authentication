import 'dart:async';

import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/fake_auth_runtime.dart';

Widget _wrap(FakeAuthRuntime fake, {required Widget child}) {
  return ProviderScope(
    overrides: [authRuntimeProvider.overrideWithValue(fake)],
    child: MaterialApp(home: Scaffold(body: Center(child: child))),
  );
}

void main() {
  testWidgets('renders default label and is enabled', (tester) async {
    final fake = FakeAuthRuntime();
    addTearDown(fake.dispose);
    await tester.pumpWidget(_wrap(fake, child: const SignInButton()));
    expect(find.text('Sign in'), findsOneWidget);
    final button = tester.widget<ElevatedButton>(find.byType(ElevatedButton));
    expect(button.onPressed, isNotNull);
  });

  testWidgets('custom label is honoured', (tester) async {
    final fake = FakeAuthRuntime();
    addTearDown(fake.dispose);
    await tester.pumpWidget(
      _wrap(fake, child: const SignInButton(label: 'Log in')),
    );
    expect(find.text('Log in'), findsOneWidget);
  });

  testWidgets('tap triggers ensureAuthenticated and onAuthenticated callback',
      (tester) async {
    final fake = FakeAuthRuntime();
    addTearDown(fake.dispose);
    var done = 0;
    await tester.pumpWidget(_wrap(
      fake,
      child: SignInButton(onAuthenticated: () => done++),
    ));
    await tester.tap(find.byType(ElevatedButton));
    await tester.pumpAndSettle();
    expect(fake.ensureAuthenticatedCalls, 1);
    expect(done, 1);
  });

  testWidgets('button disables itself while ensureAuthenticated is pending',
      (tester) async {
    final fake = FakeAuthRuntime();
    addTearDown(fake.dispose);
    final completer = FakeSlowFuture();
    fake.ensureAuthenticatedError = null;
    // Wrap in a thin shim: override ensureAuthenticated to stall on a
    // Completer so we can catch the "pending" frame.
    final slowFake = _SlowSignInFake(completer);
    addTearDown(slowFake.dispose);
    await tester.pumpWidget(_wrap(slowFake, child: const SignInButton()));
    await tester.tap(find.byType(ElevatedButton));
    await tester.pump();
    // Now pending: button should be disabled and show a progress spinner.
    final pressed =
        tester.widget<ElevatedButton>(find.byType(ElevatedButton));
    expect(pressed.onPressed, isNull);
    expect(find.byType(CircularProgressIndicator), findsOneWidget);
    completer.complete();
    await tester.pumpAndSettle();
  });

  testWidgets('onError fires and suppresses the exception', (tester) async {
    final fake = FakeAuthRuntime();
    addTearDown(fake.dispose);
    fake.ensureAuthenticatedError = AuthError(
      AuthErrorCode.oauthFailed,
      'nope',
    );
    AuthError? caught;
    await tester.pumpWidget(_wrap(
      fake,
      child: SignInButton(onError: (err) => caught = err),
    ));
    await tester.tap(find.byType(ElevatedButton));
    await tester.pumpAndSettle();
    expect(caught, isNotNull);
    expect(caught!.code, AuthErrorCode.oauthFailed);
    expect(tester.takeException(), isNull);
  });
}

class FakeSlowFuture {
  final _completer = Completer<void>();
  Future<void> get future => _completer.future;
  void complete() => _completer.complete();
}

class _SlowSignInFake extends FakeAuthRuntime {
  _SlowSignInFake(this.signal);
  final FakeSlowFuture signal;
  @override
  Future<void> ensureAuthenticated() async {
    ensureAuthenticatedCalls++;
    await signal.future;
    emitState(AuthState.authenticated);
  }
}
