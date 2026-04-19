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
  testWidgets('renders default "Sign out" label', (tester) async {
    final fake = FakeAuthRuntime();
    addTearDown(fake.dispose);
    await tester.pumpWidget(_wrap(fake, child: const SignOutButton()));
    expect(find.text('Sign out'), findsOneWidget);
  });

  testWidgets('tap triggers logout and onSignedOut callback', (tester) async {
    final fake = FakeAuthRuntime(initialState: AuthState.authenticated);
    addTearDown(fake.dispose);
    var done = 0;
    await tester.pumpWidget(_wrap(
      fake,
      child: SignOutButton(onSignedOut: () => done++),
    ));
    await tester.tap(find.byType(TextButton));
    await tester.pumpAndSettle();
    expect(fake.logoutCalls, 1);
    expect(done, 1);
  });

  testWidgets('custom label is honoured', (tester) async {
    final fake = FakeAuthRuntime();
    addTearDown(fake.dispose);
    await tester.pumpWidget(_wrap(
      fake,
      child: const SignOutButton(label: 'Log out'),
    ));
    expect(find.text('Log out'), findsOneWidget);
  });
}
