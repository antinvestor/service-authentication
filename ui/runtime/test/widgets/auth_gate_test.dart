import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/fake_auth_runtime.dart';

Widget _wrap(FakeAuthRuntime fake, {required Widget child}) {
  return ProviderScope(
    overrides: [authRuntimeProvider.overrideWithValue(fake)],
    child: MaterialApp(home: Scaffold(body: child)),
  );
}

void main() {
  testWidgets('shows loading while the stream is resolving', (tester) async {
    final fake = FakeAuthRuntime(initialState: AuthState.initializing);
    addTearDown(fake.dispose);

    await tester.pumpWidget(_wrap(
      fake,
      child: const AuthGate(
        child: Text('protected'),
      ),
    ));
    // Pre-first-event: stream is loading → default spinner shows.
    expect(find.byType(CircularProgressIndicator), findsOneWidget);
    expect(find.text('protected'), findsNothing);
  });

  testWidgets('shows child when authenticated', (tester) async {
    final fake = FakeAuthRuntime(initialState: AuthState.unauthenticated);
    addTearDown(fake.dispose);

    await tester.pumpWidget(_wrap(
      fake,
      child: const AuthGate(child: Text('protected')),
    ));
    fake.emitState(AuthState.authenticated);
    await tester.pump();
    expect(find.text('protected'), findsOneWidget);
  });

  testWidgets(
      'default unauthenticatedBuilder renders an ElevatedButton with '
      '"Sign in"', (tester) async {
    final fake = FakeAuthRuntime(initialState: AuthState.unauthenticated);
    addTearDown(fake.dispose);

    await tester.pumpWidget(_wrap(
      fake,
      child: const AuthGate(child: Text('protected')),
    ));
    fake.emitState(AuthState.unauthenticated);
    await tester.pump();
    expect(find.text('Sign in'), findsOneWidget);
    expect(find.byType(ElevatedButton), findsOneWidget);
  });

  testWidgets(
      'tapping the default Sign in button invokes ensureAuthenticated',
      (tester) async {
    final fake = FakeAuthRuntime(initialState: AuthState.unauthenticated);
    addTearDown(fake.dispose);

    await tester.pumpWidget(_wrap(
      fake,
      child: const AuthGate(child: Text('protected')),
    ));
    fake.emitState(AuthState.unauthenticated);
    await tester.pump();
    await tester.tap(find.byType(ElevatedButton));
    await tester.pumpAndSettle();
    expect(fake.ensureAuthenticatedCalls, 1);
    // ensureAuthenticated drives the state to authenticated.
    expect(find.text('protected'), findsOneWidget);
  });

  testWidgets('custom unauthenticatedBuilder is honoured', (tester) async {
    final fake = FakeAuthRuntime(initialState: AuthState.unauthenticated);
    addTearDown(fake.dispose);

    await tester.pumpWidget(_wrap(
      fake,
      child: AuthGate(
        unauthenticatedBuilder: (_) => const Text('custom-login'),
        child: const Text('protected'),
      ),
    ));
    fake.emitState(AuthState.unauthenticated);
    await tester.pump();
    expect(find.text('custom-login'), findsOneWidget);
    expect(find.text('Sign in'), findsNothing);
  });

  testWidgets('custom loadingBuilder is honoured', (tester) async {
    final fake = FakeAuthRuntime(initialState: AuthState.initializing);
    addTearDown(fake.dispose);

    await tester.pumpWidget(_wrap(
      fake,
      child: AuthGate(
        loadingBuilder: (_) => const Text('booting…'),
        child: const Text('protected'),
      ),
    ));
    expect(find.text('booting…'), findsOneWidget);
  });

  testWidgets('refreshing state uses the loading builder', (tester) async {
    final fake = FakeAuthRuntime(initialState: AuthState.authenticated);
    addTearDown(fake.dispose);

    await tester.pumpWidget(_wrap(
      fake,
      child: const AuthGate(child: Text('protected')),
    ));
    fake.emitState(AuthState.authenticated);
    await tester.pump();
    expect(find.text('protected'), findsOneWidget);

    fake.emitState(AuthState.refreshing);
    await tester.pump();
    expect(find.byType(CircularProgressIndicator), findsOneWidget);
    expect(find.text('protected'), findsNothing);
  });

  testWidgets('error state renders the default error UI with retry',
      (tester) async {
    final fake = FakeAuthRuntime(initialState: AuthState.error);
    addTearDown(fake.dispose);

    await tester.pumpWidget(_wrap(
      fake,
      child: const AuthGate(child: Text('protected')),
    ));
    fake.emitState(AuthState.error);
    await tester.pump();
    expect(find.text('Retry'), findsOneWidget);
  });
}
