import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/fake_auth_runtime.dart';

Widget _wrap(FakeAuthRuntime fake, {required Widget child}) {
  return ProviderScope(
    overrides: [authRuntimeProvider.overrideWithValue(fake)],
    child: MaterialApp(
      home: Scaffold(body: child),
    ),
  );
}

void main() {
  testWidgets('renders child as-is', (tester) async {
    final fake = FakeAuthRuntime();
    addTearDown(fake.dispose);
    await tester.pumpWidget(_wrap(
      fake,
      child: const AuthEventListener(child: Text('home')),
    ));
    expect(find.text('home'), findsOneWidget);
  });

  testWidgets('shows default SnackBar on refreshReuseDetected',
      (tester) async {
    final fake = FakeAuthRuntime();
    addTearDown(fake.dispose);
    await tester.pumpWidget(_wrap(
      fake,
      child: const AuthEventListener(child: Text('home')),
    ));
    fake.emitSecurityEvent(
      SecurityEvent.refreshReuseDetected(DateTime.utc(2026, 4, 19)),
    );
    await tester.pump();
    await tester.pump();
    expect(find.byType(SnackBar), findsOneWidget);
    expect(find.textContaining('suspicious session activity'),
        findsOneWidget);
  });

  testWidgets('shows default SnackBar on storageCorruption', (tester) async {
    final fake = FakeAuthRuntime();
    addTearDown(fake.dispose);
    await tester.pumpWidget(_wrap(
      fake,
      child: const AuthEventListener(child: Text('home')),
    ));
    fake.emitSecurityEvent(
      SecurityEvent.storageCorruption(DateTime.utc(2026, 4, 19)),
    );
    await tester.pump();
    await tester.pump();
    expect(find.textContaining('could not be read'), findsOneWidget);
  });

  testWidgets('custom builder replaces the default message', (tester) async {
    final fake = FakeAuthRuntime();
    addTearDown(fake.dispose);
    await tester.pumpWidget(_wrap(
      fake,
      child: AuthEventListener(
        builder: (context, ev, _) => const Text('custom-snack'),
        child: const Text('home'),
      ),
    ));
    fake.emitSecurityEvent(
      SecurityEvent.loggedOutElsewhere(DateTime.utc(2026, 4, 19)),
    );
    await tester.pump();
    await tester.pump();
    expect(find.text('custom-snack'), findsOneWidget);
  });

  testWidgets('builder returning null suppresses the default SnackBar',
      (tester) async {
    final fake = FakeAuthRuntime();
    addTearDown(fake.dispose);
    await tester.pumpWidget(_wrap(
      fake,
      child: AuthEventListener(
        builder: (_, _, _) => null,
        child: const Text('home'),
      ),
    ));
    fake.emitSecurityEvent(
      SecurityEvent.bindingInvalidated(DateTime.utc(2026, 4, 19)),
    );
    await tester.pump();
    await tester.pump();
    expect(find.byType(SnackBar), findsNothing);
  });
}
