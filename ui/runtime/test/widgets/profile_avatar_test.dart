import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:antinvestor_auth_runtime/src/widgets/profile_avatar.dart'
    show initialsFromClaims;
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
  group('initialsFromClaims', () {
    test('derives two initials from a multi-word name', () {
      expect(initialsFromClaims({'name': 'Alice Example'}), 'AE');
    });

    test('single-word name yields a single initial', () {
      expect(initialsFromClaims({'name': 'Alice'}), 'A');
    });

    test('falls back to email local-part when name is missing', () {
      expect(initialsFromClaims({'email': 'alice@example.com'}), 'A');
    });

    test('returns empty string when no usable claim present', () {
      expect(initialsFromClaims({}), '');
    });

    test('collapses extra whitespace in name', () {
      expect(initialsFromClaims({'name': '  Alice   Example  Smith'}), 'AE');
    });
  });

  testWidgets(
      'renders initials when claims include a name and no picture URL',
      (tester) async {
    final fake = FakeAuthRuntime(
      initialState: AuthState.authenticated,
      claims: {'name': 'Alice Example'},
    );
    addTearDown(fake.dispose);
    await tester.pumpWidget(_wrap(fake, child: const ProfileAvatar()));
    fake.emitState(AuthState.authenticated);
    await tester.pump();
    await tester.pump();
    expect(find.text('AE'), findsOneWidget);
  });

  testWidgets('renders initials from email when no name is set',
      (tester) async {
    final fake = FakeAuthRuntime(
      initialState: AuthState.authenticated,
      claims: {'email': 'bob@example.com'},
    );
    addTearDown(fake.dispose);
    await tester.pumpWidget(_wrap(fake, child: const ProfileAvatar()));
    fake.emitState(AuthState.authenticated);
    await tester.pump();
    await tester.pump();
    expect(find.text('B'), findsOneWidget);
  });

  testWidgets('falls back to a placeholder icon with no usable claims',
      (tester) async {
    final fake = FakeAuthRuntime(
      initialState: AuthState.authenticated,
      claims: {},
    );
    addTearDown(fake.dispose);
    await tester.pumpWidget(_wrap(fake, child: const ProfileAvatar()));
    fake.emitState(AuthState.authenticated);
    await tester.pump();
    await tester.pump();
    expect(find.byIcon(Icons.person_outline), findsOneWidget);
  });

  testWidgets('while claims resolve, shows an empty placeholder circle',
      (tester) async {
    final fake = FakeAuthRuntime(initialState: AuthState.unauthenticated);
    addTearDown(fake.dispose);
    await tester.pumpWidget(_wrap(fake, child: const ProfileAvatar()));
    // First frame has no resolved claims yet → loading branch.
    expect(find.byType(CircleAvatar), findsOneWidget);
  });
}
