import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/fake_auth_runtime.dart';

Widget _wrap(FakeAuthRuntime fake, {required Widget child}) {
  return ProviderScope(
    overrides: [authRuntimeProvider.overrideWithValue(fake)],
    child: MaterialApp(home: child),
  );
}

void main() {
  testWidgets('builder receives initializing while stream is loading',
      (tester) async {
    final fake = FakeAuthRuntime(initialState: AuthState.unauthenticated);
    addTearDown(fake.dispose);

    AuthState? observed;
    await tester.pumpWidget(
      _wrap(
        fake,
        child: AuthStateBuilder(
          builder: (_, s) {
            observed = s;
            return const SizedBox.shrink();
          },
        ),
      ),
    );
    // The first frame has no stream event yet — we treat "loading" as
    // initializing so widgets can render a spinner without branching on
    // AsyncValue.
    expect(observed, AuthState.initializing);
  });

  testWidgets('builder rebuilds when the runtime emits a transition',
      (tester) async {
    final fake = FakeAuthRuntime(initialState: AuthState.unauthenticated);
    addTearDown(fake.dispose);

    final observed = <AuthState>[];
    await tester.pumpWidget(
      _wrap(
        fake,
        child: AuthStateBuilder(
          builder: (_, s) {
            observed.add(s);
            return Text('state=${s.name}');
          },
        ),
      ),
    );
    expect(observed.last, AuthState.initializing);

    fake.emitState(AuthState.unauthenticated);
    await tester.pump();
    await tester.pump();
    expect(find.text('state=unauthenticated'), findsOneWidget);

    fake.emitState(AuthState.authenticated);
    await tester.pump();
    await tester.pump();
    expect(find.text('state=authenticated'), findsOneWidget);
  });
}
