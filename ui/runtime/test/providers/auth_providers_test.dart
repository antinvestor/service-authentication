import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/fake_auth_runtime.dart';

void main() {
  late FakeAuthRuntime fake;
  late ProviderContainer container;

  setUp(() {
    fake = FakeAuthRuntime(initialState: AuthState.unauthenticated);
    container = ProviderContainer(
      overrides: [authRuntimeProvider.overrideWithValue(fake)],
    );
    addTearDown(container.dispose);
    addTearDown(fake.dispose);
  });

  test('default authRuntimeProvider throws without an override', () {
    final bare = ProviderContainer();
    addTearDown(bare.dispose);
    // Riverpod 3 wraps provider-thrown errors in a ProviderException; we
    // match on the underlying message rather than the type so this stays
    // robust against future Riverpod re-wraps.
    expect(
      () => bare.read(authRuntimeProvider),
      throwsA(predicate<Object>(
        (e) => e.toString().contains('Override authRuntimeProvider'),
      )),
    );
  });

  test('authStateProvider mirrors the runtime stream', () async {
    // Attach a subscription so Riverpod starts the stream.
    final received = <AuthState>[];
    container.listen<AsyncValue<AuthState>>(
      authStateProvider,
      (_, next) {
        next.whenData(received.add);
      },
      fireImmediately: true,
    );

    fake.emitState(AuthState.initializing);
    fake.emitState(AuthState.authenticated);
    await Future<void>.microtask(() {});
    await Future<void>.delayed(Duration.zero);

    expect(received, containsAllInOrder(<AuthState>[
      AuthState.initializing,
      AuthState.authenticated,
    ]));
  });

  test('isAuthenticatedProvider reflects current AuthState', () async {
    // Subscribe so the StreamProvider starts emitting.
    container.listen(authStateProvider, (_, _) {});
    expect(container.read(isAuthenticatedProvider), isFalse);

    fake.emitState(AuthState.authenticated);
    await Future<void>.delayed(Duration.zero);
    expect(container.read(isAuthenticatedProvider), isTrue);

    fake.emitState(AuthState.unauthenticated);
    await Future<void>.delayed(Duration.zero);
    expect(container.read(isAuthenticatedProvider), isFalse);
  });

  test('userClaimsProvider returns {} while unauthenticated', () async {
    container.listen(authStateProvider, (_, _) {});
    final claims = await container.read(userClaimsProvider.future);
    expect(claims, isEmpty);
  });

  test('userClaimsProvider returns runtime claims once authenticated',
      () async {
    fake.claims = {'sub': 'u-1', 'email': 'a@b.c'};
    container.listen(authStateProvider, (_, _) {});
    fake.emitState(AuthState.authenticated);
    // Invalidate so it re-reads now that the state has flipped.
    await Future<void>.delayed(Duration.zero);
    container.invalidate(userClaimsProvider);
    final claims = await container.read(userClaimsProvider.future);
    expect(claims['sub'], 'u-1');
    expect(claims['email'], 'a@b.c');
  });

  test('rolesProvider returns [] while unauthenticated', () async {
    container.listen(authStateProvider, (_, _) {});
    final roles = await container.read(rolesProvider.future);
    expect(roles, isEmpty);
  });

  test('rolesProvider returns runtime roles once authenticated', () async {
    fake.roles = ['admin', 'user'];
    container.listen(authStateProvider, (_, _) {});
    fake.emitState(AuthState.authenticated);
    await Future<void>.delayed(Duration.zero);
    container.invalidate(rolesProvider);
    final roles = await container.read(rolesProvider.future);
    expect(roles, ['admin', 'user']);
  });

  test('securityEventsProvider streams runtime events', () async {
    final events = <SecurityEvent>[];
    container.listen<AsyncValue<SecurityEvent>>(
      securityEventsProvider,
      (_, next) {
        next.whenData(events.add);
      },
    );
    final at = DateTime.utc(2026, 4, 19, 12, 0, 0);
    fake.emitSecurityEvent(SecurityEvent.refreshReuseDetected(at));
    fake.emitSecurityEvent(SecurityEvent.storageCorruption(at));
    await Future<void>.delayed(Duration.zero);
    expect(events, hasLength(2));
    expect(events[0], isA<RefreshReuseDetected>());
    expect(events[1], isA<StorageCorruption>());
  });

  testWidgets('AuthRuntimeScope.of returns the runtime from context',
      (tester) async {
    AuthRuntime? seen;
    await tester.pumpWidget(
      AuthRuntimeScope(
        runtime: fake,
        child: Builder(
          builder: (ctx) {
            seen = AuthRuntimeScope.of(ctx);
            return const SizedBox();
          },
        ),
      ),
    );
    expect(identical(seen, fake), isTrue);
  });

  testWidgets('AuthRuntimeScope.of throws when no ancestor is present',
      (tester) async {
    FlutterError? caught;
    await tester.pumpWidget(
      Builder(
        builder: (ctx) {
          try {
            AuthRuntimeScope.of(ctx);
          } on FlutterError catch (err) {
            caught = err;
          }
          return const SizedBox();
        },
      ),
    );
    expect(caught, isNotNull);
  });

  testWidgets('AuthRuntimeScope.maybeOf returns null without ancestor',
      (tester) async {
    AuthRuntime? seen = fake;
    await tester.pumpWidget(
      Builder(
        builder: (ctx) {
          seen = AuthRuntimeScope.maybeOf(ctx);
          return const SizedBox();
        },
      ),
    );
    expect(seen, isNull);
  });
}
