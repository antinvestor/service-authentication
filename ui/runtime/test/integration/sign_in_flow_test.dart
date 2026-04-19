import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter_test/flutter_test.dart';

import '_helpers.dart';

void main() {
  late IntegrationHarness h;

  tearDown(() async {
    await h.dispose();
  });

  test('ensureAuthenticated drives full OAuth + token exchange against mock IdP',
      () async {
    h = await buildHarness();
    final states = <AuthState>[];
    h.runtime.authStateStream.listen(states.add);

    expect(h.runtime.state, AuthState.unauthenticated);

    await h.runtime.ensureAuthenticated();
    // Give the broadcast stream time to flush.
    await Future<void>.delayed(Duration.zero);

    expect(h.runtime.state, AuthState.authenticated);
    // We go unauthenticated → initializing → authenticated during sign-in.
    expect(states, contains(AuthState.authenticated));
    expect(h.fakeOAuth.calls, 1);

    // Exactly one authorization_code grant hit the mock.
    expect(
      h.mock.tokenRequests.where((r) => r.grantType == 'authorization_code'),
      hasLength(1),
    );
    // The request carried a well-formed DPoP proof with the right htm/htu.
    final authzCall = h.mock.tokenRequests.firstWhere(
      (r) => r.grantType == 'authorization_code',
    );
    expect(authzCall.dpopClaims, isNotNull);
    expect(authzCall.dpopClaims!.htm, 'POST');
    expect(authzCall.dpopClaims!.htu, h.mock.tokenEndpoint);
  });

  test('getClaims returns decoded ID token payload', () async {
    h = await buildHarness();
    await h.runtime.ensureAuthenticated();
    final claims = await h.runtime.getClaims();
    expect(claims['sub'], 'user-1');
    expect(claims['email'], 'user@example.com');
    expect(claims['name'], 'Test User');
  });

  test('getRoles extracts roles from access token', () async {
    h = await buildHarness();
    await h.runtime.ensureAuthenticated();
    final roles = await h.runtime.getRoles();
    expect(roles, unorderedEquals(<String>['user', 'admin']));
  });

  test('session persists across a runtime dispose + re-init', () async {
    h = await buildHarness();
    await h.runtime.ensureAuthenticated();
    final firstClaims = await h.runtime.getClaims();
    expect(firstClaims['sub'], 'user-1');

    // Capture the storage so the second runtime sees the same on-disk state.
    final sessionKv = h.sessionKv;
    final rootKv = h.rootKv;
    final mock = h.mock;
    final firstHarness = h;

    // Dispose the first runtime but keep the mock alive.
    await firstHarness.runtime.dispose();
    // Clear the singleton discovery cache so the fresh runtime actually
    // re-reads the well-known document from the mock.
    // (The helper does this, but we want to assert the cold-boot path.)

    final fresh = await buildHarness(
      mock: mock,
      sessionKv: sessionKv,
      rootKv: rootKv,
    );
    h = fresh;

    await Future<void>.delayed(Duration.zero);
    expect(fresh.runtime.state, AuthState.authenticated);
    // No new authorization_code call: we restored from storage.
    expect(
      fresh.mock.tokenRequests
          .where((r) => r.grantType == 'authorization_code')
          .length,
      1,
    );
  });
}
