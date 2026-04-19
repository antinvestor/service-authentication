import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter_test/flutter_test.dart';

import '_helpers.dart';

void main() {
  late IntegrationHarness h;

  tearDown(() async {
    await h.dispose();
  });

  test('logout revokes RT, calls end_session, wipes storage', () async {
    h = await buildHarness();
    await h.runtime.ensureAuthenticated();
    expect(h.runtime.state, AuthState.authenticated);
    expect(await h.tokenStore.load(h.config.namespace), isNotNull);

    await h.runtime.logout();

    expect(h.runtime.state, AuthState.unauthenticated);
    expect(await h.tokenStore.load(h.config.namespace), isNull);

    // Exactly one revocation POST; exactly one end_session GET.
    expect(h.mock.revocationRequests, hasLength(1));
    expect(h.mock.endSessionRequests, hasLength(1));

    // Revocation body includes the refresh_token + token_type_hint.
    final form = Uri.splitQueryString(h.mock.revocationRequests.single.body);
    expect(form['token'], 'rt-1');
    expect(form['token_type_hint'], 'refresh_token');
  });

  test('post-logout ensureAuthenticated drives a new OAuth flow', () async {
    h = await buildHarness();
    await h.runtime.ensureAuthenticated();
    expect(h.fakeOAuth.calls, 1);

    await h.runtime.logout();
    await Future<void>.delayed(Duration.zero);
    expect(h.runtime.state, AuthState.unauthenticated);

    await h.runtime.ensureAuthenticated();
    expect(h.fakeOAuth.calls, 2);
    expect(h.runtime.state, AuthState.authenticated);
    // Two authorization_code grants ran in total.
    expect(
      h.mock.tokenRequests
          .where((r) => r.grantType == 'authorization_code')
          .length,
      2,
    );
  });
}
