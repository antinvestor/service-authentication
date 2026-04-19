import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter_test/flutter_test.dart';

import '_helpers.dart';
import 'mock_idp.dart';

void main() {
  late IntegrationHarness h;

  tearDown(() async {
    await h.dispose();
  });

  test('near-expiry fetch triggers refresh and rotates RT', () async {
    // Short access-token lifetime so the worker's refresh buffer (60s)
    // already engulfs the token from the moment it's issued — the next
    // fetch therefore has to refresh before doing anything else.
    final mock = MockIdp(tokenLifetime: const Duration(seconds: 30));
    h = await buildHarness(mock: mock);

    await h.runtime.ensureAuthenticated();
    expect(h.runtime.state, AuthState.authenticated);

    // Only the authorization_code grant has run so far.
    expect(
      h.mock.tokenRequests.where((r) => r.grantType == 'refresh_token'),
      isEmpty,
    );

    // A fetch forces ensureFresh, which refreshes because the AT is already
    // inside the refresh buffer.
    try {
      await h.runtime.fetch('/ping');
    } catch (_) {
      // 404 from the mock is fine; the refresh ran *before* the API call.
    }

    final refreshCalls =
        h.mock.tokenRequests.where((r) => r.grantType == 'refresh_token');
    expect(refreshCalls, hasLength(1));
    // The presented RT is the original rt-1; the mock has consumed it and
    // issued rt-2.
    expect(refreshCalls.single.form['refresh_token'], 'rt-1');
  });

  test('second near-expiry fetch uses the rotated RT', () async {
    final mock = MockIdp(tokenLifetime: const Duration(seconds: 30));
    h = await buildHarness(mock: mock);

    await h.runtime.ensureAuthenticated();

    for (var i = 0; i < 2; i++) {
      try {
        await h.runtime.fetch('/ping');
      } catch (_) {/* 404 ok */}
    }

    final refreshCalls = h.mock.tokenRequests
        .where((r) => r.grantType == 'refresh_token')
        .toList();
    expect(refreshCalls.length, greaterThanOrEqualTo(2));
    // The second refresh used rt-2 (issued by the first rotation), not rt-1.
    expect(refreshCalls[0].form['refresh_token'], 'rt-1');
    expect(refreshCalls[1].form['refresh_token'], 'rt-2');
  });
}
