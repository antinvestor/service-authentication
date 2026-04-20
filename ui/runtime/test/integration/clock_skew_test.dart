import 'package:antinvestor_auth_runtime/antinvestor_auth_runtime.dart';
import 'package:flutter_test/flutter_test.dart';

import '_helpers.dart';
import 'mock_idp.dart';

void main() {
  late IntegrationHarness h;

  tearDown(() async {
    await h.dispose();
  });

  test(
      'invalid_dpop_proof with future Date header triggers client-side '
      'offset and retry', () async {
    final mock = MockIdp()..enableClockSkewChallenge();
    h = await buildHarness(mock: mock);

    await h.runtime.ensureAuthenticated();
    expect(h.runtime.state, AuthState.authenticated);

    final hits = h.mock.tokenRequests
        .where((r) => r.grantType == 'authorization_code')
        .toList();
    // Exactly two hits: first rejected for skew, second retried after the
    // runtime applied the Date-header offset.
    expect(hits, hasLength(2));

    final firstIat = hits[0].dpopClaims!.iat;
    final retryIat = hits[1].dpopClaims!.iat;
    // Retry iat should be ~5 minutes (the Date-header offset) ahead of
    // the first proof. Allow a generous tolerance for scheduler latency.
    final delta = retryIat - firstIat;
    expect(delta, greaterThan(240)); // > 4 minutes
    expect(delta, lessThan(360)); // < 6 minutes
  });
}
