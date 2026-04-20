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
      'nonce-challenge first 401 triggers retry with DPoP-Nonce claim embedded',
      () async {
    final mock = MockIdp()..enableNonceChallenge(nonce: 'srv-nonce-42');
    h = await buildHarness(mock: mock);

    await h.runtime.ensureAuthenticated();
    expect(h.runtime.state, AuthState.authenticated);

    // Exactly two /token hits: first one challenged, second carried the
    // server-issued nonce.
    final hits = h.mock.tokenRequests
        .where((r) => r.grantType == 'authorization_code')
        .toList();
    expect(hits, hasLength(2));

    expect(hits[0].dpopClaims, isNotNull);
    expect(hits[0].dpopClaims!.nonce, isNull);

    expect(hits[1].dpopClaims, isNotNull);
    expect(hits[1].dpopClaims!.nonce, 'srv-nonce-42');
  });
}
