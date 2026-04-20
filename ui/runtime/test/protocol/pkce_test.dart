import 'package:antinvestor_auth_runtime/src/protocol/pkce.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('verifier is 43-128 url-safe chars', () async {
    final pair = await generatePkcePair();
    expect(RegExp(r'^[A-Za-z0-9_-]{43,128}$').hasMatch(pair.verifier), true);
    expect(RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(pair.challenge), true);
  });

  test('challenge is deterministic from verifier', () async {
    final a = await generatePkcePair();
    expect(await computeChallenge(a.verifier), a.challenge);
  });

  test('generateVerifier produces distinct values (entropy)', () {
    final seen = <String>{
      for (var i = 0; i < 32; i++) generateVerifier(),
    };
    // Collisions with 64 random bytes are astronomically unlikely; if
    // we ever collide it likely means we're not using Random.secure().
    expect(seen.length, 32);
  });

  test('SHA-256 challenge is 43 base64url chars (no padding)', () async {
    final challenge = await computeChallenge('a-known-verifier-string');
    expect(challenge.length, 43);
    expect(challenge.contains('='), isFalse);
    expect(challenge.contains('+'), isFalse);
    expect(challenge.contains('/'), isFalse);
  });

  test('computeChallenge matches RFC 7636 known-answer vector', () async {
    // Appendix B example:
    // verifier = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
    // challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    final challenge =
        await computeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
    expect(challenge, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
}
