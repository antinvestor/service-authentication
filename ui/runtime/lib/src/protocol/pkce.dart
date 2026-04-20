import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// PKCE verifier + `S256` challenge pair.
class PkcePair {
  const PkcePair({required this.verifier, required this.challenge});

  final String verifier;
  final String challenge;
}

/// Returns [n] bytes sourced from `Random.secure()` — the only
/// cryptographic RNG exposed by the Dart core library.
Uint8List randomBytes(int n) {
  final rng = Random.secure();
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = rng.nextInt(256);
  }
  return out;
}

/// Generates a PKCE verifier. Default 64 bytes matches the JS runtime
/// and yields a 43-char base64url output (minimum size allowed by RFC 7636).
String generateVerifier([int length = 64]) {
  return _base64Url(randomBytes(length));
}

/// Computes the S256 challenge for [verifier].
Future<String> computeChallenge(String verifier) async {
  final digest = sha256.convert(utf8.encode(verifier));
  return _base64Url(Uint8List.fromList(digest.bytes));
}

/// Convenience: verifier + matching challenge.
Future<PkcePair> generatePkcePair() async {
  final verifier = generateVerifier();
  final challenge = await computeChallenge(verifier);
  return PkcePair(verifier: verifier, challenge: challenge);
}

String _base64Url(Uint8List bytes) {
  return base64Url.encode(bytes).replaceAll('=', '');
}
