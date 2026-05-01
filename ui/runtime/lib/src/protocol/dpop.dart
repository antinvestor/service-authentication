import 'dart:convert';
import 'dart:io' show HttpDate;
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/crypto/key_manager.dart';
import 'package:antinvestor_auth_runtime/src/protocol/pkce.dart'
    show randomBytes;
import 'package:crypto/crypto.dart' as crypto;
import 'package:pointycastle/export.dart' as pc;

/// Opaque handle for a P-256 key pair owned by the runtime.
///
/// The concrete backing is [pc.ECPrivateKey] + [pc.ECPublicKey] from
/// PointyCastle; callers should treat this as opaque — private material
/// never leaves the runtime.
class DpopKeyPair {
  DpopKeyPair({
    required this.privateKey,
    required this.publicKey,
  });

  final pc.ECPrivateKey privateKey;
  final pc.ECPublicKey publicKey;
}

/// Generates a fresh ECDSA P-256 key pair suitable for DPoP proofs.
///
/// The plan mandates ECDSA P-256 via `package:cryptography`'s
/// `Ecdsa.p256(Sha256())`. That backend's pure-Dart implementation
/// raises [UnimplementedError] for ECDSA (see `DartEcdsa`), so no
/// signing is possible in `flutter_test` without a platform-native
/// plugin. We therefore use `package:pointycastle` — a pure-Dart
/// implementation that works uniformly across Dart VM, web, and native
/// — and encode output to the same JWS ES256 (raw r||s) shape the plan
/// requires. [DpopKeyPair] is the runtime's stable handle so the
/// backend can be swapped without touching callers.
DpopKeyPair generateDpopKeyPair() {
  final keyGen = pc.ECKeyGenerator();
  final random = _secureRandom();
  keyGen.init(pc.ParametersWithRandom(
    pc.ECKeyGeneratorParameters(pc.ECCurve_secp256r1()),
    random,
  ));
  final pair = keyGen.generateKeyPair();
  return DpopKeyPair(
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
  );
}

/// DPoP signing context held for the lifetime of an authenticated session.
///
/// Contains the private key used to sign proofs, the matching public JWK
/// (embedded in every proof header), the accumulated `clockOffsetMs` from
/// IdP-served `Date` headers, and the per-origin nonce cache.
///
/// An optional [keyManager] may be supplied to delegate signing to an
/// injected backend. When absent, [buildProof] falls back to the built-in
/// PointyCastle signer — preserving the original F-B.4 call path so
/// pre-KeyManager callers keep working.
class DpopContext {
  DpopContext({
    required this.keyPair,
    required this.publicJwk,
    this.keyManager,
  });

  /// ECDSA P-256 key pair. Kept in memory only — never serialised by
  /// this class.
  final DpopKeyPair keyPair;

  /// Public JWK `{kty, crv, x, y}` inserted into the proof header.
  final Map<String, dynamic> publicJwk;

  /// Optional injected signer. When non-null, [buildProof] delegates
  /// ECDSA signing to `keyManager.signDpopJws`.
  final KeyManager? keyManager;

  /// Server-clock minus local-clock, in milliseconds. Applied to `iat`.
  int clockOffsetMs = 0;

  /// Nonce keyed by origin of the request URL.
  final Map<String, String> nonceByOrigin = {};
}

/// Derives a [DpopContext] from an existing P-256 key pair.
///
/// If [keyManager] is supplied it is stored on the context and used
/// for subsequent signing operations. The JWK export also goes through
/// the key manager so tests can swap in synthetic backends.
Future<DpopContext> makeDpopContextAsync(
  DpopKeyPair kp, {
  KeyManager? keyManager,
}) async {
  final Map<String, dynamic> jwk;
  if (keyManager != null) {
    jwk = await keyManager.exportDpopPublicJwk(kp);
  } else {
    jwk = _localExportJwk(kp);
  }
  return DpopContext(keyPair: kp, publicJwk: jwk, keyManager: keyManager);
}

/// Synchronous convenience factory preserved for callers that predate
/// F-C.1's [KeyManager] injection. Uses the built-in PointyCastle path
/// for JWK export.
DpopContext makeDpopContext(DpopKeyPair kp) {
  return DpopContext(keyPair: kp, publicJwk: _localExportJwk(kp));
}

Map<String, String> _localExportJwk(DpopKeyPair kp) {
  final q = kp.publicKey.Q!;
  // P-256 component size: 32 bytes. Left-pad BigInts to fixed width so
  // JWK encoding matches RFC 7518 §6.2.1.
  final xBytes = _bigIntToFixedBytes(q.x!.toBigInteger()!, 32);
  final yBytes = _bigIntToFixedBytes(q.y!.toBigInteger()!, 32);
  return <String, String>{
    'kty': 'EC',
    'crv': 'P-256',
    'x': _b64urlNoPad(xBytes),
    'y': _b64urlNoPad(yBytes),
  };
}

/// Remembers a server-issued DPoP nonce for later proofs aimed at the
/// same origin. Accepts both `DPoP-Nonce` casings.
void rememberNonce(
  DpopContext ctx,
  String audienceUrl,
  Map<String, String> headers,
) {
  final value = _headerIgnoreCase(headers, 'dpop-nonce');
  if (value == null) return;
  ctx.nonceByOrigin[_originOf(audienceUrl)] = value;
}

/// Adjusts [DpopContext.clockOffsetMs] based on the HTTP `Date` response
/// header. Malformed/absent headers are ignored.
void rememberClockOffset(
  DpopContext ctx,
  Map<String, String> headers,
) {
  final dateHeader = _headerIgnoreCase(headers, 'date');
  if (dateHeader == null) return;
  final parsed = _tryParseHttpDate(dateHeader);
  if (parsed == null) return;
  ctx.clockOffsetMs = parsed.millisecondsSinceEpoch -
      DateTime.now().millisecondsSinceEpoch;
}

/// Builds a DPoP proof JWT for the given request.
///
/// When [accessToken] is supplied the `ath` claim (access-token hash) is
/// included — required for resource-server requests per the DPoP RFC.
/// When a nonce has been remembered for the URL's origin it is embedded.
Future<String> buildProof(
  DpopContext ctx, {
  required String htm,
  required String htu,
  String? accessToken,
}) async {
  final header = <String, dynamic>{
    'typ': 'dpop+jwt',
    'alg': 'ES256',
    'jwk': ctx.publicJwk,
  };

  final nowMs = DateTime.now().millisecondsSinceEpoch + ctx.clockOffsetMs;
  final payload = <String, dynamic>{
    'htm': htm.toUpperCase(),
    'htu': htu,
    'iat': nowMs ~/ 1000,
    'jti': _b64urlNoPad(randomBytes(16)),
  };
  if (accessToken != null) {
    payload['ath'] =
        _b64urlNoPad(crypto.sha256.convert(utf8.encode(accessToken)).bytes);
  }
  final nonce = ctx.nonceByOrigin[_originOf(htu)];
  if (nonce != null) {
    payload['nonce'] = nonce;
  }

  final headerB64 = _b64urlNoPad(utf8.encode(json.encode(header)));
  final payloadB64 = _b64urlNoPad(utf8.encode(json.encode(payload)));
  final signingInput = '$headerB64.$payloadB64';

  final Uint8List signature;
  final km = ctx.keyManager;
  if (km != null) {
    signature = await km.signDpopJws(ctx.keyPair, signingInput);
  } else {
    signature = _signEcdsa(
      ctx.keyPair.privateKey,
      Uint8List.fromList(utf8.encode(signingInput)),
    );
  }
  return '$signingInput.${_b64urlNoPad(signature)}';
}

/// Signs [message] with SHA-256 ECDSA over P-256 using RFC 6979
/// deterministic k, returning the JWS-compatible raw r||s encoding.
Uint8List _signEcdsa(pc.ECPrivateKey priv, Uint8List message) {
  final signer = pc.ECDSASigner(
    pc.SHA256Digest(),
    pc.HMac.withDigest(pc.SHA256Digest()),
  )..init(
      true,
      pc.PrivateKeyParameter<pc.ECPrivateKey>(priv),
    );
  final sig = signer.generateSignature(message) as pc.ECSignature;
  // JWS ES256 format: 32-byte r || 32-byte s, left-padded.
  return Uint8List.fromList([
    ..._bigIntToFixedBytes(sig.r, 32),
    ..._bigIntToFixedBytes(sig.s, 32),
  ]);
}

/// Verifies a raw r||s ECDSA signature against [message] using the
/// public key. Exposed so the runtime's tests can self-check the
/// builder output without a real IdP.
bool verifyEcdsaRaw(
  pc.ECPublicKey pub,
  Uint8List message,
  Uint8List signature,
) {
  if (signature.length != 64) return false;
  final r = _bytesToBigInt(signature.sublist(0, 32));
  final s = _bytesToBigInt(signature.sublist(32, 64));
  final verifier = pc.ECDSASigner(pc.SHA256Digest())
    ..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(pub));
  return verifier.verifySignature(message, pc.ECSignature(r, s));
}

/// Left-pads a positive [BigInt] to exactly [size] bytes.
Uint8List _bigIntToFixedBytes(BigInt value, int size) {
  final bytes = Uint8List(size);
  var v = value;
  for (var i = size - 1; i >= 0; i--) {
    bytes[i] = (v & BigInt.from(0xff)).toInt();
    v = v >> 8;
  }
  return bytes;
}

BigInt _bytesToBigInt(Uint8List bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

String _b64urlNoPad(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

String _originOf(String url) {
  try {
    final uri = Uri.parse(url);
    final port = uri.hasPort ? ':${uri.port}' : '';
    return '${uri.scheme}://${uri.host}$port';
  } catch (_) {
    return url;
  }
}

String? _headerIgnoreCase(Map<String, String> headers, String name) {
  final lower = name.toLowerCase();
  for (final e in headers.entries) {
    if (e.key.toLowerCase() == lower) return e.value;
  }
  return null;
}

DateTime? _tryParseHttpDate(String s) {
  try {
    return HttpDate.parse(s);
  } catch (_) {
    try {
      return DateTime.parse(s);
    } catch (_) {
      return null;
    }
  }
}

/// Seeds a PointyCastle CSPRNG from `Random.secure()`.
pc.SecureRandom _secureRandom() {
  final rand = pc.SecureRandom('Fortuna');
  final seed = randomBytes(32);
  rand.seed(pc.KeyParameter(seed));
  return rand;
}
