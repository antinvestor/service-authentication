import 'dart:convert';

/// Decodes the payload segment of a compact-serialised JWT.
///
/// Does NOT verify signature — verification is the IdP's job; we only
/// read claims. Matches the JS runtime's base64url padding recovery.
Map<String, dynamic> decodeJwtPayload(String token) {
  final parts = token.split('.');
  if (parts.length != 3) {
    throw const FormatException('Invalid JWT: expected 3 parts');
  }
  final normalized = _padBase64Url(parts[1]);
  final bytes = base64Url.decode(normalized);
  final decoded = json.decode(utf8.decode(bytes));
  if (decoded is! Map) {
    throw const FormatException('Invalid JWT payload: not a JSON object');
  }
  return decoded.cast<String, dynamic>();
}

/// Extracts roles using Hydra-compatible claim paths.
///
/// Looks at `roles` first, then `realm_access.roles`. Returns an empty
/// list on any decode failure — role extraction is best-effort.
List<String> extractRolesFromToken(String token) {
  try {
    final payload = decodeJwtPayload(token);
    final direct = payload['roles'];
    if (direct is List) {
      return direct.whereType<String>().toList(growable: false);
    }
    final realm = payload['realm_access'];
    if (realm is Map) {
      final realmRoles = realm['roles'];
      if (realmRoles is List) {
        return realmRoles.whereType<String>().toList(growable: false);
      }
    }
    return const [];
  } on FormatException {
    return const [];
  } catch (_) {
    return const [];
  }
}

String _padBase64Url(String input) {
  final mod = input.length % 4;
  if (mod == 0) return input;
  if (mod == 2) return '$input==';
  if (mod == 3) return '$input=';
  throw const FormatException('Invalid base64url length');
}
