/// Thin wrapper around the claims map decoded from a JWT.
///
/// Surfaces canonical OIDC fields as typed getters plus a few
/// Antinvestor-wide non-standard claims (`contact_id`, `tenant_id`,
/// `partition_id`). Callers needing anything else can reach through
/// [raw] directly or via [customClaims]. Role extraction matches the JS
/// `extractRolesFromToken` — supporting both `roles` and
/// `realm_access.roles`.
class UserClaims {
  const UserClaims(this.raw);

  final Map<String, dynamic> raw;

  String? get sub => _asString(raw['sub']);
  String? get name => _asString(raw['name']);
  String? get email => _asString(raw['email']);
  String? get picture => _asString(raw['picture']);

  /// Non-standard `contact_id` claim issued by Antinvestor's IdP. Null
  /// when the claim is missing or not a string.
  String? get contactId => _asString(raw['contact_id']);

  /// Non-standard `tenant_id` claim issued by Antinvestor's IdP.
  String? get tenantId => _asString(raw['tenant_id']);

  /// Non-standard `partition_id` claim issued by Antinvestor's IdP.
  String? get partitionId => _asString(raw['partition_id']);

  List<String> get roles {
    final direct = raw['roles'];
    if (direct is List) {
      return direct.whereType<String>().toList(growable: false);
    }
    final realm = raw['realm_access'];
    if (realm is Map) {
      final realmRoles = realm['roles'];
      if (realmRoles is List) {
        return realmRoles.whereType<String>().toList(growable: false);
      }
    }
    return const [];
  }

  /// All non-standard (non-OIDC) claims. Use for bespoke per-app claims
  /// the runtime doesn't surface as typed getters.
  Map<String, dynamic> get customClaims {
    return Map<String, dynamic>.fromEntries(
      raw.entries.where((e) => !_standardOidcClaims.contains(e.key)),
    );
  }

  static String? _asString(Object? v) => v is String ? v : null;
}

/// RFC 8693 / OIDC Core standard claim names. Anything outside this set
/// is treated as a "custom" claim by [UserClaims.customClaims].
const Set<String> _standardOidcClaims = <String>{
  // JWT registered / OIDC id-token claims.
  'iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce',
  'azp', 'auth_time', 'acr', 'amr',
  // Profile claims.
  'name', 'given_name', 'family_name', 'middle_name', 'nickname',
  'preferred_username', 'profile', 'picture', 'website',
  // Email / phone / address claims.
  'email', 'email_verified',
  'gender', 'birthdate', 'zoneinfo', 'locale',
  'phone_number', 'phone_number_verified',
  'address', 'updated_at',
};
