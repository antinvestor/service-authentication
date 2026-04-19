/// Thin wrapper around the claims map decoded from a JWT.
///
/// Only surfaces canonical OIDC fields as typed getters; callers needing
/// custom claims can reach through [raw]. Role extraction matches the JS
/// `extractRolesFromToken` — supporting both `roles` and
/// `realm_access.roles`.
class UserClaims {
  const UserClaims(this.raw);

  final Map<String, dynamic> raw;

  String? get sub => _asString(raw['sub']);
  String? get name => _asString(raw['name']);
  String? get email => _asString(raw['email']);
  String? get picture => _asString(raw['picture']);

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

  static String? _asString(Object? v) => v is String ? v : null;
}
