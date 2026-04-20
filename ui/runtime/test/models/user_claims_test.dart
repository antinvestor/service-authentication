import 'package:antinvestor_auth_runtime/src/models/user_claims.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('UserClaims exposes canonical OIDC fields', () {
    const c = UserClaims({
      'sub': 's1',
      'name': 'Alice',
      'email': 'a@example.com',
      'picture': 'https://cdn/x.png',
      'roles': <dynamic>['admin', 'editor'],
    });
    expect(c.sub, 's1');
    expect(c.name, 'Alice');
    expect(c.email, 'a@example.com');
    expect(c.picture, 'https://cdn/x.png');
    expect(c.roles, ['admin', 'editor']);
  });

  test('UserClaims pulls roles from realm_access fallback', () {
    const c = UserClaims({
      'sub': 's',
      'realm_access': {'roles': <dynamic>['ops']},
    });
    expect(c.roles, ['ops']);
  });

  test('UserClaims missing fields return null and empty list', () {
    const c = UserClaims({});
    expect(c.sub, isNull);
    expect(c.name, isNull);
    expect(c.email, isNull);
    expect(c.picture, isNull);
    expect(c.roles, isEmpty);
  });

  test('UserClaims roles filter out non-string entries', () {
    const c = UserClaims({
      'roles': <dynamic>['ok', 1, null, 'good'],
    });
    expect(c.roles, ['ok', 'good']);
  });

  group('Antinvestor typed getters', () {
    test('contactId / tenantId / partitionId surface the claim values', () {
      const c = UserClaims({
        'sub': 'u-1',
        'contact_id': 'contact-abc',
        'tenant_id': 'tenant-xyz',
        'partition_id': 'partition-42',
      });
      expect(c.contactId, 'contact-abc');
      expect(c.tenantId, 'tenant-xyz');
      expect(c.partitionId, 'partition-42');
    });

    test('typed getters return null when claim missing or wrong type', () {
      const c = UserClaims({
        'contact_id': 123, // not a string
      });
      expect(c.contactId, isNull);
      expect(c.tenantId, isNull);
      expect(c.partitionId, isNull);
    });
  });

  group('customClaims', () {
    test('contains only non-OIDC-standard claims', () {
      const c = UserClaims({
        // Standard OIDC — must be excluded.
        'iss': 'https://idp.example.com',
        'sub': 'u-1',
        'aud': 'client',
        'exp': 9999999999,
        'iat': 1234567890,
        'nonce': 'n',
        'email': 'a@b.c',
        'email_verified': true,
        'name': 'Alice',
        'preferred_username': 'alice',
        'picture': 'https://cdn/x.png',
        'locale': 'en',
        'updated_at': 1234567890,
        // Non-standard — must be retained.
        'contact_id': 'contact-abc',
        'tenant_id': 'tenant-xyz',
        'partition_id': 'partition-42',
        'roles': <dynamic>['admin'],
        'custom_flag': true,
      });
      final custom = c.customClaims;
      expect(custom.keys, containsAll(<String>[
        'contact_id',
        'tenant_id',
        'partition_id',
        'roles',
        'custom_flag',
      ]));
      // Standard keys are filtered out.
      expect(custom.containsKey('iss'), isFalse);
      expect(custom.containsKey('sub'), isFalse);
      expect(custom.containsKey('email'), isFalse);
      expect(custom.containsKey('email_verified'), isFalse);
      expect(custom.containsKey('preferred_username'), isFalse);
      expect(custom.containsKey('picture'), isFalse);
      expect(custom.containsKey('updated_at'), isFalse);
    });

    test('customClaims is empty when only standard claims are present', () {
      const c = UserClaims({
        'sub': 'u-1',
        'email': 'a@b.c',
      });
      expect(c.customClaims, isEmpty);
    });
  });
}
