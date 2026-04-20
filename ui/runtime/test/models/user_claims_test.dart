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
}
