import 'package:antinvestor_auth_runtime/src/models/token_set.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('TokenSet constructs with bearer + DPoP variants', () {
    final now = DateTime.utc(2026, 1, 1);
    final bearer = TokenSet(
      accessToken: 'a',
      refreshToken: 'r',
      expiresAt: now,
      tokenType: TokenType.bearer,
    );
    expect(bearer.accessToken, 'a');
    expect(bearer.tokenType, TokenType.bearer);
    expect(bearer.idToken, isNull);

    final dpop = TokenSet(
      accessToken: 'a2',
      refreshToken: 'r2',
      expiresAt: now,
      tokenType: TokenType.dpop,
      idToken: 'id',
    );
    expect(dpop.tokenType, TokenType.dpop);
    expect(dpop.idToken, 'id');
  });

  test('isExpiredAt uses expiresAt comparison', () {
    final expiry = DateTime.utc(2026, 1, 1, 12, 0, 0);
    final t = TokenSet(
      accessToken: 'a',
      refreshToken: 'r',
      expiresAt: expiry,
      tokenType: TokenType.bearer,
    );
    expect(t.isExpiredAt(DateTime.utc(2026, 1, 1, 11, 59, 0)), isFalse);
    expect(t.isExpiredAt(DateTime.utc(2026, 1, 1, 12, 0, 0)), isTrue);
    expect(t.isExpiredAt(DateTime.utc(2026, 1, 1, 12, 0, 1)), isTrue);
  });

  test('TokenSet equality and hashCode are value-based', () {
    final now = DateTime.utc(2026, 1, 1);
    final a = TokenSet(
      accessToken: 'a',
      refreshToken: 'r',
      expiresAt: now,
      tokenType: TokenType.bearer,
    );
    final b = TokenSet(
      accessToken: 'a',
      refreshToken: 'r',
      expiresAt: now,
      tokenType: TokenType.bearer,
    );
    expect(a, equals(b));
    expect(a.hashCode, b.hashCode);
  });

  test('TokenType.fromString normalizes DPoP/Bearer case-insensitively', () {
    expect(TokenType.fromString('Bearer'), TokenType.bearer);
    expect(TokenType.fromString('bearer'), TokenType.bearer);
    expect(TokenType.fromString('DPoP'), TokenType.dpop);
    expect(TokenType.fromString('dpop'), TokenType.dpop);
    expect(TokenType.fromString(null), TokenType.bearer);
    expect(TokenType.fromString('unknown'), TokenType.bearer);
  });
}
