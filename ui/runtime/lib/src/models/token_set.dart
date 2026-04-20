import 'package:equatable/equatable.dart';

/// Token presentation mode negotiated with the IdP.
enum TokenType {
  bearer,
  dpop;

  String get headerValue => switch (this) {
        TokenType.bearer => 'Bearer',
        TokenType.dpop => 'DPoP',
      };

  /// Parses a `token_type` response field; defaults to [TokenType.bearer]
  /// on null/unknown values to match the JS runtime behaviour.
  static TokenType fromString(String? v) {
    if (v == null) return TokenType.bearer;
    return v.toLowerCase() == 'dpop' ? TokenType.dpop : TokenType.bearer;
  }
}

/// Immutable token bundle returned by the IdP.
///
/// [expiresAt] is the absolute clock-time the access token stops being
/// valid. The refresh token lives long enough for rotation.
class TokenSet extends Equatable {
  const TokenSet({
    required this.accessToken,
    required this.refreshToken,
    required this.expiresAt,
    required this.tokenType,
    this.idToken,
  });

  final String accessToken;
  final String refreshToken;
  final DateTime expiresAt;
  final TokenType tokenType;
  final String? idToken;

  bool isExpiredAt(DateTime now) =>
      !now.isBefore(expiresAt); // `now >= expiresAt`

  @override
  List<Object?> get props =>
      [accessToken, refreshToken, expiresAt, tokenType, idToken];
}
