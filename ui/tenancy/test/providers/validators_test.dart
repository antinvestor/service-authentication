import 'package:antinvestor_ui_tenancy/antinvestor_ui_tenancy.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('v2 OAuth contract validation', () {
    test('accepts subdomain HTTPS resource recipients', () {
      expect(
        validateResourceRecipients(
          'https://profile.stawi.org, https://tenancy.stawi.org',
        ),
        isNull,
      );
    });

    test('accepts legacy path HTTPS resource recipients', () {
      expect(
        validateResourceRecipients(
          'https://api.stawi.org/profile, https://api.stawi.org/tenancy',
        ),
        isNull,
      );
    });

    test('requires at least one resource recipient', () {
      expect(validateResourceRecipients(null), isNotNull);
      expect(validateResourceRecipients(''), isNotNull);
    });

    for (final recipient in [
      'http://profile.stawi.org',
      'https://profile.stawi.org/',
      'https://profile.stawi.org:443',
      'https://profile.stawi.org?tenant=1',
      'https://api.stawi.org/profile/',
      'https://api.stawi.org:443/profile',
      'https://api.stawi.org/profile?tenant=1',
    ]) {
      test('rejects non-canonical recipient $recipient', () {
        expect(validateResourceRecipients(recipient), isNotNull);
      });
    }

    test('rejects removed OAuth flow values', () {
      expect(validateGrantTypes('implicit'), isNotNull);
      expect(validateResponseTypes('id_token'), isNotNull);
    });

    test('client names follow the v2 minimum length', () {
      expect(validateClientName('ab'), isNotNull);
      expect(validateClientName('abc'), isNull);
    });
  });
}
