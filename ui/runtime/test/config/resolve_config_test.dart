import 'package:antinvestor_auth_runtime/src/config/auth_config.dart';
import 'package:antinvestor_auth_runtime/src/config/resolve_config.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('throws invalidConfig when clientId is empty', () {
    expect(
      () => resolveConfig(const AuthConfig(
        clientId: '',
        idpBaseUrl: 'https://i',
        apiBaseUrl: 'https://a',
        redirectScheme: 'x',
      )),
      throwsA(isA<AuthError>()
          .having((e) => e.code, 'code', AuthErrorCode.invalidConfig)),
    );
  });

  test('throws invalidConfig when idpBaseUrl is empty', () {
    expect(
      () => resolveConfig(const AuthConfig(
        clientId: 'c',
        idpBaseUrl: '',
        apiBaseUrl: 'https://a',
        redirectScheme: 'x',
      )),
      throwsA(isA<AuthError>()
          .having((e) => e.code, 'code', AuthErrorCode.invalidConfig)),
    );
  });

  test('throws invalidConfig when apiBaseUrl is empty', () {
    expect(
      () => resolveConfig(const AuthConfig(
        clientId: 'c',
        idpBaseUrl: 'https://i',
        apiBaseUrl: '',
        redirectScheme: 'x',
      )),
      throwsA(isA<AuthError>()
          .having((e) => e.code, 'code', AuthErrorCode.invalidConfig)),
    );
  });

  test('throws invalidConfig when redirectScheme is empty', () {
    expect(
      () => resolveConfig(const AuthConfig(
        clientId: 'c',
        idpBaseUrl: 'https://i',
        apiBaseUrl: 'https://a',
        redirectScheme: '',
      )),
      throwsA(isA<AuthError>()
          .having((e) => e.code, 'code', AuthErrorCode.invalidConfig)),
    );
  });

  test('strips trailing slashes and namespaces', () {
    final cfg = resolveConfig(const AuthConfig(
      clientId: 'c',
      idpBaseUrl: 'https://i/',
      apiBaseUrl: 'https://a/',
      redirectScheme: 'com.example.app',
    ));
    expect(cfg.idpBaseUrl, 'https://i');
    expect(cfg.apiBaseUrl, 'https://a');
    expect(cfg.namespace, 'c::https://i');
    expect(cfg.scopes, contains('offline_access'));
  });

  test('applies default scopes when caller omits them', () {
    final cfg = resolveConfig(const AuthConfig(
      clientId: 'c',
      idpBaseUrl: 'https://i',
      apiBaseUrl: 'https://a',
      redirectScheme: 'x',
    ));
    expect(cfg.scopes, ['openid', 'profile', 'email', 'offline_access']);
  });

  test('honors timeout overrides partially', () {
    final cfg = resolveConfig(const AuthConfig(
      clientId: 'c',
      idpBaseUrl: 'https://i',
      apiBaseUrl: 'https://a',
      redirectScheme: 'x',
      apiTimeout: Duration(seconds: 5),
    ));
    expect(cfg.apiTimeout, const Duration(seconds: 5));
    expect(cfg.tokenTimeout, const Duration(seconds: 10));
    expect(cfg.discoveryTimeout, const Duration(seconds: 10));
    expect(cfg.uploadTimeout, const Duration(seconds: 60));
  });

  test('keeps caller-provided scopes', () {
    final cfg = resolveConfig(const AuthConfig(
      clientId: 'c',
      idpBaseUrl: 'https://i',
      apiBaseUrl: 'https://a',
      redirectScheme: 'x',
      scopes: ['openid', 'profile'],
    ));
    expect(cfg.scopes, ['openid', 'profile']);
  });

  test('AuthConfig has value equality', () {
    const a = AuthConfig(
      clientId: 'c',
      idpBaseUrl: 'https://i',
      apiBaseUrl: 'https://a',
      redirectScheme: 'x',
    );
    const b = AuthConfig(
      clientId: 'c',
      idpBaseUrl: 'https://i',
      apiBaseUrl: 'https://a',
      redirectScheme: 'x',
    );
    expect(a, equals(b));
    expect(a.hashCode, b.hashCode);
  });

  group('redirectUri', () {
    test(
        'defaults to {scheme}://callback when only redirectScheme is provided',
        () {
      final cfg = resolveConfig(const AuthConfig(
        clientId: 'c',
        idpBaseUrl: 'https://i',
        apiBaseUrl: 'https://a',
        redirectScheme: 'com.example.app',
      ));
      expect(cfg.redirectUri, 'com.example.app://callback');
    });

    test('explicit redirectUri takes precedence over redirectScheme', () {
      final cfg = resolveConfig(const AuthConfig(
        clientId: 'c',
        idpBaseUrl: 'https://i',
        apiBaseUrl: 'https://a',
        redirectScheme: 'com.example.app',
        redirectUri: 'http://localhost:5173/auth',
      ));
      expect(cfg.redirectUri, 'http://localhost:5173/auth');
    });

    test('explicit redirectUri works when redirectScheme is empty', () {
      final cfg = resolveConfig(const AuthConfig(
        clientId: 'c',
        idpBaseUrl: 'https://i',
        apiBaseUrl: 'https://a',
        redirectScheme: '',
        redirectUri: 'http://localhost:5173/auth',
      ));
      expect(cfg.redirectUri, 'http://localhost:5173/auth');
    });

    test(
        'throws invalidConfig when neither redirectUri nor redirectScheme '
        'is supplied', () {
      expect(
        () => resolveConfig(const AuthConfig(
          clientId: 'c',
          idpBaseUrl: 'https://i',
          apiBaseUrl: 'https://a',
          redirectScheme: '',
        )),
        throwsA(isA<AuthError>()
            .having((e) => e.code, 'code', AuthErrorCode.invalidConfig)),
      );
    });
  });

  group('audiences', () {
    test('defaults to empty list when omitted', () {
      final cfg = resolveConfig(const AuthConfig(
        clientId: 'c',
        idpBaseUrl: 'https://i',
        apiBaseUrl: 'https://a',
        redirectScheme: 'x',
      ));
      expect(cfg.audiences, isEmpty);
    });

    test('carries through when caller supplies them', () {
      final cfg = resolveConfig(const AuthConfig(
        clientId: 'c',
        idpBaseUrl: 'https://i',
        apiBaseUrl: 'https://a',
        redirectScheme: 'x',
        audiences: ['svc-a', 'svc-b', 'svc-c'],
      ));
      expect(cfg.audiences, ['svc-a', 'svc-b', 'svc-c']);
    });

    test('resolved audiences list is immutable', () {
      final cfg = resolveConfig(const AuthConfig(
        clientId: 'c',
        idpBaseUrl: 'https://i',
        apiBaseUrl: 'https://a',
        redirectScheme: 'x',
        audiences: ['svc-a'],
      ));
      expect(() => cfg.audiences.add('mutated'), throwsUnsupportedError);
    });
  });
}
