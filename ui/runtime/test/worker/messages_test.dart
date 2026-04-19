import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/models/api_response.dart';
import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:antinvestor_auth_runtime/src/models/security_event.dart';
import 'package:antinvestor_auth_runtime/src/worker/messages.dart';
import 'package:flutter_test/flutter_test.dart';

T _roundTripRequest<T extends WorkerRequest>(T req) {
  final map = req.toMap();
  return WorkerRequest.fromMap(map) as T;
}

T _roundTripEvent<T extends WorkerEvent>(T ev) {
  final map = ev.toMap();
  return WorkerEvent.fromMap(map) as T;
}

void main() {
  group('WorkerRequest', () {
    test('init round-trips', () {
      final r = _roundTripRequest(const InitRequest(correlationId: 'c-1'));
      expect(r.correlationId, 'c-1');
    });

    test('prepareAuth round-trips', () {
      final r = _roundTripRequest(
          const PrepareAuthRequest(correlationId: 'c-2'));
      expect(r.correlationId, 'c-2');
    });

    test('completeAuth round-trips all fields', () {
      final orig = const CompleteAuthRequest(
        correlationId: 'c-3',
        code: 'CODE',
        verifier: 'VERIF',
        state: 'STATE',
        nonce: 'NONCE',
      );
      final r = _roundTripRequest(orig);
      expect(r.code, 'CODE');
      expect(r.verifier, 'VERIF');
      expect(r.state, 'STATE');
      expect(r.nonce, 'NONCE');
    });

    test('fetch round-trips headers and body', () {
      final orig = const FetchRequest(
        correlationId: 'c-4',
        path: '/users',
        method: 'GET',
        headers: {'X-Trace': 't1'},
        timeoutMs: 15000,
      );
      final r = _roundTripRequest(orig);
      expect(r.path, '/users');
      expect(r.method, 'GET');
      expect(r.headers, {'X-Trace': 't1'});
      expect(r.timeoutMs, 15000);
    });

    test('upload round-trips binary payload', () {
      final bytes = Uint8List.fromList(List<int>.generate(128, (i) => i));
      final orig = UploadRequest(
        correlationId: 'c-5',
        path: '/media',
        fieldName: 'file',
        filename: 'a.bin',
        contentType: 'application/octet-stream',
        bytes: bytes,
      );
      final r = _roundTripRequest(orig);
      expect(r.bytes, bytes);
      expect(r.filename, 'a.bin');
      expect(r.contentType, 'application/octet-stream');
    });

    test('completeNativeCredential round-trips all fields', () {
      final orig = const CompleteNativeCredentialRequest(
        correlationId: 'c-nc',
        provider: NativeCredentialProviderKind.google,
        idToken: 'id-token-xyz',
        autoSelected: true,
        expectedNonce: 'expected-nonce',
        nonce: 'nonce',
        authorizationCode: 'auth-code',
      );
      final r = _roundTripRequest(orig);
      expect(r.provider, NativeCredentialProviderKind.google);
      expect(r.idToken, 'id-token-xyz');
      expect(r.autoSelected, true);
      expect(r.expectedNonce, 'expected-nonce');
      expect(r.nonce, 'nonce');
      expect(r.authorizationCode, 'auth-code');
      final result = r.toResult();
      expect(result.provider, NativeCredentialProviderKind.google);
      expect(result.idToken, 'id-token-xyz');
    });

    test('getRoles, getClaims, logout, destroy round-trip', () {
      expect(_roundTripRequest(
          const GetRolesRequest(correlationId: 'a')).correlationId, 'a');
      expect(_roundTripRequest(
          const GetClaimsRequest(correlationId: 'b')).correlationId, 'b');
      expect(_roundTripRequest(
          const LogoutRequest(correlationId: 'c')).correlationId, 'c');
      expect(_roundTripRequest(
          const DestroyRequest(correlationId: 'd')).correlationId, 'd');
    });

    test('unknown kind throws FormatException', () {
      expect(
        () => WorkerRequest.fromMap({'kind': 'nope', 'correlationId': 'x'}),
        throwsA(isA<FormatException>()),
      );
    });
  });

  group('WorkerEvent', () {
    test('ready + ok round-trip', () {
      final r = _roundTripEvent(const ReadyEvent(correlationId: 'c-1'));
      expect(r.correlationId, 'c-1');
      final o = _roundTripEvent(const OkEvent(correlationId: 'c-2'));
      expect(o.correlationId, 'c-2');
    });

    test('state round-trips AuthState by name', () {
      for (final s in AuthState.values) {
        final r = _roundTripEvent(StateEvent(state: s));
        expect(r.state, s);
      }
    });

    test('authUrl round-trips', () {
      final r = _roundTripEvent(const AuthUrlEvent(
        correlationId: 'c-3',
        url: 'https://idp/auth?...',
        verifier: 'v',
        state: 's',
        nonce: 'n',
      ));
      expect(r.url, 'https://idp/auth?...');
      expect(r.verifier, 'v');
      expect(r.state, 's');
      expect(r.nonce, 'n');
    });

    test('response round-trips body + headers', () {
      final bytes = Uint8List.fromList([1, 2, 3, 4, 5]);
      final r = _roundTripEvent(ResponseEvent(
        correlationId: 'c-4',
        response: ApiResponse(
          status: 200,
          headers: const {'content-type': 'application/json'},
          body: bytes,
        ),
      ));
      expect(r.response.status, 200);
      expect(r.response.headers['content-type'], 'application/json');
      expect(r.response.body, bytes);
    });

    test('error round-trips code, message, traceId', () {
      final r = _roundTripEvent(const ErrorEvent(
        correlationId: 'c-5',
        code: AuthErrorCode.apiUnauthorized,
        message: 'boom',
        traceId: 'trace-xyz',
      ));
      expect(r.code, AuthErrorCode.apiUnauthorized);
      expect(r.message, 'boom');
      expect(r.traceId, 'trace-xyz');

      final err = r.toAuthError();
      expect(err.code, AuthErrorCode.apiUnauthorized);
      expect(err.traceId, 'trace-xyz');
    });

    test('completeNativeCredentialOk round-trips provider', () {
      final r = _roundTripEvent(const CompleteNativeCredentialOkEvent(
        correlationId: 'c-nc-ok',
        provider: NativeCredentialProviderKind.apple,
      ));
      expect(r.provider, NativeCredentialProviderKind.apple);
      expect(r.correlationId, 'c-nc-ok');
    });

    test('roles + claims round-trip', () {
      final roles = _roundTripEvent(const RolesEvent(
        correlationId: 'c-6',
        roles: ['admin', 'user'],
      ));
      expect(roles.roles, ['admin', 'user']);

      final claims = _roundTripEvent(const ClaimsEvent(
        correlationId: 'c-7',
        claims: {
          'sub': 'u-1',
          'email': 'a@b.c',
          'roles': ['admin'],
        },
      ));
      expect(claims.claims['sub'], 'u-1');
      expect(claims.claims['roles'], ['admin']);
    });

    test('securityEvent round-trips every variant', () {
      final at = DateTime.utc(2026, 4, 19, 12, 0, 0);
      for (final ev in [
        SecurityEvent.refreshReuseDetected(at),
        SecurityEvent.storageCorruption(at),
        SecurityEvent.bindingInvalidated(at),
        SecurityEvent.loggedOutElsewhere(at),
      ]) {
        final w = SecurityEventWire(event: ev);
        final back = _roundTripEvent(w);
        expect(back.event.runtimeType, ev.runtimeType);
        expect(back.event.at, at);
      }
    });

    test('unknown event kind throws FormatException', () {
      expect(
        () => WorkerEvent.fromMap({'kind': 'nope'}),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
