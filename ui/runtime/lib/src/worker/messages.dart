import 'dart:convert';
import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/credentials/native_credential.dart';
import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/models/api_response.dart';
import 'package:antinvestor_auth_runtime/src/models/auth_state.dart';
import 'package:antinvestor_auth_runtime/src/models/security_event.dart';

/// Wire-format key for the discriminator field used by every message.
const String _kind = 'kind';
const String _corrId = 'correlationId';

/// Union of all requests the main isolate sends to the token worker.
///
/// Every variant is serialisable via [toMap] / [fromMap] so it can travel
/// across a `SendPort` (only primitives + maps + lists survive isolate
/// boundaries). A [correlationId] is attached by the caller so the
/// matching [WorkerEvent] can be routed back.
sealed class WorkerRequest {
  const WorkerRequest({required this.correlationId});

  final String correlationId;

  Map<String, Object?> toMap();

  /// Dispatches on the `kind` field.
  static WorkerRequest fromMap(Map<String, Object?> map) {
    final kind = map[_kind];
    return switch (kind) {
      'init' => InitRequest._fromMap(map),
      'prepareAuth' => PrepareAuthRequest._fromMap(map),
      'completeAuth' => CompleteAuthRequest._fromMap(map),
      'completeNativeCredential' =>
        CompleteNativeCredentialRequest._fromMap(map),
      'fetch' => FetchRequest._fromMap(map),
      'upload' => UploadRequest._fromMap(map),
      'getRoles' => GetRolesRequest._fromMap(map),
      'getClaims' => GetClaimsRequest._fromMap(map),
      'logout' => LogoutRequest._fromMap(map),
      'destroy' => DestroyRequest._fromMap(map),
      _ => throw FormatException('unknown WorkerRequest kind: $kind'),
    };
  }
}

final class InitRequest extends WorkerRequest {
  const InitRequest({required super.correlationId});

  @override
  Map<String, Object?> toMap() => {_kind: 'init', _corrId: correlationId};

  factory InitRequest._fromMap(Map<String, Object?> map) =>
      InitRequest(correlationId: map[_corrId] as String);
}

final class PrepareAuthRequest extends WorkerRequest {
  const PrepareAuthRequest({required super.correlationId});

  @override
  Map<String, Object?> toMap() =>
      {_kind: 'prepareAuth', _corrId: correlationId};

  factory PrepareAuthRequest._fromMap(Map<String, Object?> map) =>
      PrepareAuthRequest(correlationId: map[_corrId] as String);
}

final class CompleteAuthRequest extends WorkerRequest {
  const CompleteAuthRequest({
    required super.correlationId,
    required this.code,
    required this.verifier,
    required this.state,
    required this.nonce,
  });

  final String code;
  final String verifier;
  final String state;
  final String nonce;

  @override
  Map<String, Object?> toMap() => {
        _kind: 'completeAuth',
        _corrId: correlationId,
        'code': code,
        'verifier': verifier,
        'state': state,
        'nonce': nonce,
      };

  factory CompleteAuthRequest._fromMap(Map<String, Object?> map) =>
      CompleteAuthRequest(
        correlationId: map[_corrId] as String,
        code: map['code'] as String,
        verifier: map['verifier'] as String,
        state: map['state'] as String,
        nonce: map['nonce'] as String,
      );
}

final class CompleteNativeCredentialRequest extends WorkerRequest {
  const CompleteNativeCredentialRequest({
    required super.correlationId,
    required this.provider,
    required this.idToken,
    required this.autoSelected,
    required this.expectedNonce,
    this.authorizationCode,
    this.nonce,
  });

  final NativeCredentialProviderKind provider;
  final String idToken;
  final String? authorizationCode;
  final String? nonce;
  final bool autoSelected;
  final String expectedNonce;

  NativeCredentialResult toResult() => NativeCredentialResult(
        provider: provider,
        idToken: idToken,
        autoSelected: autoSelected,
        authorizationCode: authorizationCode,
        nonce: nonce,
      );

  @override
  Map<String, Object?> toMap() => {
        _kind: 'completeNativeCredential',
        _corrId: correlationId,
        'provider': provider.name,
        'idToken': idToken,
        'autoSelected': autoSelected,
        'expectedNonce': expectedNonce,
        if (authorizationCode != null) 'authorizationCode': authorizationCode,
        if (nonce != null) 'nonce': nonce,
      };

  factory CompleteNativeCredentialRequest._fromMap(Map<String, Object?> map) {
    final name = map['provider'] as String;
    final provider = NativeCredentialProviderKind.values.firstWhere(
      (v) => v.name == name,
    );
    return CompleteNativeCredentialRequest(
      correlationId: map[_corrId] as String,
      provider: provider,
      idToken: map['idToken'] as String,
      autoSelected: map['autoSelected'] as bool,
      expectedNonce: map['expectedNonce'] as String,
      authorizationCode: map['authorizationCode'] as String?,
      nonce: map['nonce'] as String?,
    );
  }
}

final class FetchRequest extends WorkerRequest {
  const FetchRequest({
    required super.correlationId,
    required this.path,
    required this.method,
    this.headers,
    this.body,
    this.timeoutMs,
  });

  final String path;
  final String method;
  final Map<String, String>? headers;

  /// [body] is serialised as base64 when binary, raw string when text.
  /// Null when there is no body.
  final String? body;
  final int? timeoutMs;

  @override
  Map<String, Object?> toMap() => {
        _kind: 'fetch',
        _corrId: correlationId,
        'path': path,
        'method': method,
        if (headers != null) 'headers': headers,
        if (body != null) 'body': body,
        if (timeoutMs != null) 'timeoutMs': timeoutMs,
      };

  factory FetchRequest._fromMap(Map<String, Object?> map) => FetchRequest(
        correlationId: map[_corrId] as String,
        path: map['path'] as String,
        method: map['method'] as String,
        headers: _mapOfString(map['headers']),
        body: map['body'] as String?,
        timeoutMs: map['timeoutMs'] as int?,
      );
}

final class UploadRequest extends WorkerRequest {
  const UploadRequest({
    required super.correlationId,
    required this.path,
    required this.fieldName,
    required this.filename,
    required this.contentType,
    required this.bytes,
    this.headers,
    this.timeoutMs,
  });

  final String path;
  final String fieldName;
  final String filename;
  final String contentType;

  /// Raw bytes — the buffer travels as `TransferableTypedData` at the
  /// isolate boundary; here we keep [Uint8List] for typing.
  final Uint8List bytes;
  final Map<String, String>? headers;
  final int? timeoutMs;

  @override
  Map<String, Object?> toMap() => {
        _kind: 'upload',
        _corrId: correlationId,
        'path': path,
        'fieldName': fieldName,
        'filename': filename,
        'contentType': contentType,
        'bytes': bytes,
        if (headers != null) 'headers': headers,
        if (timeoutMs != null) 'timeoutMs': timeoutMs,
      };

  factory UploadRequest._fromMap(Map<String, Object?> map) => UploadRequest(
        correlationId: map[_corrId] as String,
        path: map['path'] as String,
        fieldName: map['fieldName'] as String,
        filename: map['filename'] as String,
        contentType: map['contentType'] as String,
        bytes: _asBytes(map['bytes']),
        headers: _mapOfString(map['headers']),
        timeoutMs: map['timeoutMs'] as int?,
      );
}

final class GetRolesRequest extends WorkerRequest {
  const GetRolesRequest({required super.correlationId});

  @override
  Map<String, Object?> toMap() =>
      {_kind: 'getRoles', _corrId: correlationId};

  factory GetRolesRequest._fromMap(Map<String, Object?> map) =>
      GetRolesRequest(correlationId: map[_corrId] as String);
}

final class GetClaimsRequest extends WorkerRequest {
  const GetClaimsRequest({required super.correlationId});

  @override
  Map<String, Object?> toMap() =>
      {_kind: 'getClaims', _corrId: correlationId};

  factory GetClaimsRequest._fromMap(Map<String, Object?> map) =>
      GetClaimsRequest(correlationId: map[_corrId] as String);
}

final class LogoutRequest extends WorkerRequest {
  const LogoutRequest({required super.correlationId});

  @override
  Map<String, Object?> toMap() => {_kind: 'logout', _corrId: correlationId};

  factory LogoutRequest._fromMap(Map<String, Object?> map) =>
      LogoutRequest(correlationId: map[_corrId] as String);
}

final class DestroyRequest extends WorkerRequest {
  const DestroyRequest({required super.correlationId});

  @override
  Map<String, Object?> toMap() =>
      {_kind: 'destroy', _corrId: correlationId};

  factory DestroyRequest._fromMap(Map<String, Object?> map) =>
      DestroyRequest(correlationId: map[_corrId] as String);
}

/// Union of all events the worker emits. Some events are correlated (they
/// answer a specific [WorkerRequest]); others are broadcast (state
/// changes, security signals).
sealed class WorkerEvent {
  const WorkerEvent({this.correlationId});

  final String? correlationId;

  Map<String, Object?> toMap();

  static WorkerEvent fromMap(Map<String, Object?> map) {
    final kind = map[_kind];
    return switch (kind) {
      'ready' => ReadyEvent._fromMap(map),
      'state' => StateEvent._fromMap(map),
      'authUrl' => AuthUrlEvent._fromMap(map),
      'response' => ResponseEvent._fromMap(map),
      'error' => ErrorEvent._fromMap(map),
      'ok' => OkEvent._fromMap(map),
      'completeNativeCredentialOk' =>
        CompleteNativeCredentialOkEvent._fromMap(map),
      'roles' => RolesEvent._fromMap(map),
      'claims' => ClaimsEvent._fromMap(map),
      'securityEvent' => SecurityEventWire._fromMap(map),
      _ => throw FormatException('unknown WorkerEvent kind: $kind'),
    };
  }
}

final class ReadyEvent extends WorkerEvent {
  const ReadyEvent({super.correlationId});

  @override
  Map<String, Object?> toMap() => {_kind: 'ready', _corrId: correlationId};

  factory ReadyEvent._fromMap(Map<String, Object?> map) =>
      ReadyEvent(correlationId: map[_corrId] as String?);
}

final class StateEvent extends WorkerEvent {
  const StateEvent({required this.state, super.correlationId});

  final AuthState state;

  @override
  Map<String, Object?> toMap() => {
        _kind: 'state',
        _corrId: correlationId,
        'state': state.name,
      };

  factory StateEvent._fromMap(Map<String, Object?> map) => StateEvent(
        state: AuthState.values.firstWhere((s) => s.name == map['state']),
        correlationId: map[_corrId] as String?,
      );
}

final class AuthUrlEvent extends WorkerEvent {
  const AuthUrlEvent({
    required this.url,
    required this.verifier,
    required this.state,
    required this.nonce,
    super.correlationId,
  });

  final String url;
  final String verifier;
  final String state;
  final String nonce;

  @override
  Map<String, Object?> toMap() => {
        _kind: 'authUrl',
        _corrId: correlationId,
        'url': url,
        'verifier': verifier,
        'state': state,
        'nonce': nonce,
      };

  factory AuthUrlEvent._fromMap(Map<String, Object?> map) => AuthUrlEvent(
        correlationId: map[_corrId] as String?,
        url: map['url'] as String,
        verifier: map['verifier'] as String,
        state: map['state'] as String,
        nonce: map['nonce'] as String,
      );
}

final class ResponseEvent extends WorkerEvent {
  const ResponseEvent({required this.response, super.correlationId});

  final ApiResponse response;

  @override
  Map<String, Object?> toMap() => {
        _kind: 'response',
        _corrId: correlationId,
        'status': response.status,
        'headers': response.headers,
        'body': response.body,
      };

  factory ResponseEvent._fromMap(Map<String, Object?> map) => ResponseEvent(
        correlationId: map[_corrId] as String?,
        response: ApiResponse(
          status: map['status'] as int,
          headers: _mapOfString(map['headers']) ?? const {},
          body: _asBytes(map['body']),
        ),
      );
}

final class ErrorEvent extends WorkerEvent {
  const ErrorEvent({
    required this.code,
    required this.message,
    this.traceId,
    super.correlationId,
  });

  final AuthErrorCode code;
  final String message;
  final String? traceId;

  @override
  Map<String, Object?> toMap() => {
        _kind: 'error',
        _corrId: correlationId,
        'code': code.name,
        'message': message,
        if (traceId != null) 'traceId': traceId,
      };

  factory ErrorEvent._fromMap(Map<String, Object?> map) => ErrorEvent(
        correlationId: map[_corrId] as String?,
        code: AuthErrorCode.values.firstWhere((c) => c.name == map['code']),
        message: map['message'] as String,
        traceId: map['traceId'] as String?,
      );

  /// Converts back into a throwable [AuthError]. Useful on the caller side
  /// when translating isolate errors into ordinary exceptions.
  AuthError toAuthError() =>
      AuthError(code, message, traceId: traceId);
}

final class OkEvent extends WorkerEvent {
  const OkEvent({super.correlationId});

  @override
  Map<String, Object?> toMap() => {_kind: 'ok', _corrId: correlationId};

  factory OkEvent._fromMap(Map<String, Object?> map) =>
      OkEvent(correlationId: map[_corrId] as String?);
}

/// Success ack for [CompleteNativeCredentialRequest]. Carries the
/// [NativeCredentialProviderKind] so the main-isolate side can emit
/// matching telemetry / credential events after the worker has
/// transitioned to `authenticated`.
final class CompleteNativeCredentialOkEvent extends WorkerEvent {
  const CompleteNativeCredentialOkEvent({
    required this.provider,
    super.correlationId,
  });

  final NativeCredentialProviderKind provider;

  @override
  Map<String, Object?> toMap() => {
        _kind: 'completeNativeCredentialOk',
        _corrId: correlationId,
        'provider': provider.name,
      };

  factory CompleteNativeCredentialOkEvent._fromMap(Map<String, Object?> map) {
    final name = map['provider'] as String;
    final provider = NativeCredentialProviderKind.values.firstWhere(
      (v) => v.name == name,
    );
    return CompleteNativeCredentialOkEvent(
      correlationId: map[_corrId] as String?,
      provider: provider,
    );
  }
}

final class RolesEvent extends WorkerEvent {
  const RolesEvent({required this.roles, super.correlationId});

  final List<String> roles;

  @override
  Map<String, Object?> toMap() => {
        _kind: 'roles',
        _corrId: correlationId,
        'roles': roles,
      };

  factory RolesEvent._fromMap(Map<String, Object?> map) => RolesEvent(
        correlationId: map[_corrId] as String?,
        roles: (map['roles'] as List).cast<String>(),
      );
}

final class ClaimsEvent extends WorkerEvent {
  const ClaimsEvent({required this.claims, super.correlationId});

  final Map<String, dynamic> claims;

  @override
  Map<String, Object?> toMap() => {
        _kind: 'claims',
        _corrId: correlationId,
        // Stringify to guarantee the map survives SendPort on every
        // platform; some contents (e.g. nested DateTime) aren't
        // transferable otherwise.
        'claimsJson': json.encode(claims),
      };

  factory ClaimsEvent._fromMap(Map<String, Object?> map) => ClaimsEvent(
        correlationId: map[_corrId] as String?,
        claims:
            (json.decode(map['claimsJson'] as String) as Map<String, dynamic>),
      );
}

/// Wire mirror of [SecurityEvent]. We carry a kind discriminator plus an
/// ISO-8601 timestamp; the caller reconstructs the sealed hierarchy on
/// receipt. Kept separate from the domain class to avoid coupling
/// serialisation to public model invariants.
final class SecurityEventWire extends WorkerEvent {
  const SecurityEventWire({
    required this.event,
    super.correlationId,
  });

  final SecurityEvent event;

  @override
  Map<String, Object?> toMap() {
    final kind = switch (event) {
      RefreshReuseDetected() => 'refreshReuseDetected',
      StorageCorruption() => 'storageCorruption',
      BindingInvalidated() => 'bindingInvalidated',
      LoggedOutElsewhere() => 'loggedOutElsewhere',
    };
    return {
      _kind: 'securityEvent',
      _corrId: correlationId,
      'eventKind': kind,
      'at': event.at.toUtc().toIso8601String(),
    };
  }

  factory SecurityEventWire._fromMap(Map<String, Object?> map) {
    final at = DateTime.parse(map['at'] as String);
    final eventKind = map['eventKind'] as String;
    final ev = switch (eventKind) {
      'refreshReuseDetected' => SecurityEvent.refreshReuseDetected(at),
      'storageCorruption' => SecurityEvent.storageCorruption(at),
      'bindingInvalidated' => SecurityEvent.bindingInvalidated(at),
      'loggedOutElsewhere' => SecurityEvent.loggedOutElsewhere(at),
      _ => throw FormatException('unknown security event kind: $eventKind'),
    };
    return SecurityEventWire(
      event: ev,
      correlationId: map[_corrId] as String?,
    );
  }
}

Map<String, String>? _mapOfString(Object? raw) {
  if (raw is! Map) return null;
  return raw.map((k, v) => MapEntry(k.toString(), v.toString()));
}

Uint8List _asBytes(Object? raw) {
  if (raw is Uint8List) return raw;
  if (raw is List<int>) return Uint8List.fromList(raw);
  if (raw is List) return Uint8List.fromList(raw.cast<int>());
  throw const FormatException('expected byte buffer');
}
