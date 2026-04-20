import 'dart:async';
import 'dart:isolate';

import 'package:antinvestor_auth_runtime/src/errors/auth_error.dart';
import 'package:antinvestor_auth_runtime/src/worker/messages.dart';

/// Handle to a spawned token isolate.
///
/// Owns the [Isolate] reference, the bi-directional ports, and lifecycle
/// bookkeeping. Callers typically go through [IsolatedTokenWorkerProxy]
/// rather than the handle directly.
///
/// ## Why "scaffolding"?
///
/// v0.1 ships the isolate path disabled by default (`useIsolate: false`
/// on `createAuthRuntime`). Passing real dependencies — HTTP clients,
/// [FlutterAppAuth], a [KeyManager] — through an isolate boundary is
/// intentionally non-trivial: most are non-transferable (closures, plugin
/// channels). The v0.1 scaffolding exercises only the message plumbing
/// and lifecycle; end-to-end OAuth + refresh through the isolate is
/// validated in the F-J integration pass where a real HTTP server is
/// available.
class TokenIsolateHandle {
  TokenIsolateHandle._({
    required this.isolate,
    required this.sendPort,
    required ReceivePort responsePort,
    required ReceivePort errorPort,
    required ReceivePort exitPort,
    required Stream<WorkerEvent> eventStream,
    required StreamSubscription<dynamic> responseSubscription,
    required StreamSubscription<dynamic> errorSubscription,
    required StreamSubscription<dynamic> exitSubscription,
    required StreamController<WorkerEvent> controller,
  })  : _responsePort = responsePort,
        _errorPort = errorPort,
        _exitPort = exitPort,
        _eventStream = eventStream,
        _responseSubscription = responseSubscription,
        _errorSubscription = errorSubscription,
        _exitSubscription = exitSubscription,
        _controller = controller;

  final Isolate isolate;
  final SendPort sendPort;
  final ReceivePort _responsePort;
  final ReceivePort _errorPort;
  final ReceivePort _exitPort;
  final Stream<WorkerEvent> _eventStream;
  final StreamSubscription<dynamic> _responseSubscription;
  final StreamSubscription<dynamic> _errorSubscription;
  final StreamSubscription<dynamic> _exitSubscription;
  final StreamController<WorkerEvent> _controller;

  /// Broadcast stream of everything the isolate has sent back. Events
  /// without a [WorkerEvent.correlationId] are drop-ins for the worker's
  /// state/security channels; correlated events answer specific
  /// [WorkerRequest]s.
  Stream<WorkerEvent> get events => _eventStream;

  bool _disposed = false;

  /// Spawns a fresh token isolate and awaits its ready signal.
  ///
  /// The default [entryPoint] boots a minimal scaffolding worker that
  /// answers [InitRequest] and [DestroyRequest] only; richer entry
  /// points (integration tests, F-J production wiring) can be injected.
  static Future<TokenIsolateHandle> spawn({
    void Function(SendPort)? entryPoint,
    Duration readyTimeout = const Duration(seconds: 5),
  }) async {
    final responsePort = ReceivePort();
    final errorPort = ReceivePort();
    final exitPort = ReceivePort();
    final ready = Completer<SendPort>();
    final controller = StreamController<WorkerEvent>.broadcast();

    final responseSubscription = responsePort.listen((dynamic msg) {
      if (!ready.isCompleted) {
        if (msg is SendPort) {
          ready.complete(msg);
          return;
        }
        ready.completeError(
          StateError('first isolate message was not a SendPort: $msg'),
        );
        return;
      }
      if (msg is Map) {
        try {
          controller.add(WorkerEvent.fromMap(msg.cast<String, Object?>()));
        } catch (err, st) {
          controller.addError(err, st);
        }
      }
    });
    final errorSubscription = errorPort.listen((dynamic err) {
      controller.addError(StateError('isolate error: $err'));
    });
    final exitSubscription = exitPort.listen((_) {
      if (!controller.isClosed) controller.close();
    });

    final isolate = await Isolate.spawn<SendPort>(
      entryPoint ?? defaultTokenIsolateEntryPoint,
      responsePort.sendPort,
      onError: errorPort.sendPort,
      onExit: exitPort.sendPort,
      errorsAreFatal: false,
      debugName: 'antinvestor-auth-token-worker',
    );

    SendPort sendPort;
    try {
      sendPort = await ready.future.timeout(readyTimeout);
    } catch (err) {
      isolate.kill(priority: Isolate.immediate);
      await responseSubscription.cancel();
      await errorSubscription.cancel();
      await exitSubscription.cancel();
      responsePort.close();
      errorPort.close();
      exitPort.close();
      if (!controller.isClosed) await controller.close();
      rethrow;
    }

    return TokenIsolateHandle._(
      isolate: isolate,
      sendPort: sendPort,
      responsePort: responsePort,
      errorPort: errorPort,
      exitPort: exitPort,
      eventStream: controller.stream,
      responseSubscription: responseSubscription,
      errorSubscription: errorSubscription,
      exitSubscription: exitSubscription,
      controller: controller,
    );
  }

  /// Fire-and-forget send. Callers correlate responses on [events] by
  /// matching [WorkerRequest.correlationId] to [WorkerEvent.correlationId].
  void send(WorkerRequest request) {
    if (_disposed) {
      throw StateError('TokenIsolateHandle has been disposed');
    }
    sendPort.send(request.toMap());
  }

  /// Sends [request] and awaits the first matching event. Raises
  /// [TimeoutException] if [timeout] elapses first.
  Future<WorkerEvent> request(
    WorkerRequest request, {
    Duration timeout = const Duration(seconds: 5),
  }) {
    final completer = Completer<WorkerEvent>();
    late final StreamSubscription<WorkerEvent> sub;
    sub = events.listen(
      (ev) {
        if (ev.correlationId == request.correlationId &&
            !completer.isCompleted) {
          completer.complete(ev);
          sub.cancel();
        }
      },
      onError: (Object err, StackTrace st) {
        if (!completer.isCompleted) completer.completeError(err, st);
        sub.cancel();
      },
    );
    send(request);
    return completer.future.timeout(timeout, onTimeout: () {
      sub.cancel();
      throw TimeoutException('isolate request timed out', timeout);
    });
  }

  /// Kills the isolate, drains ports, cancels subscriptions. Idempotent.
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    isolate.kill(priority: Isolate.immediate);
    await _responseSubscription.cancel();
    await _errorSubscription.cancel();
    await _exitSubscription.cancel();
    _responsePort.close();
    _errorPort.close();
    _exitPort.close();
    if (!_controller.isClosed) await _controller.close();
  }
}

/// Main-thread proxy that forwards [TokenWorker]-shaped calls through a
/// [TokenIsolateHandle].
///
/// The v0.1 surface only wires [init] + [destroy] end-to-end — enough to
/// validate the isolate lifecycle. The remaining methods (`prepareAuth`,
/// `completeAuth`, `fetch`, `upload`, …) are declared for API parity and
/// will be completed in F-J when the integration harness supplies a
/// real HTTP surface the isolate can talk to.
class IsolatedTokenWorkerProxy {
  IsolatedTokenWorkerProxy(this.handle);

  final TokenIsolateHandle handle;

  /// Broadcasted events (state changes, security signals) from the
  /// worker. Correlated events (answers to [request]s) also flow here.
  Stream<WorkerEvent> get events => handle.events;

  /// Sends an [InitRequest] and awaits the matching [OkEvent].
  Future<void> init({
    Duration timeout = const Duration(seconds: 5),
    String correlationId = 'init',
  }) async {
    final ev = await handle.request(
      InitRequest(correlationId: correlationId),
      timeout: timeout,
    );
    if (ev is ErrorEvent) throw ev.toAuthError();
    if (ev is OkEvent) return;
    throw StateError('unexpected init response: $ev');
  }

  /// Sends a [DestroyRequest], awaits the ack, then tears down the
  /// isolate. Swallowing the timeout is intentional — we kill the
  /// isolate either way so a hung worker doesn't wedge shutdown.
  Future<void> destroy({
    Duration timeout = const Duration(seconds: 5),
    String correlationId = 'destroy',
  }) async {
    try {
      await handle.request(
        DestroyRequest(correlationId: correlationId),
        timeout: timeout,
      );
    } on TimeoutException {
      // Fall through to kill.
    } catch (_) {
      // Same: we still own the kill.
    }
    await handle.dispose();
  }
}

/// Scaffolding entry point used by [TokenIsolateHandle.spawn] when no
/// custom one is supplied. Answers [InitRequest] and [DestroyRequest];
/// every other request produces an [ErrorEvent] tagged
/// [AuthErrorCode.cryptoUnsupported] as a placeholder for "not wired".
///
/// Kept deliberately small so lifecycle tests don't drag in the full
/// [TokenWorker] stack.
void defaultTokenIsolateEntryPoint(SendPort main) {
  final receive = ReceivePort();
  main.send(receive.sendPort);
  // Broadcast a ready transition so the main isolate can observe the
  // worker settling into 'initializing'.
  main.send(const ReadyEvent().toMap());

  receive.listen((dynamic raw) {
    if (raw is! Map) return;
    final map = raw.cast<String, Object?>();
    final WorkerRequest req;
    try {
      req = WorkerRequest.fromMap(map);
    } catch (err) {
      main.send(
        ErrorEvent(
          code: AuthErrorCode.cryptoUnsupported,
          message: 'malformed request: $err',
        ).toMap(),
      );
      return;
    }
    switch (req) {
      case InitRequest():
        main.send(OkEvent(correlationId: req.correlationId).toMap());
        break;
      case DestroyRequest():
        main.send(OkEvent(correlationId: req.correlationId).toMap());
        receive.close();
        Isolate.current.kill(priority: Isolate.immediate);
        break;
      default:
        main.send(
          ErrorEvent(
            code: AuthErrorCode.cryptoUnsupported,
            message: 'scaffolding entry point does not implement '
                '${req.runtimeType}; see F-J integration pass',
            correlationId: req.correlationId,
          ).toMap(),
        );
    }
  });
}
