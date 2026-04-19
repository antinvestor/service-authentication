import 'package:antinvestor_auth_runtime/src/worker/messages.dart';
import 'package:antinvestor_auth_runtime/src/worker/token_isolate.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('TokenIsolateHandle', () {
    test('spawn + destroy round-trip completes cleanly', () async {
      final handle = await TokenIsolateHandle.spawn();
      final proxy = IsolatedTokenWorkerProxy(handle);

      // init is answered with OkEvent by the scaffolding entry point.
      await proxy.init();

      // destroy both acks and kills the isolate. It should complete
      // without throwing even though the isolate tears itself down.
      await proxy.destroy();
    });

    test('ReadyEvent is emitted on spawn', () async {
      final handle = await TokenIsolateHandle.spawn();
      try {
        final ev = await handle.events.firstWhere((e) => e is ReadyEvent);
        expect(ev, isA<ReadyEvent>());
      } finally {
        await handle.dispose();
      }
    });

    test('request/response correlation works', () async {
      final handle = await TokenIsolateHandle.spawn();
      try {
        final ev = await handle.request(
          const InitRequest(correlationId: 'corr-init-1'),
          timeout: const Duration(seconds: 3),
        );
        expect(ev, isA<OkEvent>());
        expect(ev.correlationId, 'corr-init-1');
      } finally {
        await handle.dispose();
      }
    });

    test('unimplemented request yields an ErrorEvent', () async {
      final handle = await TokenIsolateHandle.spawn();
      try {
        final ev = await handle.request(
          const PrepareAuthRequest(correlationId: 'corr-prepare-1'),
          timeout: const Duration(seconds: 3),
        );
        expect(ev, isA<ErrorEvent>());
        expect(ev.correlationId, 'corr-prepare-1');
      } finally {
        await handle.dispose();
      }
    });

    test('dispose is idempotent', () async {
      final handle = await TokenIsolateHandle.spawn();
      await handle.dispose();
      await handle.dispose();
    });

    test('send after dispose throws StateError', () async {
      final handle = await TokenIsolateHandle.spawn();
      await handle.dispose();
      expect(
        () => handle.send(const InitRequest(correlationId: 'corr')),
        throwsStateError,
      );
    });
  });
}
