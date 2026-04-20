import 'dart:async';

import 'package:antinvestor_auth_runtime/src/runtime/refresh_lock.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('two concurrent calls on the same key serialize', () async {
    final lock = RefreshLock();
    final order = <String>[];
    final c1 = Completer<void>();
    final c2 = Completer<void>();

    final f1 = lock.withLock<int>('ns', () async {
      order.add('start-1');
      await c1.future;
      order.add('end-1');
      return 1;
    });
    final f2 = lock.withLock<int>('ns', () async {
      order.add('start-2');
      await c2.future;
      order.add('end-2');
      return 2;
    });

    // Give the scheduler a chance to run task 1.
    await Future<void>.delayed(Duration.zero);
    expect(order, ['start-1']);

    c1.complete();
    await Future<void>.delayed(Duration.zero);
    // Only after task 1 completes may task 2 enter.
    expect(order.contains('start-2'), isTrue);

    c2.complete();
    expect(await f1, 1);
    expect(await f2, 2);
    expect(order, ['start-1', 'end-1', 'start-2', 'end-2']);
  });

  test('different keys proceed in parallel', () async {
    final lock = RefreshLock();
    final started = <String>[];

    final barrier = Completer<void>();
    final a = lock.withLock<void>('a', () async {
      started.add('a');
      await barrier.future;
    });
    final b = lock.withLock<void>('b', () async {
      started.add('b');
    });

    // Task b must be able to finish even though task a is blocked.
    await b;
    expect(started, containsAll(<String>['a', 'b']));

    barrier.complete();
    await a;
  });

  test('a thrown error releases the lock for the next caller', () async {
    final lock = RefreshLock();

    await expectLater(
      lock.withLock<void>('ns', () async {
        throw StateError('boom');
      }),
      throwsA(isA<StateError>()),
    );

    // Second caller must still be able to acquire.
    final result = await lock.withLock<int>('ns', () async => 42);
    expect(result, 42);
  });

  test('sequential calls on the same key execute one at a time', () async {
    final lock = RefreshLock();
    var active = 0;
    var peakActive = 0;

    Future<void> run() async {
      await lock.withLock<void>('ns', () async {
        active++;
        peakActive = active > peakActive ? active : peakActive;
        await Future<void>.delayed(const Duration(milliseconds: 5));
        active--;
      });
    }

    await Future.wait(<Future<void>>[run(), run(), run(), run()]);
    expect(peakActive, 1);
  });
}
