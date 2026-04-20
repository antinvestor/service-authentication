import 'package:antinvestor_auth_runtime/src/models/security_event.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final at = DateTime.utc(2026, 1, 1);

  test('SecurityEvent has four variants with the at timestamp', () {
    final events = <SecurityEvent>[
      SecurityEvent.refreshReuseDetected(at),
      SecurityEvent.storageCorruption(at),
      SecurityEvent.bindingInvalidated(at),
      SecurityEvent.loggedOutElsewhere(at),
    ];
    for (final e in events) {
      expect(e.at, at);
    }
    expect(events[0], isA<RefreshReuseDetected>());
    expect(events[1], isA<StorageCorruption>());
    expect(events[2], isA<BindingInvalidated>());
    expect(events[3], isA<LoggedOutElsewhere>());
  });

  test('SecurityEvent pattern-matches exhaustively', () {
    String label(SecurityEvent e) => switch (e) {
          RefreshReuseDetected() => 'reuse',
          StorageCorruption() => 'storage',
          BindingInvalidated() => 'binding',
          LoggedOutElsewhere() => 'logout-elsewhere',
        };
    expect(label(SecurityEvent.refreshReuseDetected(at)), 'reuse');
    expect(label(SecurityEvent.storageCorruption(at)), 'storage');
    expect(label(SecurityEvent.bindingInvalidated(at)), 'binding');
    expect(label(SecurityEvent.loggedOutElsewhere(at)), 'logout-elsewhere');
  });

  test('SecurityEvent equality compares variant and timestamp', () {
    expect(
      SecurityEvent.refreshReuseDetected(at),
      equals(SecurityEvent.refreshReuseDetected(at)),
    );
    expect(
      SecurityEvent.refreshReuseDetected(at),
      isNot(equals(SecurityEvent.storageCorruption(at))),
    );
  });
}
