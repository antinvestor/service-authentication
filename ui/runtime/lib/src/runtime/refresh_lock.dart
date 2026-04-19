import 'package:synchronized/synchronized.dart';

/// Keyed async mutex used to serialize refresh-token calls per session.
///
/// A refresh-token grant must never race against itself for the same
/// session: two concurrent rotations would cause the IdP to return
/// `invalid_grant` on the loser (RT reuse). All operations keyed the same
/// are serialised; different keys proceed in parallel so unrelated
/// runtime instances don't block each other.
///
/// The lock is released even if [fn] throws so a failed refresh doesn't
/// wedge subsequent attempts.
class RefreshLock {
  final Map<String, Lock> _locks = {};

  Future<T> withLock<T>(String key, Future<T> Function() fn) {
    final lock = _locks.putIfAbsent(key, Lock.new);
    return lock.synchronized<T>(fn);
  }
}
