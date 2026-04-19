import 'package:antinvestor_auth_runtime/src/providers/auth_providers.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Renders the signed-in user's avatar:
///
/// - If claims contain a non-empty `picture` URL, uses it.
/// - Otherwise falls back to initials derived from `name` (first letter
///   of each whitespace-separated word, up to two) or `email` (first
///   letter of the local part).
/// - While claims are still resolving renders a neutral circle.
class ProfileAvatar extends ConsumerWidget {
  const ProfileAvatar({
    this.radius = 20,
    this.backgroundColor,
    this.foregroundColor,
    super.key,
  });

  final double radius;
  final Color? backgroundColor;
  final Color? foregroundColor;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final bg = backgroundColor ?? theme.colorScheme.primaryContainer;
    final fg = foregroundColor ?? theme.colorScheme.onPrimaryContainer;
    final async = ref.watch(userClaimsProvider);
    return async.when(
      loading: () => CircleAvatar(
        radius: radius,
        backgroundColor: bg,
      ),
      error: (_, _) => CircleAvatar(
        radius: radius,
        backgroundColor: bg,
        foregroundColor: fg,
        child: const Icon(Icons.person_outline),
      ),
      data: (claims) {
        final picture = claims['picture'];
        if (picture is String && picture.isNotEmpty) {
          return CircleAvatar(
            radius: radius,
            backgroundImage: NetworkImage(picture),
            backgroundColor: bg,
          );
        }
        final initials = _initialsFrom(claims);
        return CircleAvatar(
          radius: radius,
          backgroundColor: bg,
          foregroundColor: fg,
          child: initials.isEmpty
              ? const Icon(Icons.person_outline)
              : Text(initials),
        );
      },
    );
  }
}

/// Visible for testing — derives initials using the same priority chain
/// as [ProfileAvatar].
String initialsFromClaims(Map<String, dynamic> claims) =>
    _initialsFrom(claims);

String _initialsFrom(Map<String, dynamic> claims) {
  final name = claims['name'];
  if (name is String && name.trim().isNotEmpty) {
    final parts = name
        .trim()
        .split(RegExp(r'\s+'))
        .where((p) => p.isNotEmpty)
        .toList();
    final first = parts.isNotEmpty ? parts.first[0] : '';
    final second = parts.length > 1 ? parts[1][0] : '';
    return (first + second).toUpperCase();
  }
  final email = claims['email'];
  if (email is String && email.isNotEmpty) {
    final local = email.split('@').first;
    if (local.isNotEmpty) return local[0].toUpperCase();
  }
  return '';
}
