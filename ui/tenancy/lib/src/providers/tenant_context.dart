import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Represents the active tenant/partition context for tenancy management.
///
/// Host applications must override [jwtTenantContextProvider] with their own
/// implementation that extracts context from the JWT access token.
class TenantContext {
  const TenantContext({
    required this.tenantId,
    required this.partitionId,
    this.accessId = '',
    this.roles = const [],
    this.profileId = '',
  });

  final String tenantId;
  final String partitionId;
  final String accessId;
  final List<String> roles;
  final String profileId;

  /// Whether this is the root context (no specific tenant selected).
  bool get isRoot => tenantId.isEmpty;

  /// Whether the user has the owner role.
  bool get isOwner => roles.contains('owner');

  /// Whether the user has admin or owner role.
  bool get isAdmin => roles.contains('admin') || isOwner;

  /// Whether the user has the "internal" role (root-tenant owner/admin).
  /// Internal users can switch tenant context for cross-tenant administration.
  bool get isInternal => roles.contains('internal');

  /// Whether the user can switch partition context.
  /// Internal users can switch across tenants; owners can switch across
  /// partitions within their tenant.
  bool get canSwitchContext => isInternal || isOwner;

  TenantContext copyWith({
    String? tenantId,
    String? partitionId,
  }) =>
      TenantContext(
        tenantId: tenantId ?? this.tenantId,
        partitionId: partitionId ?? this.partitionId,
        accessId: accessId,
        roles: roles,
        profileId: profileId,
      );
}

/// JWT-based tenant context provider.
///
/// **Host apps must override this** in their ProviderScope with their own
/// implementation that extracts tenant context from the JWT:
/// ```dart
/// ProviderScope(
///   overrides: [
///     jwtTenantContextProvider.overrideWith((ref) async {
///       // Parse JWT and return TenantContext
///     }),
///   ],
///   child: MyApp(),
/// )
/// ```
final jwtTenantContextProvider =
    FutureProvider<TenantContext>((ref) async {
  // Default implementation returns empty context.
  // Host app must override this provider.
  return const TenantContext(tenantId: '', partitionId: '');
});

/// Notifier for the active working tenant/partition context.
///
/// Defaults to the JWT context but can be overridden by the user
/// to work within a different tenant/partition scope.
class ActiveTenantNotifier extends Notifier<TenantContext?> {
  @override
  TenantContext? build() => null;

  void set(TenantContext? context) => state = context;

  void clear() => state = null;
}

final activeTenantProvider =
    NotifierProvider<ActiveTenantNotifier, TenantContext?>(
  ActiveTenantNotifier.new,
);

/// The effective tenant context - either the user's override or the JWT default.
final effectiveTenantProvider = Provider<TenantContext>((ref) {
  final override = ref.watch(activeTenantProvider);
  if (override != null) return override;

  final jwt = ref.watch(jwtTenantContextProvider);
  return jwt.whenOrNull(data: (ctx) => ctx) ??
      const TenantContext(tenantId: '', partitionId: '');
});
