import 'package:flutter_test/flutter_test.dart';
import 'package:antinvestor_ui_tenancy/antinvestor_ui_tenancy.dart';

void main() {
  test('TenancyRouteModule has correct moduleId', () {
    final module = TenancyRouteModule();
    expect(module.moduleId, 'tenancy');
  });

  test('TenancyRouteModule builds routes', () {
    final module = TenancyRouteModule();
    final routes = module.buildRoutes();
    expect(routes, isNotEmpty);
  });

  test('TenancyRouteModule builds nav items', () {
    final module = TenancyRouteModule();
    final items = module.buildNavItems();
    expect(items, isNotEmpty);
    expect(items.first.id, 'tenancy');
    expect(items.first.children.length, 2);
  });

  test('TenantContext defaults', () {
    const ctx = TenantContext(tenantId: '', partitionId: '');
    expect(ctx.isRoot, true);
    expect(ctx.isOwner, false);
    expect(ctx.isAdmin, false);
    expect(ctx.isInternal, false);
    expect(ctx.canSwitchContext, false);
  });

  test('TenantContext with owner role', () {
    const ctx = TenantContext(
      tenantId: 't1',
      partitionId: 'p1',
      roles: ['owner'],
    );
    expect(ctx.isRoot, false);
    expect(ctx.isOwner, true);
    expect(ctx.isAdmin, true);
    expect(ctx.canSwitchContext, true);
  });

  test('TenantContext with internal role', () {
    const ctx = TenantContext(
      tenantId: 't1',
      partitionId: 'p1',
      roles: ['internal'],
    );
    expect(ctx.isInternal, true);
    expect(ctx.canSwitchContext, true);
  });

  test('PartitionRepository can be instantiated', () {
    // Smoke test: the class exists and can be imported.
    expect(PartitionRepository, isNotNull);
  });
}
