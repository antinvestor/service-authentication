import 'package:flutter_test/flutter_test.dart';
import 'package:antinvestor_ui_audit/antinvestor_ui_audit.dart';

void main() {
  test('AuditRouteModule has correct moduleId', () {
    final module = AuditRouteModule();
    expect(module.moduleId, 'audit');
  });

  test('AuditRouteModule builds routes', () {
    final module = AuditRouteModule();
    final routes = module.buildRoutes();
    expect(routes, isNotEmpty);
  });

  test('AuditRouteModule builds nav items', () {
    final module = AuditRouteModule();
    final items = module.buildNavItems();
    expect(items, isNotEmpty);
    expect(items.first.id, 'audit');
    expect(items.first.children.length, 2);
  });

  test('AuditRouteModule has route permissions', () {
    final module = AuditRouteModule();
    expect(module.routePermissions, isNotEmpty);
    expect(
      module.routePermissions['/services/audit'],
      contains('audit_view'),
    );
    expect(
      module.routePermissions['/services/audit/integrity'],
      contains('audit_verify'),
    );
  });

  test('AuditListParams equality', () {
    const p1 = AuditListParams(action: 'create', count: 50);
    const p2 = AuditListParams(action: 'create', count: 50);
    const p3 = AuditListParams(action: 'delete', count: 50);
    expect(p1, equals(p2));
    expect(p1.hashCode, equals(p2.hashCode));
    expect(p1, isNot(equals(p3)));
  });

  test('AuditSearchParams equality', () {
    const s1 = AuditSearchParams(query: 'test', count: 25);
    const s2 = AuditSearchParams(query: 'test', count: 25);
    const s3 = AuditSearchParams(query: 'other', count: 25);
    expect(s1, equals(s2));
    expect(s1.hashCode, equals(s2.hashCode));
    expect(s1, isNot(equals(s3)));
  });

  test('DateRange equality', () {
    final now = DateTime(2026, 4, 9);
    final later = DateTime(2026, 4, 10);
    final r1 = DateRange(start: now, end: later);
    final r2 = DateRange(start: now, end: later);
    expect(r1, equals(r2));
    expect(r1.hashCode, equals(r2.hashCode));
  });

  test('AuditEntryTile icon helpers return expected values', () {
    expect(AuditEntryTile.iconForAction('create'), isNotNull);
    expect(AuditEntryTile.iconForAction('delete'), isNotNull);
    expect(AuditEntryTile.iconForAction('unknown'), isNotNull);
  });
}
