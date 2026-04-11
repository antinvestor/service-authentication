import 'package:antinvestor_api_audit/antinvestor_api_audit.dart';
import 'package:antinvestor_ui_core/api/api_base.dart';
import 'package:connectrpc/connect.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

const _auditUrl = String.fromEnvironment(
  'AUDIT_URL',
  defaultValue: 'https://api.antinvestor.com/audit',
);

final auditTransportProvider = Provider<Transport>((ref) {
  final tokenProvider = ref.watch(authTokenProviderProvider);
  return createTransport(tokenProvider, baseUrl: _auditUrl);
});

final auditServiceClientProvider = Provider<AuditServiceClient>((ref) {
  final transport = ref.watch(auditTransportProvider);
  return AuditServiceClient(transport);
});
