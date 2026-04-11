import 'package:antinvestor_api_audit/antinvestor_api_audit.dart';
import 'package:antinvestor_ui_core/api/stream_helpers.dart';
import 'package:fixnum/fixnum.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'audit_transport_provider.dart';

// ---------------------------------------------------------------------------
// Parameter classes
// ---------------------------------------------------------------------------

/// Parameters for listing audit entries with filters.
class AuditListParams {
  const AuditListParams({
    this.profileId = '',
    this.action = '',
    this.resourceType = '',
    this.resourceId = '',
    this.service = '',
    this.targetProfileId = '',
    this.deviceId = '',
    this.startDate,
    this.endDate,
    this.count = 50,
    this.page = '',
  });

  final String profileId;
  final String action;
  final String resourceType;
  final String resourceId;
  final String service;
  final String targetProfileId;
  final String deviceId;
  final DateTime? startDate;
  final DateTime? endDate;
  final int count;
  final String page;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is AuditListParams &&
          runtimeType == other.runtimeType &&
          profileId == other.profileId &&
          action == other.action &&
          resourceType == other.resourceType &&
          resourceId == other.resourceId &&
          service == other.service &&
          targetProfileId == other.targetProfileId &&
          deviceId == other.deviceId &&
          startDate == other.startDate &&
          endDate == other.endDate &&
          count == other.count &&
          page == other.page;

  @override
  int get hashCode => Object.hash(
        profileId,
        action,
        resourceType,
        resourceId,
        service,
        targetProfileId,
        deviceId,
        startDate,
        endDate,
        count,
        page,
      );
}

/// Parameters for free-text search across audit entries.
class AuditSearchParams {
  const AuditSearchParams({
    required this.query,
    this.startDate,
    this.endDate,
    this.count = 50,
    this.page = '',
  });

  final String query;
  final DateTime? startDate;
  final DateTime? endDate;
  final int count;
  final String page;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is AuditSearchParams &&
          runtimeType == other.runtimeType &&
          query == other.query &&
          startDate == other.startDate &&
          endDate == other.endDate &&
          count == other.count &&
          page == other.page;

  @override
  int get hashCode => Object.hash(query, startDate, endDate, count, page);
}

/// Date range for integrity verification.
class DateRange {
  const DateRange({required this.start, required this.end});
  final DateTime start;
  final DateTime end;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is DateRange &&
          runtimeType == other.runtimeType &&
          start == other.start &&
          end == other.end;

  @override
  int get hashCode => Object.hash(start, end);
}

// ---------------------------------------------------------------------------
// Helper: DateTime -> Timestamp
// ---------------------------------------------------------------------------

Timestamp _toTimestamp(DateTime dt) {
  final seconds = dt.millisecondsSinceEpoch ~/ 1000;
  final nanos = (dt.millisecondsSinceEpoch % 1000) * 1000000;
  return Timestamp(seconds: Int64(seconds), nanos: nanos);
}

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

/// Fetch a single audit entry by ID.
final auditEntryByIdProvider =
    FutureProvider.family<AuditEntryObject, String>((ref, id) async {
  final client = ref.watch(auditServiceClientProvider);
  final response = await client.getAuditEntry(GetAuditEntryRequest(id: id));
  return response.data;
});

/// List audit entries with filters. Collects the server stream into a list.
final auditEntriesProvider =
    FutureProvider.family<List<AuditEntryObject>, AuditListParams>(
        (ref, params) async {
  final client = ref.watch(auditServiceClientProvider);

  final request = ListAuditEntriesRequest(count: params.count);
  if (params.profileId.isNotEmpty) request.profileId = params.profileId;
  if (params.action.isNotEmpty) request.action = params.action;
  if (params.resourceType.isNotEmpty) {
    request.resourceType = params.resourceType;
  }
  if (params.resourceId.isNotEmpty) request.resourceId = params.resourceId;
  if (params.service.isNotEmpty) request.service = params.service;
  if (params.targetProfileId.isNotEmpty) {
    request.targetProfileId = params.targetProfileId;
  }
  if (params.deviceId.isNotEmpty) request.deviceId = params.deviceId;
  if (params.startDate != null) {
    request.startDate = _toTimestamp(params.startDate!);
  }
  if (params.endDate != null) {
    request.endDate = _toTimestamp(params.endDate!);
  }
  if (params.page.isNotEmpty) request.page = params.page;

  final stream = client.listAuditEntries(request);
  return collectStream<ListAuditEntriesResponse, AuditEntryObject>(
    stream,
    extract: (r) => r.data,
  );
});

/// Search audit entries with free-text query. Collects server stream.
final auditSearchProvider =
    FutureProvider.family<List<AuditEntryObject>, AuditSearchParams>(
        (ref, params) async {
  final client = ref.watch(auditServiceClientProvider);

  final request = SearchAuditEntriesRequest(
    query: params.query,
    count: params.count,
  );
  if (params.startDate != null) {
    request.startDate = _toTimestamp(params.startDate!);
  }
  if (params.endDate != null) {
    request.endDate = _toTimestamp(params.endDate!);
  }
  if (params.page.isNotEmpty) request.page = params.page;

  final stream = client.searchAuditEntries(request);
  return collectStream<SearchAuditEntriesResponse, AuditEntryObject>(
    stream,
    extract: (r) => r.data,
  );
});

/// Verify hash chain integrity over a date range.
final verifyIntegrityProvider =
    FutureProvider.family<VerifyIntegrityResponse, DateRange>(
        (ref, range) async {
  final client = ref.watch(auditServiceClientProvider);
  final request = VerifyIntegrityRequest(
    startDate: _toTimestamp(range.start),
    endDate: _toTimestamp(range.end),
  );
  return client.verifyIntegrity(request);
});

// ---------------------------------------------------------------------------
// AuditNotifier — create / batch-create mutations
// ---------------------------------------------------------------------------

/// Notifier for creating audit entries (mutations).
class AuditNotifier extends Notifier<void> {
  @override
  void build() {}

  /// Create a single audit entry.
  Future<AuditEntryObject> createEntry({
    required String action,
    required String resourceType,
    String resourceId = '',
    String service = '',
    Struct? details,
    String targetProfileId = '',
  }) async {
    final client = ref.read(auditServiceClientProvider);
    final request = CreateAuditEntryRequest(
      action: action,
      resourceType: resourceType,
    );
    if (resourceId.isNotEmpty) request.resourceId = resourceId;
    if (service.isNotEmpty) request.service = service;
    if (details != null) request.details = details;
    if (targetProfileId.isNotEmpty) {
      request.targetProfileId = targetProfileId;
    }
    final response = await client.createAuditEntry(request);
    return response.data;
  }

  /// Create multiple audit entries atomically.
  Future<List<AuditEntryObject>> batchCreate(
    List<CreateAuditEntryRequest> entries,
  ) async {
    final client = ref.read(auditServiceClientProvider);
    final request = BatchCreateAuditEntriesRequest(entries: entries);
    final response = await client.batchCreateAuditEntries(request);
    return response.data;
  }
}

final auditNotifierProvider =
    NotifierProvider<AuditNotifier, void>(AuditNotifier.new);
