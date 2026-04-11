//
//  Generated code. Do not modify.
//  source: audit/v1/audit.proto
//

import "package:connectrpc/connect.dart" as connect;
import "audit.pb.dart" as auditv1audit;
import "audit.connect.spec.dart" as specs;

/// AuditService provides a tamper-proof, append-only audit trail.
/// All RPCs require authentication via Bearer token.
extension type AuditServiceClient (connect.Transport _transport) {
  /// CreateAuditEntry appends a new entry to the audit trail.
  Future<auditv1audit.CreateAuditEntryResponse> createAuditEntry(
    auditv1audit.CreateAuditEntryRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuditService.createAuditEntry,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// BatchCreateAuditEntries appends multiple entries atomically.
  Future<auditv1audit.BatchCreateAuditEntriesResponse> batchCreateAuditEntries(
    auditv1audit.BatchCreateAuditEntriesRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuditService.batchCreateAuditEntries,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// GetAuditEntry retrieves a single audit entry by ID.
  Future<auditv1audit.GetAuditEntryResponse> getAuditEntry(
    auditv1audit.GetAuditEntryRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuditService.getAuditEntry,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// ListAuditEntries queries audit entries with filtering and pagination.
  Stream<auditv1audit.ListAuditEntriesResponse> listAuditEntries(
    auditv1audit.ListAuditEntriesRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).server(
      specs.AuditService.listAuditEntries,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// SearchAuditEntries performs free-text search across audit entries.
  Stream<auditv1audit.SearchAuditEntriesResponse> searchAuditEntries(
    auditv1audit.SearchAuditEntriesRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).server(
      specs.AuditService.searchAuditEntries,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// VerifyIntegrity verifies the hash chain integrity over a time range.
  Future<auditv1audit.VerifyIntegrityResponse> verifyIntegrity(
    auditv1audit.VerifyIntegrityRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuditService.verifyIntegrity,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }
}
