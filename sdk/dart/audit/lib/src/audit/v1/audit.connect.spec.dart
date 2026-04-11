//
//  Generated code. Do not modify.
//  source: audit/v1/audit.proto
//

import "package:connectrpc/connect.dart" as connect;
import "audit.pb.dart" as auditv1audit;

/// AuditService provides a tamper-proof, append-only audit trail.
/// All RPCs require authentication via Bearer token.
abstract final class AuditService {
  /// Fully-qualified name of the AuditService service.
  static const name = 'audit.v1.AuditService';

  /// CreateAuditEntry appends a new entry to the audit trail.
  static const createAuditEntry = connect.Spec(
    '/$name/CreateAuditEntry',
    connect.StreamType.unary,
    auditv1audit.CreateAuditEntryRequest.new,
    auditv1audit.CreateAuditEntryResponse.new,
  );

  /// BatchCreateAuditEntries appends multiple entries atomically.
  static const batchCreateAuditEntries = connect.Spec(
    '/$name/BatchCreateAuditEntries',
    connect.StreamType.unary,
    auditv1audit.BatchCreateAuditEntriesRequest.new,
    auditv1audit.BatchCreateAuditEntriesResponse.new,
  );

  /// GetAuditEntry retrieves a single audit entry by ID.
  static const getAuditEntry = connect.Spec(
    '/$name/GetAuditEntry',
    connect.StreamType.unary,
    auditv1audit.GetAuditEntryRequest.new,
    auditv1audit.GetAuditEntryResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// ListAuditEntries queries audit entries with filtering and pagination.
  static const listAuditEntries = connect.Spec(
    '/$name/ListAuditEntries',
    connect.StreamType.server,
    auditv1audit.ListAuditEntriesRequest.new,
    auditv1audit.ListAuditEntriesResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// SearchAuditEntries performs free-text search across audit entries.
  static const searchAuditEntries = connect.Spec(
    '/$name/SearchAuditEntries',
    connect.StreamType.server,
    auditv1audit.SearchAuditEntriesRequest.new,
    auditv1audit.SearchAuditEntriesResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// VerifyIntegrity verifies the hash chain integrity over a time range.
  static const verifyIntegrity = connect.Spec(
    '/$name/VerifyIntegrity',
    connect.StreamType.unary,
    auditv1audit.VerifyIntegrityRequest.new,
    auditv1audit.VerifyIntegrityResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );
}
