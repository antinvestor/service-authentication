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

  /// VerifyIntegrity verifies the hash chain integrity over a sequence range.
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

  /// ExportAuditEntries streams entries with bounding checkpoints and keys for offline verification.
  Stream<auditv1audit.ExportAuditEntriesResponse> exportAuditEntries(
    auditv1audit.ExportAuditEntriesRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).server(
      specs.AuditService.exportAuditEntries,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// ListCheckpoints lists signed checkpoints for the caller's tenant.
  Future<auditv1audit.ListCheckpointsResponse> listCheckpoints(
    auditv1audit.ListCheckpointsRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuditService.listCheckpoints,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// GetSigningKeys returns all signing public keys, including retired ones.
  Future<auditv1audit.GetSigningKeysResponse> getSigningKeys(
    auditv1audit.GetSigningKeysRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuditService.getSigningKeys,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// RegisterAuditManifest registers or updates a producing service's audit vocabulary.
  Future<auditv1audit.RegisterAuditManifestResponse> registerAuditManifest(
    auditv1audit.RegisterAuditManifestRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuditService.registerAuditManifest,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// GetAuditManifest returns the latest manifest for a service.
  Future<auditv1audit.GetAuditManifestResponse> getAuditManifest(
    auditv1audit.GetAuditManifestRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuditService.getAuditManifest,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// RequeueIntake returns FAILED intake rows to ACCEPTED after operator remediation.
  Future<auditv1audit.RequeueIntakeResponse> requeueIntake(
    auditv1audit.RequeueIntakeRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuditService.requeueIntake,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// RetireSigningKey marks a signing key retired; it keeps verifying but can no longer sign.
  Future<auditv1audit.RetireSigningKeyResponse> retireSigningKey(
    auditv1audit.RetireSigningKeyRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuditService.retireSigningKey,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }
}
