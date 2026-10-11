//
//  Generated code. Do not modify.
//  source: authentication/v1/authentication.proto
//

import "package:connectrpc/connect.dart" as connect;
import "authentication.pb.dart" as authenticationv1authentication;

/// AuthenticationService provides read-only access to login history.
/// All RPCs require authentication via Bearer token.
abstract final class AuthenticationService {
  /// Fully-qualified name of the AuthenticationService service.
  static const name = 'authentication.v1.AuthenticationService';

  /// GetLoginEvent retrieves a single login event by ID.
  static const getLoginEvent = connect.Spec(
    '/$name/GetLoginEvent',
    connect.StreamType.unary,
    authenticationv1authentication.GetLoginEventRequest.new,
    authenticationv1authentication.GetLoginEventResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// ListLoginEvents queries login events with filtering and pagination.
  static const listLoginEvents = connect.Spec(
    '/$name/ListLoginEvents',
    connect.StreamType.server,
    authenticationv1authentication.ListLoginEventsRequest.new,
    authenticationv1authentication.ListLoginEventsResponse.new,
    idempotency: connect.Idempotency.noSideEffects,
  );

  /// IssueGenesisSessionProof mints a short-lived, single-use proof that the
  /// caller holds a live authenticated session on this device (P26). It is
  /// refused for service accounts and for sessions whose login event is not
  /// this profile on this device. The verifying keys are published at
  /// /.well-known/genesis-session-proof-keys.json.
  static const issueGenesisSessionProof = connect.Spec(
    '/$name/IssueGenesisSessionProof',
    connect.StreamType.unary,
    authenticationv1authentication.IssueGenesisSessionProofRequest.new,
    authenticationv1authentication.IssueGenesisSessionProofResponse.new,
  );

  /// VerifyGenesisSessionProof checks a proof and, with consume set, spends
  /// its nonce so it cannot be presented again.
  static const verifyGenesisSessionProof = connect.Spec(
    '/$name/VerifyGenesisSessionProof',
    connect.StreamType.unary,
    authenticationv1authentication.VerifyGenesisSessionProofRequest.new,
    authenticationv1authentication.VerifyGenesisSessionProofResponse.new,
  );
}
