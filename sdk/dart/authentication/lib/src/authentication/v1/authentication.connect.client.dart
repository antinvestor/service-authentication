//
//  Generated code. Do not modify.
//  source: authentication/v1/authentication.proto
//

import "package:connectrpc/connect.dart" as connect;
import "authentication.pb.dart" as authenticationv1authentication;
import "authentication.connect.spec.dart" as specs;

/// AuthenticationService provides read-only access to login history.
/// All RPCs require authentication via Bearer token.
extension type AuthenticationServiceClient (connect.Transport _transport) {
  /// GetLoginEvent retrieves a single login event by ID.
  Future<authenticationv1authentication.GetLoginEventResponse> getLoginEvent(
    authenticationv1authentication.GetLoginEventRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthenticationService.getLoginEvent,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// ListLoginEvents queries login events with filtering and pagination.
  Stream<authenticationv1authentication.ListLoginEventsResponse> listLoginEvents(
    authenticationv1authentication.ListLoginEventsRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).server(
      specs.AuthenticationService.listLoginEvents,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// IssueGenesisSessionProof mints a short-lived, single-use proof that the
  /// caller holds a live authenticated session on this device (P26). It is
  /// refused for service accounts and for sessions whose login event is not
  /// this profile on this device. The verifying keys are published at
  /// /.well-known/genesis-session-proof-keys.json.
  Future<authenticationv1authentication.IssueGenesisSessionProofResponse> issueGenesisSessionProof(
    authenticationv1authentication.IssueGenesisSessionProofRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthenticationService.issueGenesisSessionProof,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }

  /// VerifyGenesisSessionProof checks a proof and, with consume set, spends
  /// its nonce so it cannot be presented again.
  Future<authenticationv1authentication.VerifyGenesisSessionProofResponse> verifyGenesisSessionProof(
    authenticationv1authentication.VerifyGenesisSessionProofRequest input, {
    connect.Headers? headers,
    connect.AbortSignal? signal,
    Function(connect.Headers)? onHeader,
    Function(connect.Headers)? onTrailer,
  }) {
    return connect.Client(_transport).unary(
      specs.AuthenticationService.verifyGenesisSessionProof,
      input,
      signal: signal,
      headers: headers,
      onHeader: onHeader,
      onTrailer: onTrailer,
    );
  }
}
