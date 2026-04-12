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
}
