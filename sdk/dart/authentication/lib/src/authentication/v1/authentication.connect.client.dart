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
}
