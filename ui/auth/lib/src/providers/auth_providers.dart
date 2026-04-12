import 'package:antinvestor_api_authentication/antinvestor_api_authentication.dart';
import 'package:antinvestor_ui_core/api/stream_helpers.dart';
import 'package:fixnum/fixnum.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'auth_transport_provider.dart';

// ---------------------------------------------------------------------------
// Parameter classes
// ---------------------------------------------------------------------------

/// Parameters for listing login events with filters.
class LoginEventListParams {
  const LoginEventListParams({
    this.profileId = '',
    this.clientId = '',
    this.source = '',
    this.deviceId = '',
    this.startDate,
    this.endDate,
    this.count = 50,
    this.page = '',
  });

  final String profileId;
  final String clientId;
  final String source;
  final String deviceId;
  final DateTime? startDate;
  final DateTime? endDate;
  final int count;
  final String page;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is LoginEventListParams &&
          runtimeType == other.runtimeType &&
          profileId == other.profileId &&
          clientId == other.clientId &&
          source == other.source &&
          deviceId == other.deviceId &&
          startDate == other.startDate &&
          endDate == other.endDate &&
          count == other.count &&
          page == other.page;

  @override
  int get hashCode => Object.hash(
        profileId,
        clientId,
        source,
        deviceId,
        startDate,
        endDate,
        count,
        page,
      );
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

/// Fetch a single login event by ID.
final loginEventByIdProvider =
    FutureProvider.family<LoginEventObject, String>((ref, id) async {
  final client = ref.watch(authServiceClientProvider);
  final response = await client.getLoginEvent(GetLoginEventRequest(id: id));
  return response.data;
});

/// List login events with filters. Collects the server stream into a list.
final loginEventsProvider =
    FutureProvider.family<List<LoginEventObject>, LoginEventListParams>(
        (ref, params) async {
  final client = ref.watch(authServiceClientProvider);

  final request = ListLoginEventsRequest(count: params.count);
  if (params.profileId.isNotEmpty) request.profileId = params.profileId;
  if (params.clientId.isNotEmpty) request.clientId = params.clientId;
  if (params.source.isNotEmpty) request.source = params.source;
  if (params.deviceId.isNotEmpty) request.deviceId = params.deviceId;
  if (params.startDate != null) {
    request.startDate = _toTimestamp(params.startDate!);
  }
  if (params.endDate != null) {
    request.endDate = _toTimestamp(params.endDate!);
  }
  if (params.page.isNotEmpty) request.page = params.page;

  final stream = client.listLoginEvents(request);
  return collectStream<ListLoginEventsResponse, LoginEventObject>(
    stream,
    extract: (r) => r.data,
  );
});
