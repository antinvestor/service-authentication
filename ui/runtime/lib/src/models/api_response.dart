import 'dart:typed_data';

/// Opaque response returned by [AuthRuntime.fetch] / [AuthRuntime.upload].
///
/// Callers never see access tokens or raw [http.Response] objects — only
/// status, headers, and bytes.
class ApiResponse {
  ApiResponse({
    required this.status,
    required Map<String, String> headers,
    required this.body,
  }) : headers = Map<String, String>.unmodifiable(headers);

  final int status;
  final Map<String, String> headers;
  final Uint8List body;
}
