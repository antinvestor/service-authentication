import 'dart:typed_data';

import 'package:antinvestor_auth_runtime/src/models/api_response.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('ApiResponse exposes status, headers, body', () {
    final body = Uint8List.fromList(const [1, 2, 3]);
    final r = ApiResponse(
      status: 200,
      headers: const {'content-type': 'application/json'},
      body: body,
    );
    expect(r.status, 200);
    expect(r.headers['content-type'], 'application/json');
    expect(r.body, body);
  });

  test('ApiResponse headers are unmodifiable', () {
    final r = ApiResponse(
      status: 200,
      headers: const {'x-trace-id': 't'},
      body: Uint8List(0),
    );
    expect(() => r.headers['x'] = 'y', throwsUnsupportedError);
  });
}
