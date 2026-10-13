## 0.2.0

- Regenerated with protoc_plugin 25.1 / connect-dart 2.0; requires protobuf ^6.1.0, connectrpc ^2.0.0, Dart ^3.7. WKTs now come from package:protobuf.
- Depends on `antinvestor_api_common` ^2.0.0.
- Breaking: the vendored `google.protobuf` well-known types (`Any`, `Duration`, `FieldMask`, `Struct`, `Timestamp`) are gone. The barrel re-exports `Struct` and `Timestamp` from `package:protobuf/well_known_types/`, so every SDK shares one type.

## 0.1.0

- Initial release
- Dart client library for Ant Investor Audit Service with tamper-proof audit trail, hash chaining, and digital signatures
