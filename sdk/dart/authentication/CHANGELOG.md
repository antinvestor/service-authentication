## 0.3.0

- Regenerated with protoc_plugin 25.1 / connect-dart 2.0; requires protobuf ^6.1.0, connectrpc ^2.0.0, Dart ^3.7. WKTs now come from package:protobuf.
- Depends on `antinvestor_api_common` ^2.0.0.
- Breaking: the vendored `google.protobuf` well-known types (`Any`, `Duration`, `FieldMask`, `Struct`, `Timestamp`) are gone. The barrel re-exports `Struct` and `Timestamp` from `package:protobuf/well_known_types/`, so every SDK shares one type.

## 0.2.0

- Add `AuthenticationService.IssueGenesisSessionProof`: mints a genesis
  session proof bound to the caller's live session, device and the device key
  being registered (the proof settlement's `DeployAccount` expects).
- Add `AuthenticationService.VerifyGenesisSessionProof`: verifies a proof and
  optionally spends its nonce. Requires the `auth_genesis_verify` permission
  (service consumers only).
- New messages `IssueGenesisSessionProofRequest/Response`,
  `VerifyGenesisSessionProofRequest/Response` and `GenesisSessionProofClaims`.

## 0.1.0

- Initial release
- Dart client library for Ant Investor Authentication Service with login history and session information
