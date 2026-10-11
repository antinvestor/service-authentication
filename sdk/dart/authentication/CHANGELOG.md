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
