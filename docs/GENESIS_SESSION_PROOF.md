# Genesis session proof (K9)

**Status:** implemented in `apps/default` (`service/sessionproof`, `service/handlers/genesis_session_proof.go`).
**Serves:** Stawi Group Financial OS §8.2 / P26 and §21 row K9 — "short-lived token signed by the
authentication service binding `profile_id ‖ device_id ‖ pubkey_hash ‖ nonce ‖ issued_at`, issued only
inside a live session on that device".

A device row in the devices service says a key exists. It never says a person was present when the key
was registered. The genesis session proof is the statement that they were: this service mints it only
from inside a live authenticated session, on the device that session runs on, and signs it with a key
whose public half is published. The GFOS finance service verifies it before deploying an account, and
the on-chain attestation carries its digest as `AccountFactory.GenesisRequest.sessionProofHash`, so a
proof that was swapped, expired or minted for another device cannot be made to fit.

## Wire format

```
token = "GSP1" "." base64url(payload_json) "." base64url(signature)
```

`base64url` is RFC 4648 §5 without padding. `signature` is Ed25519 over the **binding pre-image**
below — never over the JSON — so a verifier rebuilds the bytes it checks from the parsed fields and
cannot be steered by JSON formatting, key order or whitespace.

`payload_json` (every field is present unless marked optional):

| Key | Meaning |
|-----|---------|
| `v` | `"GSP1"` |
| `kid` | signing key id, resolvable in the published key set |
| `alg` | `"ed25519"` |
| `sub` | `profile_id` of the person (the platform invariant is JWT `sub === profile_id`) |
| `did` | `device_id` the live session runs on |
| `pkh` | `pubkey_hash`: 32-byte lowercase hex digest of the device public key being registered. On EVM that is `keccak256(device address)`; this service binds the value, it does not interpret it |
| `dkid` | optional devices-service key id for `pkh` |
| `nonce` | 16 random bytes, lowercase hex; makes the proof single-use |
| `iat`, `exp` | issued-at and expiry, RFC 3339 UTC with microseconds (`2006-01-02T15:04:05.000000Z`) |
| `sid` | login event id the proof was issued inside |
| `tid`, `pid` | tenant and partition |
| `aud` | audience, `stawi-genesis` by default |

## Binding pre-image (what is signed)

```
LP(s)   = uvarint(len(s)) ‖ UTF-8 bytes of s        // the audit chain's length-prefix rule

Binding = "stawi.genesis-session-proof.v1"
          ‖ LP(profile_id) ‖ LP(device_id) ‖ LP(pubkey_hash) ‖ LP(nonce) ‖ LP(issued_at)
          ‖ LP(expires_at) ‖ LP(session_id) ‖ LP(device_key_id)
          ‖ LP(tenant_id) ‖ LP(partition_id) ‖ LP(audience) ‖ LP(key_id)

signature   = Ed25519(private_key_of(kid), Binding)
BindingHash = SHA-256(Binding)
```

The five fields §8.2 names come first and in its order; the rest bind the lifetime, session, tenant,
audience and signing key so none of them can be swapped without breaking the signature. Timestamps in
the pre-image are byte-identical to the strings in the JSON, so the two can never disagree.

`BindingHash` is the 32 bytes a consumer records and the attestation signer carries on-chain as
`sessionProofHash`. Its hex form is returned by both endpoints as `binding_hash`.

Golden vector (pinned by `TestBinding_GoldenVector`): for
`sub=profile-1, did=device-1, pkh=ab×32, dkid=devkey-1, nonce=0123456789abcdef0123456789abcdef,
iat=2026-09-16T10:30:00.000000Z, exp=2026-09-16T10:35:00.000000Z, sid=login-event-1, tid=tenant-1,
pid=partition-1, aud=stawi-genesis, kid=gsp-k1`:

```
BindingHash = f842718e6dbe316a9ada27602589845de9c2a287dec14f399b7875671ec562bd
```

## Endpoints

| Method and path | Auth | Purpose |
|-----------------|------|---------|
| `POST /s/genesis/session-proof` | Bearer JWT of the person's own session | Mint a proof. Body `{"pubkey_hash": "<64 hex>", "device_key_id": "…", "device_id": "…"}` — `device_key_id` and `device_id` are optional and `device_id`, when sent, must equal the session's device. Returns `{token, key_id, algorithm, nonce, issued_at, expires_at, binding_hash, audience}` |
| `POST /s/genesis/session-proof/verify` | Bearer JWT | Convenience for a consumer that would rather not carry a verifier. Body `{"token", "profile_id", "device_id", "pubkey_hash", "device_key_id", "consume"}`; empty expectations are not checked. Returns `{valid, reason?, claims?, binding_hash?}`. `consume: true` spends the nonce, so the second call reports `valid: false` with the replay reason |
| `GET /.well-known/genesis-session-proof-keys.json` | public | `{"keys":[{key_id, algorithm, public_key_hex, valid_from, retired_at?}]}`, `Cache-Control: max-age=300` — the same shape the audit service publishes, so a consumer reuses its key-set loader |

Issuance refuses, with no proof minted, when: the caller is a service account (a machine holds no
session on a device); the token carries no profile, device or session; the named login event is
missing, belongs to another profile or to another device; `pubkey_hash` is not a 32-byte lowercase hex
digest; or no signing key is configured.

## Verifying a proof (consumer side)

1. Fetch and cache the key set; resolve `kid`. Retired keys keep verifying — proofs live minutes.
2. Rebuild `Binding` from the parsed claims and check the Ed25519 signature.
3. Check `exp` (and `iat`) against your clock with a small leeway, and the audience.
4. Check the claims against what you know: `sub` is the acting profile, `did` the device, `pkh` the key
   being registered.
5. Enforce single use in your own domain (GFOS: a genesis happens once per account) or call the verify
   endpoint with `consume: true`.

The GFOS-side seam is `identity.SessionProofVerifier.Verify(ctx, profileID, deviceKeyID, proof)`, which
replaces `PresenceOnlyVerifier`: `proof` is the token bytes, `profileID` must equal `sub`, and
`deviceKeyID` is matched against `dkid` (and, where the devices service resolves the key, `pkh`).

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `GENESIS_PROOF_SIGNING_KEY_REF` | *(empty: feature off)* | `file:///path` or `vault://<path>#<prop>`, the latter read from `GENESIS_PROOF_SIGNING_KEY_MOUNT_DIR/<key id>` |
| `GENESIS_PROOF_SIGNING_KEY_ID` | *(empty)* | Active key id, published with the key |
| `GENESIS_PROOF_SIGNING_KEY_MOUNT_DIR` | `/var/run/secrets/genesis-proof` | Where the projected secret is mounted |
| `GENESIS_PROOF_RETIRED_KEYS` | *(empty)* | `kid:hex,kid2:hex` — published and verifying, never signing |
| `GENESIS_PROOF_TTL` | `5m` | Lifetime; it asserts presence, which stops being true quickly |
| `GENESIS_PROOF_AUDIENCE` | `stawi-genesis` | Bound into the proof and checked on verify |

There is no generate-a-key-on-startup path: with a key reference that does not resolve the process
stops, and with no reference at all the endpoints answer `503`. A proof nobody can verify is worse than
no proof.

## Rotation

1. Project the new key alongside the old one and set `GENESIS_PROOF_SIGNING_KEY_ID` to it.
2. Move the previous public key into `GENESIS_PROOF_RETIRED_KEYS` so proofs issued in the last minutes
   still verify.
3. Roll. Consumers pick the new key up from the well-known document within its 5-minute cache window.
