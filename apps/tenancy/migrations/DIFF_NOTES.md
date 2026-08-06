# Greenfield v2 baseline

The tenancy database starts directly on the v2 authentication contract. The baseline contains:

- OAuth clients with canonical HTTPS resource recipients in `oauth_client_recipients`;
- service accounts with independent authorization policies, grants, and explicit permissions;
- no overloaded `audiences`, client `roles`, or service-account secret columns;
- no runtime backfill, compatibility schema, or destructive startup DDL.

`20260704_01_greenfield_seed.sql` contains stable platform entities. `20260704_02_auth_contract_seed.sql` contains normalized contract rows derived from the audited deployment catalog snapshot. Internal recipient, policy, grant, and permission IDs are stable seed implementation details and are excluded from `IDS.md`.

The snapshot is bootstrap data, not a service catalog. After bootstrap, new service audiences are accepted as canonical HTTPS children of the configured platform audience base, and permission namespaces are registered by authenticated services at startup. Adding a service does not require an authentication-service source or migration change.

If the baseline itself is intentionally regenerated, use `new-partition.sh` or `new-service.sh`. Both accept canonical recipient URL arrays; service seeds also require explicit authorization grants.

## Product peer edges (read before writing another migration)

**ADR:** `docs/adr/0002-product-peer-mesh-not-per-tenant-grants.md`

| Do | Do not |
|----|--------|
| Declare S2S peers on the **consumer product SA** (recipients + SA grants) at platform root | Write “grant customer X chat-agent” / per-tenant S2S rows |
| Use dated SQL only as **live-cluster repair** of a named `client_id` / SA | Treat repair migrations as the product model or copy them per tenant |
| Keep deploy `requested_audience_paths` ⊆ consumer recipients | Ship deploy peers without Hydra whitelist + ReBAC grants |
| Scaffold **new** SAs with `new-service.sh` (`RECIPIENTS` + `GRANTS`) | Expect `new-service` to reverse-wire existing consumers |

When a product bot starts calling a peer (e.g. matching → chat-agent), update
**that product SA’s** auth contract in the same program of work. Logged-in users
inherit the feature via product edge access (SPA audience + partition membership);
they never need SA grant rows for the peer.

Historical repair example (not a customer template):
`0001/20260806_01_matching_chat_agent_audience.sql`.
