# Greenfield v2 baseline

The tenancy database starts directly on the v2 authentication contract. The baseline contains:

- OAuth clients with canonical HTTPS resource recipients in `oauth_client_recipients`;
- service accounts with independent authorization policies, grants, and explicit permissions;
- no overloaded `audiences`, client `roles`, or service-account secret columns;
- no runtime backfill, compatibility schema, or destructive startup DDL.

`20260704_01_greenfield_seed.sql` contains stable platform entities. `20260704_02_auth_contract_seed.sql` contains normalized contract rows derived from the audited deployment catalog snapshot. Internal recipient, policy, grant, and permission IDs are stable seed implementation details and are excluded from `IDS.md`.

New seed migrations must use `new-partition.sh` or `new-service.sh`. Both accept canonical recipient URL arrays; service seeds also require explicit authorization grants.
