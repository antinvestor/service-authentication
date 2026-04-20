# Tenancy ID registry

Every xid introduced by a seed migration is recorded here.
`check-ids.sh` (wired into `make format`) fails if any xid in the SQL files
is missing from this file, or vice versa.

## How to add a new entry

Use `make new-partition NAME=<snake>` or `make new-service NAME=<snake>`;
the scaffolder generates fresh xids and appends rows here automatically.

Never hand-edit xids. Never reuse an xid across rows.

## Carve-out: service-account client_ids

The spec's "xid-only client_id" rule applies to partition public clients
(end-user-facing apps). Service-account `clients.client_id` columns keep
their human-readable form (e.g. `service-authentication`, `service-profile`)
because they are the public identifiers other services target in the `aud`
claim; making them xids would cascade into every consumer's OAuth2 audience
configuration.

## Tenants
| xid | name | file |
|-----|------|------|
| c2f4j7au6s7f91uqnojg | Thesa | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |

## Partitions
| xid | tenant | parent | file |
|-----|--------|--------|------|
| c2f4j7au6s7f91uqnokg | c2f4j7au6s7f91uqnojg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv60 | c2f4j7au6s7f91uqnojg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |

## Clients (OAuth2)
| xid | client_id (xid) | partition | file |
|-----|-----------------|-----------|------|
| c2f4j7au6s7f91uqnom0 | c2f4j7au6s7f91uqnomg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv80 | d7b4qekpf2tshigkrv8g | d7b4qekpf2tshigkrv60 | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |

## Service accounts
| xid | profile_id (placeholder) | client | file |
|-----|--------------------------|--------|------|

## Partition roles
| xid | role | partition | file |
|-----|------|-----------|------|
| c2f4j7au6s7f91uqnol0 | owner  | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| c2f4j7au6s7f91uqnol1 | admin  | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| c2f4j7au6s7f91uqnol2 | member | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv70 | owner  | d7b4qekpf2tshigkrv60 | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv71 | admin  | d7b4qekpf2tshigkrv60 | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv72 | member | d7b4qekpf2tshigkrv60 | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
