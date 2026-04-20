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

## Partitions
| xid | tenant | parent | file |
|-----|--------|--------|------|

## Clients (OAuth2)
| xid | client_id (xid) | partition | file |
|-----|-----------------|-----------|------|

## Service accounts
| xid | profile_id (placeholder) | client | file |
|-----|--------------------------|--------|------|

## Partition roles
| xid | role | partition | file |
|-----|------|-----------|------|
