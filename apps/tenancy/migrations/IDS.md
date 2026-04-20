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
| 9bsv0s0hijjg02z5lbjg | Stawi | apps/tenancy/migrations/0001/20260420_partition_stawi.sql |
| 9bsv0s0hijjg09bzz6dg | Stawi Development | apps/tenancy/migrations/0001/20260420_partition_stawi.sql |
| 9bsv0s0hijjg02z5lr4g | Stawi AI Builder | apps/tenancy/migrations/0001/20260420_partition_stawi_dev.sql |
| 9bsv0s0hijjghdbz96dg | Stawi AI Builder Development | apps/tenancy/migrations/0001/20260420_partition_stawi_dev.sql |
| d6q1aekpf2taeg5iovp0 | Ant Investor | apps/tenancy/migrations/0001/20260420_partition_ant_investor.sql |
| d6q1aekpf2taeg5iovqg | Ant Investor Development | apps/tenancy/migrations/0001/20260420_partition_ant_investor.sql |
| d7gi6lkpf2t67dlsqre0 | Stawi Jobs | apps/tenancy/migrations/0001/20260420_partition_stawi_jobs.sql |
| d7gi6lkpf2t67dlsqrh0 | Stawi Jobs Development | apps/tenancy/migrations/0001/20260420_partition_stawi_jobs.sql |

## Partitions
| xid | tenant | parent | file |
|-----|--------|--------|------|
| c2f4j7au6s7f91uqnokg | c2f4j7au6s7f91uqnojg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv60 | c2f4j7au6s7f91uqnojg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| 9bsv0s0hijjg02qk7l1g | 9bsv0s0hijjg02z5lbjg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_stawi.sql |
| 9bsv0s0hijjg02qks6i0 | 9bsv0s0hijjg09bzz6dg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_stawi.sql |
| 9bsv0s0hid5g02qkl7gjg | 9bsv0s0hijjg02z5lr4g | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_stawi_dev.sql |
| 9bsv0s0hijjb83qksr20 | 9bsv0s0hijjghdbz96dg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_stawi_dev.sql |
| d6q1aekpf2taeg5iovpg | d6q1aekpf2taeg5iovp0 | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_ant_investor.sql |
| d6q1aekpf2taeg5iovr0 | d6q1aekpf2taeg5iovqg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_ant_investor.sql |
| d7gi6lkpf2t67dlsqreg | d7gi6lkpf2t67dlsqre0 | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_stawi_jobs.sql |
| d7gi6lkpf2t67dlsqrhg | d7gi6lkpf2t67dlsqrh0 | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_stawi_jobs.sql |

## Clients (OAuth2)
| xid | client_id (xid) | partition | file |
|-----|-----------------|-----------|------|
| c2f4j7au6s7f91uqnom0 | c2f4j7au6s7f91uqnomg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv80 | d7b4qekpf2tshigkrv8g | d7b4qekpf2tshigkrv60 | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| d6l82t4pf2t82gudn7tg | d6qbqdkpf2t52mcunf40 | 9bsv0s0hijjg02qk7l1g | apps/tenancy/migrations/0001/20260420_partition_stawi.sql |
| d6l82t4pf2t82gudn7u0 | d6qbqdkpf2t52mcunf4g | 9bsv0s0hijjg02qks6i0 | apps/tenancy/migrations/0001/20260420_partition_stawi.sql |
| d6l82t4pf2t82gudn7ug | d6qbqdkpf2t52mcunf50 | 9bsv0s0hid5g02qkl7gjg | apps/tenancy/migrations/0001/20260420_partition_stawi_dev.sql |
| d6l82t4pf2t82gudn7v0 | d6qbqdkpf2t52mcunf5g | 9bsv0s0hijjb83qksr20 | apps/tenancy/migrations/0001/20260420_partition_stawi_dev.sql |
| d6q1aekpf2taeg5iovq0 | d6qbqdkpf2t52mcunf60 | d6q1aekpf2taeg5iovpg | apps/tenancy/migrations/0001/20260420_partition_ant_investor.sql |
| d6q1aekpf2taeg5iovrg | d6qbqdkpf2t52mcunf6g | d6q1aekpf2taeg5iovr0 | apps/tenancy/migrations/0001/20260420_partition_ant_investor.sql |
| d7gi6lkpf2t67dlsqrgg | d7is2kspf2t7cl19qlp0 | d7gi6lkpf2t67dlsqreg | apps/tenancy/migrations/0001/20260420_partition_stawi_jobs.sql |
| d7gi6ncpf2t7oh5akfr0 | d7is2kspf2t7cl19qlpg | d7gi6lkpf2t67dlsqrhg | apps/tenancy/migrations/0001/20260420_partition_stawi_jobs.sql |
| c2f4j7au6s7f91uqnoog | service-authentication | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_authentication.sql |
| c2f4j7au6s7f91uqnopg | service-profile | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_profile.sql |
| c2f4j7au6s7f91uqnorg | service-tenancy | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_tenancy.sql |
| c2f4j7au6s7f91uqnotg | service-notification | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_notification.sql |
| c2f4j7au6s7f91uqnovg | service-device | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_device.sql |
| c2f4j7au6s7f91uqnp1g | service-settings | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_setting.sql |
| c2f4j7au6s7f91uqnp3g | service-payment | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_payment.sql |
| c2f4j7au6s7f91uqnp5g | service-payment-jenga | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_payment_jenga.sql |
| c2f4j7au6s7f91uqnp7g | service-ledger | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_ledger.sql |
| c2f4j7au6s7f91uqnp9g | service-billing | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_billing.sql |
| c2f4j7au6s7f91uqnpbg | service-files | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_files.sql |
| c2f4j7au6s7f91uqnpdg | service-chat-drone | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_chat_drone.sql |
| c2f4j7au6s7f91uqnpfg | service-chat-gateway | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_chat_gateway.sql |
| c2f4j7au6s7f91uqnphg | foundry | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_foundry.sql |
| c2f4j7au6s7f91uqnpjg | gitvault | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_gitvault.sql |
| c2f4j7au6s7f91uqnplg | trustage | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_trustage.sql |
| c2f4j7au6s7f91uqnpng | service-notification-integration-africastalking | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_notification_africastalking.sql |
| c2f4j7au6s7f91uqnppg | service-notification-integration-emailsmtp | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_notification_emailsmtp.sql |
| c2f4j7au6s7f91uqnprg | synchronise-partitions | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_synchronise_partitions.sql |
| c2f4j7au6s7f91uqnptg | service-identity | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_identity.sql |
| c2f4j7au6s7f91uqnpvg | service-loans | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_loans.sql |
| c2f4j7au6s7f91uqnq3g | service-funding | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_funding.sql |
| c2f4j7au6s7f91uqnq5g | service-savings | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_savings.sql |
| c2f4j7au6s7f91uqnq7g | service-operations | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_operations.sql |
| c2f4j7au6s7f91uqnq9g | service-seed | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_seed.sql |
| c2f4j7au6s7f91uqnqbg | service-stawi | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_service_service_stawi.sql |

## Service accounts
| xid | profile_id (placeholder) | client | file |
|-----|--------------------------|--------|------|
| c2f4j7au6s7f91uqnolg | d75qclkpf2t1uum8ij40 | c2f4j7au6s7f91uqnoog | apps/tenancy/migrations/0001/20260420_service_service_authentication.sql |
| c2f4j7au6s7f91uqnoqg | d75qclkpf2t1uum8ij4g | c2f4j7au6s7f91uqnopg | apps/tenancy/migrations/0001/20260420_service_service_profile.sql |
| c2f4j7au6s7f91uqnosg | d75qclkpf2t1uum8ij50 | c2f4j7au6s7f91uqnorg | apps/tenancy/migrations/0001/20260420_service_service_tenancy.sql |
| c2f4j7au6s7f91uqnoug | d75qclkpf2t1uum8ij5g | c2f4j7au6s7f91uqnotg | apps/tenancy/migrations/0001/20260420_service_service_notification.sql |
| c2f4j7au6s7f91uqnp0g | d75qclkpf2t1uum8ij60 | c2f4j7au6s7f91uqnovg | apps/tenancy/migrations/0001/20260420_service_service_device.sql |
| c2f4j7au6s7f91uqnp2g | d75qclkpf2t1uum8ij6g | c2f4j7au6s7f91uqnp1g | apps/tenancy/migrations/0001/20260420_service_service_setting.sql |
| c2f4j7au6s7f91uqnp4g | d75qclkpf2t1uum8ij70 | c2f4j7au6s7f91uqnp3g | apps/tenancy/migrations/0001/20260420_service_service_payment.sql |
| c2f4j7au6s7f91uqnp6g | d75qclkpf2t1uum8ij7g | c2f4j7au6s7f91uqnp5g | apps/tenancy/migrations/0001/20260420_service_service_payment_jenga.sql |
| c2f4j7au6s7f91uqnp8g | d75qclkpf2t1uum8ij80 | c2f4j7au6s7f91uqnp7g | apps/tenancy/migrations/0001/20260420_service_service_ledger.sql |
| c2f4j7au6s7f91uqnpag | d75qclkpf2t1uum8ij8g | c2f4j7au6s7f91uqnp9g | apps/tenancy/migrations/0001/20260420_service_service_billing.sql |
| c2f4j7au6s7f91uqnpcg | d75qclkpf2t1uum8ij90 | c2f4j7au6s7f91uqnpbg | apps/tenancy/migrations/0001/20260420_service_service_files.sql |
| c2f4j7au6s7f91uqnpeg | d75qclkpf2t1uum8ij9g | c2f4j7au6s7f91uqnpdg | apps/tenancy/migrations/0001/20260420_service_service_chat_drone.sql |
| c2f4j7au6s7f91uqnpgg | d75qclkpf2t1uum8ija0 | c2f4j7au6s7f91uqnpfg | apps/tenancy/migrations/0001/20260420_service_service_chat_gateway.sql |
| c2f4j7au6s7f91uqnpig | d75qclkpf2t1uum8ijag | c2f4j7au6s7f91uqnphg | apps/tenancy/migrations/0001/20260420_service_service_foundry.sql |
| c2f4j7au6s7f91uqnpkg | d75qclkpf2t1uum8ijb0 | c2f4j7au6s7f91uqnpjg | apps/tenancy/migrations/0001/20260420_service_service_gitvault.sql |
| c2f4j7au6s7f91uqnpmg | d75qclkpf2t1uum8ijbg | c2f4j7au6s7f91uqnplg | apps/tenancy/migrations/0001/20260420_service_service_trustage.sql |
| c2f4j7au6s7f91uqnpog | d75qclkpf2t1uum8ijc0 | c2f4j7au6s7f91uqnpng | apps/tenancy/migrations/0001/20260420_service_service_notification_africastalking.sql |
| c2f4j7au6s7f91uqnpqg | d75qclkpf2t1uum8ijcg | c2f4j7au6s7f91uqnppg | apps/tenancy/migrations/0001/20260420_service_service_notification_emailsmtp.sql |
| c2f4j7au6s7f91uqnpsg | synchronise_partitions | c2f4j7au6s7f91uqnprg | apps/tenancy/migrations/0001/20260420_service_service_synchronise_partitions.sql |
| c2f4j7au6s7f91uqnpug | d75qclkpf2t1uum8ijdg | c2f4j7au6s7f91uqnptg | apps/tenancy/migrations/0001/20260420_service_service_identity.sql |
| c2f4j7au6s7f91uqnq0g | d75qclkpf2t1uum8ije0 | c2f4j7au6s7f91uqnpvg | apps/tenancy/migrations/0001/20260420_service_service_loans.sql |
| c2f4j7au6s7f91uqnq4g | d75qclkpf2t1uum8ijf0 | c2f4j7au6s7f91uqnq3g | apps/tenancy/migrations/0001/20260420_service_service_funding.sql |
| c2f4j7au6s7f91uqnq6g | d75qclkpf2t1uum8ijfg | c2f4j7au6s7f91uqnq5g | apps/tenancy/migrations/0001/20260420_service_service_savings.sql |
| c2f4j7au6s7f91uqnq8g | d75qclkpf2t1uum8ijg0 | c2f4j7au6s7f91uqnq7g | apps/tenancy/migrations/0001/20260420_service_service_operations.sql |
| c2f4j7au6s7f91uqnqag | d75qclkpf2t1uum8ijgg | c2f4j7au6s7f91uqnq9g | apps/tenancy/migrations/0001/20260420_service_service_seed.sql |
| c2f4j7au6s7f91uqnqcg | d75qclkpf2t1uum8ijh0 | c2f4j7au6s7f91uqnqbg | apps/tenancy/migrations/0001/20260420_service_service_stawi.sql |

## Partition roles
| xid | role | partition | file |
|-----|------|-----------|------|
| c2f4j7au6s7f91uqnol0 | owner  | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| c2f4j7au6s7f91uqnol1 | admin  | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| c2f4j7au6s7f91uqnol2 | member | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv70 | owner  | d7b4qekpf2tshigkrv60 | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv71 | admin  | d7b4qekpf2tshigkrv60 | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| d7b4qekpf2tshigkrv72 | member | d7b4qekpf2tshigkrv60 | apps/tenancy/migrations/0001/20260420_partition_thesa.sql |
| 9bsv0s0hijjg02qk7l20 | owner  | 9bsv0s0hijjg02qk7l1g | apps/tenancy/migrations/0001/20260420_partition_stawi.sql |
| 9bsv0s0hijjg02qk7l21 | admin  | 9bsv0s0hijjg02qk7l1g | apps/tenancy/migrations/0001/20260420_partition_stawi.sql |
| 9bsv0s0hijjg02qk7l22 | member | 9bsv0s0hijjg02qk7l1g | apps/tenancy/migrations/0001/20260420_partition_stawi.sql |
| 9bsv0s0hijjg02qks6j0 | owner  | 9bsv0s0hijjg02qks6i0 | apps/tenancy/migrations/0001/20260420_partition_stawi.sql |
| 9bsv0s0hijjg02qks6j1 | admin  | 9bsv0s0hijjg02qks6i0 | apps/tenancy/migrations/0001/20260420_partition_stawi.sql |
| 9bsv0s0hijjg02qks6j2 | member | 9bsv0s0hijjg02qks6i0 | apps/tenancy/migrations/0001/20260420_partition_stawi.sql |
| 9bsv0s0hid5g02qkl7h0 | owner  | 9bsv0s0hid5g02qkl7gjg | apps/tenancy/migrations/0001/20260420_partition_stawi_dev.sql |
| 9bsv0s0hid5g02qkl7h1 | admin  | 9bsv0s0hid5g02qkl7gjg | apps/tenancy/migrations/0001/20260420_partition_stawi_dev.sql |
| 9bsv0s0hid5g02qkl7h2 | member | 9bsv0s0hid5g02qkl7gjg | apps/tenancy/migrations/0001/20260420_partition_stawi_dev.sql |
| 9bsv0s0hijjb83qksr30 | owner  | 9bsv0s0hijjb83qksr20 | apps/tenancy/migrations/0001/20260420_partition_stawi_dev.sql |
| 9bsv0s0hijjb83qksr31 | admin  | 9bsv0s0hijjb83qksr20 | apps/tenancy/migrations/0001/20260420_partition_stawi_dev.sql |
| 9bsv0s0hijjb83qksr32 | member | 9bsv0s0hijjb83qksr20 | apps/tenancy/migrations/0001/20260420_partition_stawi_dev.sql |
| d6q1aekpf2taeg5iovq1 | owner  | d6q1aekpf2taeg5iovpg | apps/tenancy/migrations/0001/20260420_partition_ant_investor.sql |
| d6q1aekpf2taeg5iovq2 | admin  | d6q1aekpf2taeg5iovpg | apps/tenancy/migrations/0001/20260420_partition_ant_investor.sql |
| d6q1aekpf2taeg5iovq3 | member | d6q1aekpf2taeg5iovpg | apps/tenancy/migrations/0001/20260420_partition_ant_investor.sql |
| d6q1aekpf2taeg5iovr1 | owner  | d6q1aekpf2taeg5iovr0 | apps/tenancy/migrations/0001/20260420_partition_ant_investor.sql |
| d6q1aekpf2taeg5iovr2 | admin  | d6q1aekpf2taeg5iovr0 | apps/tenancy/migrations/0001/20260420_partition_ant_investor.sql |
| d6q1aekpf2taeg5iovr3 | member | d6q1aekpf2taeg5iovr0 | apps/tenancy/migrations/0001/20260420_partition_ant_investor.sql |
| d7gi6lkpf2t67dlsqrf0 | owner  | d7gi6lkpf2t67dlsqreg | apps/tenancy/migrations/0001/20260420_partition_stawi_jobs.sql |
| d7gi6lkpf2t67dlsqrfg | admin  | d7gi6lkpf2t67dlsqreg | apps/tenancy/migrations/0001/20260420_partition_stawi_jobs.sql |
| d7gi6lkpf2t67dlsqrg0 | member | d7gi6lkpf2t67dlsqreg | apps/tenancy/migrations/0001/20260420_partition_stawi_jobs.sql |
| d7gi6lkpf2t67dlsqri0 | owner  | d7gi6lkpf2t67dlsqrhg | apps/tenancy/migrations/0001/20260420_partition_stawi_jobs.sql |
| d7gi6lkpf2t67dlsqrig | admin  | d7gi6lkpf2t67dlsqrhg | apps/tenancy/migrations/0001/20260420_partition_stawi_jobs.sql |
| d7gi6ncpf2t7oh5akfqg | member | d7gi6lkpf2t67dlsqrhg | apps/tenancy/migrations/0001/20260420_partition_stawi_jobs.sql |
