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
| d8gueekpf2tfslum7lmg | Thesa Development | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnojg | Thesa | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| 9bsv0s0hijjg02z5lbjg | Stawi | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| 9bsv0s0hijjg09bzz6dg | Stawi Development | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| 9bsv0s0hijjg02z5lr4g | Stawi AI Builder | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| 9bsv0s0hijjghdbz96dg | Stawi AI Builder Development | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d6q1aekpf2taeg5iovp0 | Ant Investor | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d6q1aekpf2taeg5iovqg | Ant Investor Development | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7gi6lkpf2t67dlsqre0 | Stawi Opportunities | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7gi6lkpf2t67dlsqrh0 | Stawi Opportunities Development | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |

## Partitions
| xid | tenant | parent | file |
|-----|--------|--------|------|
| d8gueekpf2tfslum7ln0 | d8gueekpf2tfslum7lmg | d8gueekpf2tfslum7ln0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnokg | c2f4j7au6s7f91uqnojg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7b4qekpf2tshigkrv60 | c2f4j7au6s7f91uqnojg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| 9bsv0s0hijjg02qk7l1g | 9bsv0s0hijjg02z5lbjg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| 9bsv0s0hijjg02qks6i0 | 9bsv0s0hijjg09bzz6dg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| 9bsv0s0hid5g02qkl7gjg | 9bsv0s0hijjg02z5lr4g | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh40 | 9bsv0s0hijjg02z5lr4g | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| 9bsv0s0hijjb83qksr20 | 9bsv0s0hijjghdbz96dg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d6q1aekpf2taeg5iovpg | d6q1aekpf2taeg5iovp0 | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d6q1aekpf2taeg5iovr0 | d6q1aekpf2taeg5iovqg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7gi6lkpf2t67dlsqreg | d7gi6lkpf2t67dlsqre0 | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7gi6lkpf2t67dlsqrhg | d7gi6lkpf2t67dlsqrh0 | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |

## Clients (OAuth2)
| xid | client_id (xid) | partition | file |
|-----|-----------------|-----------|------|
| daid3uspf2t8dfvkjnl0 | service-manufacturing | (SA: service_manufacturing) | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daend44pf2t8c15rs7vg | service-notification-integration-whatsapp | (SA: service_notification_whatsapp) | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daaltq4pf2tb6me3uap0 | imports | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| d8gueekpf2tfslum7lp0 | d8gueekpf2tfslum7lpg | d8gueekpf2tfslum7ln0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnom0 | c2f4j7au6s7f91uqnomg | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7b4qekpf2tshigkrv80 | d7b4qekpf2tshigkrv8g | d7b4qekpf2tshigkrv60 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d6l82t4pf2t82gudn7tg | d6qbqdkpf2t52mcunf40 | 9bsv0s0hijjg02qk7l1g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d6l82t4pf2t82gudn7u0 | d6qbqdkpf2t52mcunf4g | 9bsv0s0hijjg02qks6i0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d6l82t4pf2t82gudn7ug | d6qbqdkpf2t52mcunf50 | 9bsv0s0hid5g02qkl7gjg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d6l82t4pf2t82gudn7v0 | d6qbqdkpf2t52mcunf5g | 9bsv0s0hijjb83qksr20 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d6q1aekpf2taeg5iovq0 | d6qbqdkpf2t52mcunf60 | d6q1aekpf2taeg5iovpg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d6q1aekpf2taeg5iovrg | d6qbqdkpf2t52mcunf6g | d6q1aekpf2taeg5iovr0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7gi6lkpf2t67dlsqrgg | d7is2kspf2t7cl19qlp0 | d7gi6lkpf2t67dlsqreg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7gi6ncpf2t7oh5akfr0 | d7is2kspf2t7cl19qlpg | d7gi6lkpf2t67dlsqrhg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnoog | service-authentication | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnopg | service-profile | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnorg | service-tenancy | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnotg | service-notification | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnovg | service-device | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnp1g | service-settings | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnp3g | service-payment | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnp5g | service-payment-jenga | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnp7g | service-ledger | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnp9g | service-billing | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpbg | service-files | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpdg | service-chat-drone | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpfg | service-chat-gateway | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnplg | trustage | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpng | service-notification-integration-africastalking | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnppg | service-notification-integration-emailsmtp | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnprg | synchronise-partitions | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnptg | service-identity | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpvg | service-loans | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnq3g | service-funding | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnq5g | service-savings | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnq7g | service-operations | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnq9g | service-seed | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnqbg | service-stawi | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d87bdkcpf2t58bn6vaeg | service-limits | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d87bdkcpf2t58bn6vag0 | operations-formstore | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d87bdkcpf2t58bn6vahg | operations-queuestore | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d8as62bvfo145u8bon3g | service-fort | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d8le7qspf2t8u08dff3g | service-payment-pawapay | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d8lt2gkpf2t1ql3csd1g | service-payment-checkout | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d9lemh4pf2t9nfnavkag | service-chat-agent | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9ubvfcpf2tcpcf6c8jg | service-calendar | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8r0 | service-ats | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |

## Service accounts
| xid | profile_id (placeholder) | client | file |
|-----|--------------------------|--------|------|
| daid3uspf2t8dfvkjnm0 | daid38spf2t72pqigk80 | daid3uspf2t8dfvkjnl0 | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daend44pf2t8c15rs80g | daenc7kpf2t8pa1q04hg | daend44pf2t8c15rs7vg | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daaltq4pf2tb6me3uaq0 | daalssspf2tbp6p7ekrg | daaltq4pf2tb6me3uap0 | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| c2f4j7au6s7f91uqnolg | d75qclkpf2t1uum8ij40 | c2f4j7au6s7f91uqnoog | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnoqg | d75qclkpf2t1uum8ij4g | c2f4j7au6s7f91uqnopg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnosg | d75qclkpf2t1uum8ij50 | c2f4j7au6s7f91uqnorg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnoug | d75qclkpf2t1uum8ij5g | c2f4j7au6s7f91uqnotg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnp0g | d75qclkpf2t1uum8ij60 | c2f4j7au6s7f91uqnovg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnp2g | d75qclkpf2t1uum8ij6g | c2f4j7au6s7f91uqnp1g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnp4g | d75qclkpf2t1uum8ij70 | c2f4j7au6s7f91uqnp3g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnp6g | d75qclkpf2t1uum8ij7g | c2f4j7au6s7f91uqnp5g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnp8g | d75qclkpf2t1uum8ij80 | c2f4j7au6s7f91uqnp7g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpag | d75qclkpf2t1uum8ij8g | c2f4j7au6s7f91uqnp9g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpcg | d75qclkpf2t1uum8ij90 | c2f4j7au6s7f91uqnpbg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpeg | d75qclkpf2t1uum8ij9g | c2f4j7au6s7f91uqnpdg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpgg | d75qclkpf2t1uum8ija0 | c2f4j7au6s7f91uqnpfg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpmg | d75qclkpf2t1uum8ijbg | c2f4j7au6s7f91uqnplg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpog | d75qclkpf2t1uum8ijc0 | c2f4j7au6s7f91uqnpng | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpqg | d75qclkpf2t1uum8ijcg | c2f4j7au6s7f91uqnppg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpsg | synchronise_partitions | c2f4j7au6s7f91uqnprg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnpug | d75qclkpf2t1uum8ijdg | c2f4j7au6s7f91uqnptg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnq0g | d75qclkpf2t1uum8ije0 | c2f4j7au6s7f91uqnpvg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnq4g | d75qclkpf2t1uum8ijf0 | c2f4j7au6s7f91uqnq3g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnq6g | d75qclkpf2t1uum8ijfg | c2f4j7au6s7f91uqnq5g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnq8g | d75qclkpf2t1uum8ijg0 | c2f4j7au6s7f91uqnq7g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnqag | d75qclkpf2t1uum8ijgg | c2f4j7au6s7f91uqnq9g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnqcg | d75qclkpf2t1uum8ijh0 | c2f4j7au6s7f91uqnqbg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d87bdkcpf2t58bn6vaf0 | d87bdkcpf2t58bn6vafg | d87bdkcpf2t58bn6vaeg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d87bdkcpf2t58bn6vagg | d87bdkcpf2t58bn6vah0 | d87bdkcpf2t58bn6vag0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d87bdkcpf2t58bn6vai0 | d87bdqcpf2t5b0c3bgbg | d87bdkcpf2t58bn6vahg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9pb0 | d86tt34pf2tddudk9pbg | d86tt34pf2tddudk9pag | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9pcg | d86tt34pf2tddudk9pd0 | d86tt34pf2tddudk9pc0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9pe0 | d86tt34pf2tddudk9peg | d86tt34pf2tddudk9pdg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9pfg | d86tt34pf2tddudk9pg0 | d86tt34pf2tddudk9pf0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9plg | d86tt34pf2tddudk9pm0 | d86tt34pf2tddudk9pl0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9pn0 | d86tt34pf2tddudk9png | d86tt34pf2tddudk9pmg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9pog | d86tt34pf2tddudk9pp0 | d86tt34pf2tddudk9po0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9pq0 | d86tt34pf2tddudk9pqg | d86tt34pf2tddudk9ppg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9prg | d86tt34pf2tddudk9ps0 | d86tt34pf2tddudk9pr0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d8le7qspf2t8u08dff40 | d8le7qspf2t8u08dff4g | d8le7qspf2t8u08dff3g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d8lt2gkpf2t1ql3csd20 | d8lt2gkpf2t1ql3csd2g | d8lt2gkpf2t1ql3csd1g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9q00 | d86tt34pf2tddudk9q0g | d86tt34pf2tddudk9pvg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9q1g | d86tt34pf2tddudk9q20 | d86tt34pf2tddudk9q10 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9q30 | d86tt34pf2tddudk9q3g | d86tt34pf2tddudk9q2g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9q4g | d86tt34pf2tddudk9q50 | d86tt34pf2tddudk9q40 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9q60 | d86tt34pf2tddudk9q6g | d86tt34pf2tddudk9q5g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d86tt34pf2tddudk9q7g | d86tt34pf2tddudk9q80 | d86tt34pf2tddudk9q70 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d8as62fieol45uar4okg | d8as6297jdi45ufqlh70 | d8as62bvfo145u8bon3g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d9lemh4pf2t9nfnavkbg | d9lemh4pf2t9nfnavkcg | d9lemh4pf2t9nfnavkag | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9ubvfcpf2tcpcf6c8k0 | d9ubvfcpf2tcpcf6c8kg | d9ubvfcpf2tcpcf6c8jg | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8rg | d9ubvfcpf2tcpcf6c8s0 | d9ubvfcpf2tcpcf6c8r0 | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |

## Referenced profile IDs
| xid | what | file |
|-----|------|------|

## Partition roles
| xid | role | partition | file |
|-----|------|-----------|------|
| d8gueekpf2tfslum7log | member | d8gueekpf2tfslum7ln0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d8gueekpf2tfslum7lo0 | admin  | d8gueekpf2tfslum7ln0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d8gueekpf2tfslum7lng | owner  | d8gueekpf2tfslum7ln0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| c2f4j7au6s7f91uqnol0 | owner  | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7b4qekpf2tshigkrv70 | owner  | d7b4qekpf2tshigkrv60 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| 9bsv0s0hijjg02qk7l20 | owner  | 9bsv0s0hijjg02qk7l1g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| 9bsv0s0hijjg02qks6j0 | owner  | 9bsv0s0hijjg02qks6i0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| 9bsv0s0hid5g02qkl7h0 | owner  | 9bsv0s0hid5g02qkl7gjg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| 9bsv0s0hijjb83qksr30 | owner  | 9bsv0s0hijjb83qksr20 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7gi6lkpf2t67dlsqrf0 | owner  | d7gi6lkpf2t67dlsqreg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7gi6lkpf2t67dlsqrfg | admin  | d7gi6lkpf2t67dlsqreg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7gi6lkpf2t67dlsqrg0 | member | d7gi6lkpf2t67dlsqreg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7gi6lkpf2t67dlsqri0 | owner  | d7gi6lkpf2t67dlsqrhg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7gi6lkpf2t67dlsqrig | admin  | d7gi6lkpf2t67dlsqrhg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7gi6ncpf2t7oh5akfqg | member | d7gi6lkpf2t67dlsqrhg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfgt0 | admin  | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfgtg | member | c2f4j7au6s7f91uqnokg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfgu0 | admin  | d7b4qekpf2tshigkrv60 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfgug | member | d7b4qekpf2tshigkrv60 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfgv0 | owner  | d6q1aekpf2taeg5iovpg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfgvg | admin  | d6q1aekpf2taeg5iovpg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh00 | member | d6q1aekpf2taeg5iovpg | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh0g | owner  | d6q1aekpf2taeg5iovr0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh10 | admin  | d6q1aekpf2taeg5iovr0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh1g | member | d6q1aekpf2taeg5iovr0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh20 | admin  | 9bsv0s0hijjg02qk7l1g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh2g | member | 9bsv0s0hijjg02qk7l1g | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh30 | admin  | 9bsv0s0hijjg02qks6i0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh3g | member | 9bsv0s0hijjg02qks6i0 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh4g | admin  | d7j42dspf2tfev9jfh40 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh50 | member | d7j42dspf2tfev9jfh40 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh5g | admin  | 9bsv0s0hijjb83qksr20 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |
| d7j42dspf2tfev9jfh60 | member | 9bsv0s0hijjb83qksr20 | apps/tenancy/migrations/0001/20260704_01_greenfield_seed.sql |

## Service chat-agent seed extras
| xid | what | file |
|-----|------|------|
| d9lemh4pf2t9nfnavkag | client row id | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9lemh4pf2t9nfnavkbg | service account | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9lemh4pf2t9nfnavkcg | profile placeholder | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9lemh4pf2t9nfnavkc0 | authorization policy | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9lemn4pf2t9a621dr00 | oauth recipient chat-agent | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9lemn4pf2t9a621dr0g | oauth recipient profile | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9lemn4pf2t9a621dr10 | oauth recipient tenancy | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9lemn4pf2t9a621dr1g | oauth recipient notification | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9lemn4pf2t9a621dr20 | auth grant service_chat_agent | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9lemn4pf2t9a621dr2g | perm chat_agent_view | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9lemn4pf2t9a621dr30 | perm chat_agent_manage | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |
| d9lemn4pf2t9a621dr3g | perm chat_agent_turn | apps/tenancy/migrations/0001/20260730_01_service_chat_agent.sql |

## Matching chat-agent audience (2026-08-06)
| xid | what | file |
|-----|------|------|
| d9mchat1matchaud0001 | oauth recipient matching→chat-agent | apps/tenancy/migrations/0001/20260806_01_matching_chat_agent_audience.sql |
| d9mchat1matchaud0002 | oauth recipient matching→checkout | apps/tenancy/migrations/0001/20260806_01_matching_chat_agent_audience.sql |
| d9mchat1matchgrant001 | auth grant matching service_chat_agent | apps/tenancy/migrations/0001/20260806_01_matching_chat_agent_audience.sql |
| d9mchat1matchperm0001 | perm chat_agent_view (matching) | apps/tenancy/migrations/0001/20260806_01_matching_chat_agent_audience.sql |
| d9mchat1matchperm0002 | perm chat_agent_manage (matching) | apps/tenancy/migrations/0001/20260806_01_matching_chat_agent_audience.sql |
| d9mchat1matchperm0003 | perm chat_agent_turn (matching) | apps/tenancy/migrations/0001/20260806_01_matching_chat_agent_audience.sql |

## Service calendar + ATS (2026-08-12)
| xid | what | file |
|-----|------|------|
| d9ubvfcpf2tcpcf6c8jg | client service-calendar | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8k0 | SA service_calendar | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8kg | profile placeholder calendar | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8l0 | policy calendar | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8lg | recipient /calendar | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8m0 | recipient /profile | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8mg | recipient /tenancy | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8n0 | grant service_calendar | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8ng | perm calendar_resource_view | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8o0 | perm calendar_resource_manage | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8og | perm calendar_availability_manage | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8p0 | perm calendar_slot_view | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8pg | perm calendar_booking_view | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8q0 | perm calendar_booking_manage | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8qg | perm calendar_sync_manage | apps/tenancy/migrations/0001/20260812_01_service_calendar.sql |
| d9ubvfcpf2tcpcf6c8r0 | client service-ats | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c8rg | SA service_ats | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c8s0 | profile placeholder ats | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c8sg | policy ats | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c8t0 | recipient ATS /ats | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c8tg | recipient ATS /calendar | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c8u0 | recipient ATS /profile | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c8ug | recipient ATS /tenancy | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c8v0 | recipient ATS /notification | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c8vg | grant service_ats | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c900 | grant ATS→service_calendar | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c90g | perm ats_dashboard_view | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c910 | perm ats_job_view | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c91g | perm ats_job_manage | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c920 | perm ats_application_view | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c92g | perm ats_application_manage | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c930 | perm ats_interview_view | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c93g | perm ats_interview_manage | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c940 | perm ats_talent_view | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c94g | perm ats_talent_manage | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c950 | perm ats_availability_manage | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c95g | perm ats_ai_use | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c960 | perm ats_hire | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvfcpf2tcpcf6c96g | perm ats_publish | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvjcpf2tcrc8moomg | perm ATS calendar_resource_view | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvjcpf2tcrc8moon0 | perm ATS calendar_resource_manage | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvjcpf2tcrc8moong | perm ATS calendar_availability_manage | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvjcpf2tcrc8mooo0 | perm ATS calendar_slot_view | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvjcpf2tcrc8mooog | perm ATS calendar_booking_view | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvjcpf2tcrc8moop0 | perm ATS calendar_booking_manage | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvjcpf2tcrc8moopg | SPA prod /ats audience | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |
| d9ubvjcpf2tcrc8mooq0 | SPA dev /ats audience | apps/tenancy/migrations/0001/20260812_02_service_ats.sql |

## Service imports (service_imports SA) (2026-08-31)
| xid | what | file |
|-----|------|------|
| daaltq4pf2tb6me3uap0 | client imports | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb6me3uaq0 | SA service_imports | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daalssspf2tbp6p7ekrg | profile placeholder imports | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb6me3uaqg | policy imports | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vshg | recipient /profile | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsi0 | recipient /tenancy | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsig | grant service_imports | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daan2nkpf2t03l5g386g | recipient /trustage | apps/tenancy/migrations/0001/20260831_02_service_imports_trustage.sql |
| daan2nkpf2t03l5g3870 | grant service_trustage | apps/tenancy/migrations/0001/20260831_02_service_imports_trustage.sql |
| daan2nkpf2t03l5g387g | perm workflow_manage | apps/tenancy/migrations/0001/20260831_02_service_imports_trustage.sql |
| daan2nkpf2t03l5g3880 | perm workflow_view | apps/tenancy/migrations/0001/20260831_02_service_imports_trustage.sql |
| daaltq4pf2tb7p83vsj0 | perm acquisition_authorize | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsjg | perm analytics_view | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsk0 | perm orders_update | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vskg | perm orders_view | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsl0 | perm payments_create | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vslg | perm payments_update | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsm0 | perm payments_view | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsmg | perm quotes_create | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsn0 | perm quotes_update | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsng | perm quotes_view | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vso0 | perm requests_update | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsog | perm requests_view | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsp0 | perm transactions_update | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vspg | perm transactions_view | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsq0 | perm vehicles_create | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsqg | perm vehicles_delete | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsr0 | perm vehicles_update | apps/tenancy/migrations/0001/20260831_service_imports.sql |
| daaltq4pf2tb7p83vsrg | perm vehicles_view | apps/tenancy/migrations/0001/20260831_service_imports.sql |

## Stawi Imports Web (prod + dev) (2026-08-30)
| xid | what | file |
|-----|------|------|
| daa7eagthrqitmq00000 | tenant Stawi Imports (prod) | apps/tenancy/migrations/0001/20260830_01_stawi_imports_web_production.sql |
| daa7eagthrqitmq0000g | partition Stawi Imports (prod) | apps/tenancy/migrations/0001/20260830_01_stawi_imports_web_production.sql |
| daa7eagthrqitmq00010 | client row Stawi Imports Web (prod) | apps/tenancy/migrations/0001/20260830_01_stawi_imports_web_production.sql |
| daa7eagthrqitmq0001g | client_id Stawi Imports Web (prod) | apps/tenancy/migrations/0001/20260830_01_stawi_imports_web_production.sql |
| daa7eagthrqitmq00040 | SPA prod /imports audience | apps/tenancy/migrations/0001/20260830_01_stawi_imports_web_production.sql |
| daa7eagthrqitmq0004g | SPA prod /profile audience | apps/tenancy/migrations/0001/20260830_01_stawi_imports_web_production.sql |
| daa7eagthrqitmq00020 | tenant Stawi Imports Development | apps/tenancy/migrations/0001/20260830_02_stawi_imports_web_development.sql |
| daa7eagthrqitmq0002g | partition Stawi Imports Development | apps/tenancy/migrations/0001/20260830_02_stawi_imports_web_development.sql |
| daa7eagthrqitmq00030 | client row Stawi Imports Development | apps/tenancy/migrations/0001/20260830_02_stawi_imports_web_development.sql |
| daa7eagthrqitmq0003g | client_id Stawi Imports Development | apps/tenancy/migrations/0001/20260830_02_stawi_imports_web_development.sql |
| daa7eagthrqitmq00050 | SPA dev /imports audience | apps/tenancy/migrations/0001/20260830_02_stawi_imports_web_development.sql |
| daa7eagthrqitmq0005g | SPA dev /profile audience | apps/tenancy/migrations/0001/20260830_02_stawi_imports_web_development.sql |

## Stawi Imports identity & tenancy access (2026-09-01)
| xid | what | file |
|-----|------|------|
| daa7eagthrqitmq00060 | SPA prod /identity audience | apps/tenancy/migrations/0001/20260901_01_stawi_imports_identity_audience.sql |
| daa7eagthrqitmq0006g | SPA dev /identity audience | apps/tenancy/migrations/0001/20260901_01_stawi_imports_identity_audience.sql |
| daa7eagthrqitmq00070 | SPA prod /tenancy audience | apps/tenancy/migrations/0001/20260901_02_stawi_imports_tenancy_audience.sql |
| daa7eagthrqitmq0007g | SPA dev /tenancy audience | apps/tenancy/migrations/0001/20260901_02_stawi_imports_tenancy_audience.sql |
| daaour1f39n0ifkgrv31 | service_imports SA /identity audience | apps/tenancy/migrations/0001/20260901_03_service_imports_identity.sql |
| daaomolp4gr0qukc6sbi | service_imports SA grant service_identity partition_tree | apps/tenancy/migrations/0001/20260901_03_service_imports_identity.sql |
| daaod4dssiicthalhbah | service_imports SA permit workforce_member_view | apps/tenancy/migrations/0001/20260901_03_service_imports_identity.sql |
| daaolf7gln59nje4cd1b | service_imports SA permit team_view | apps/tenancy/migrations/0001/20260901_03_service_imports_identity.sql |
| daao7mg15br87bq1h5ia | service_imports SA permit team_membership_view | apps/tenancy/migrations/0001/20260901_03_service_imports_identity.sql |

## service_commerce, service_procurement, trustage commerce access (2026-09-06)
| xid | name | file |
|-----|------|------|
| daeltdcpf2t6p29e33f0 | service_commerce service account | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33fg | service_commerce SA placeholder profile | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33eg | service_commerce SA placeholder profile | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33g0 | service_commerce SA authorization policy | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33k0 | service_commerce SA grant service_commerce partition_tree | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33kg | service_commerce SA grant service_checkout partition_tree | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33l0 | service_commerce SA grant service_ledger partition_tree | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33lg | service_commerce SA grant service_notification partition_tree | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33m0 | service_commerce SA grant service_trustage partition_tree | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33mg | service_commerce SA permit shop_view | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33n0 | service_commerce SA permit shops_list | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33ng | service_commerce SA permit product_view | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33o0 | service_commerce SA permit order_view | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33og | service_commerce SA permit order_manage | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33p0 | service_commerce SA permit ledger_post | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33pg | service_commerce SA permit checkout_session_create | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33q0 | service_commerce SA permit checkout_session_view | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33qg | service_commerce SA permit ledger_view | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33r0 | service_commerce SA permit ledger_manage | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33rg | service_commerce SA permit account_view | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33s0 | service_commerce SA permit account_manage | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33sg | service_commerce SA permit transaction_view | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33t0 | service_commerce SA permit transaction_manage | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33tg | service_commerce SA permit book_view | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33u0 | service_commerce SA permit book_manage | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33ug | service_commerce SA permit notification_send | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33v0 | service_commerce SA permit template_manage | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33vg | service_commerce SA permit template_view | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e3400 | service_commerce SA permit workflow_view | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e340g | service_commerce SA permit workflow_manage | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e341g | service_procurement service account | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e3420 | service_procurement SA placeholder profile | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e3410 | service_procurement SA placeholder profile | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e342g | service_procurement SA authorization policy | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e344g | service_procurement SA grant service_procurement partition_tree | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e3450 | service_procurement SA permit supplier_view | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e345g | service_procurement SA permit supplier_manage | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e3460 | service_procurement SA permit purchase_order_view | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e346g | service_procurement SA permit purchase_order_create | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e3470 | service_procurement SA permit purchase_order_submit | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e347g | service_procurement SA permit purchase_order_cancel | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e3480 | service_procurement SA permit goods_receipt_view | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e348g | service_procurement SA permit goods_receipt_create | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e3490 | trustage SA grant service_commerce partition_tree | apps/tenancy/migrations/0001/20260906_03_trustage_commerce.sql |
| daeltdcpf2t6p29e34a0 | trustage SA permit ledger_post | apps/tenancy/migrations/0001/20260906_03_trustage_commerce.sql |
| daeltdcpf2t6p29e34ag | trustage SA permit shops_list | apps/tenancy/migrations/0001/20260906_03_trustage_commerce.sql |
| dadbslspf2t8u24o8r1g | service_imports SA /files audience | apps/tenancy/migrations/0001/20260904_02_service_imports_files.sql |
| dadbslspf2t8u24o8r20 | service_imports SA grant service_file partition_tree | apps/tenancy/migrations/0001/20260904_02_service_imports_files.sql |
| dadbslspf2t8u24o8r2g | service_imports SA permit content_upload | apps/tenancy/migrations/0001/20260904_02_service_imports_files.sql |
| dadbslspf2t8u24o8r30 | service_imports SA permit content_view | apps/tenancy/migrations/0001/20260904_02_service_imports_files.sql |
| dadbslspf2t8u24o8r3g | service_imports SA permit content_manage | apps/tenancy/migrations/0001/20260904_02_service_imports_files.sql |
| dadbslspf2t8u24o8r40 | service_imports SA permit content_delete | apps/tenancy/migrations/0001/20260904_02_service_imports_files.sql |
| dadbol4pf2t2qn50nh0g | service_imports SA /notification audience | apps/tenancy/migrations/0001/20260904_service_imports_notification.sql |
| dadbol4pf2t2qn50nh10 | service_imports SA grant service_notification partition_tree | apps/tenancy/migrations/0001/20260904_service_imports_notification.sql |
| dadbol4pf2t2qn50nh1g | service_imports SA permit template_manage | apps/tenancy/migrations/0001/20260904_service_imports_notification.sql |
| dadbol4pf2t2qn50nh20 | service_imports SA permit notification_send | apps/tenancy/migrations/0001/20260904_service_imports_notification.sql |
| daeltdcpf2t6p29e33gg | service_commerce SA /commerce audience | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33h0 | service_commerce SA /tenancy audience | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33hg | service_commerce SA /profile audience | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33i0 | service_commerce SA /checkout audience | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33ig | service_commerce SA /ledger audience | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33j0 | service_commerce SA /notification audience | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e33jg | service_commerce SA /trustage audience | apps/tenancy/migrations/0001/20260906_01_service_commerce.sql |
| daeltdcpf2t6p29e3430 | service_procurement SA /procurement audience | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e343g | service_procurement SA /tenancy audience | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e3440 | service_procurement SA /profile audience | apps/tenancy/migrations/0001/20260906_02_service_procurement.sql |
| daeltdcpf2t6p29e349g | trustage SA /commerce audience | apps/tenancy/migrations/0001/20260906_03_trustage_commerce.sql |
| d94lkmcpf2t39vdkp1f0 | trustage SA authorization policy (auth contract seed) (reference) | apps/tenancy/migrations/0001/20260906_03_trustage_commerce.sql |

## service_notification_whatsapp integration SA (2026-09-06)
| xid | name | file |
|-----|------|------|
| daend4kpf2t8cmavmue0 | service_notification_whatsapp SA audience https://api.stawi.org/notification | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmueg | service_notification_whatsapp SA audience https://api.stawi.org/profile | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuf0 | service_notification_whatsapp SA audience https://api.stawi.org/settings | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmufg | service_notification_whatsapp SA audience https://api.stawi.org/tenancy | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend44pf2t8c15rs810 | service_notification_whatsapp SA authorization policy | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmug0 | service_notification_whatsapp SA grant service_notification partition_tree | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmugg | service_notification_whatsapp SA permit notification_release | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuh0 | service_notification_whatsapp SA permit notification_search | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuhg | service_notification_whatsapp SA permit notification_send | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmui0 | service_notification_whatsapp SA permit notification_status_update | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuig | service_notification_whatsapp SA permit notification_status_view | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuj0 | service_notification_whatsapp SA permit template_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmujg | service_notification_whatsapp SA permit template_view | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuk0 | service_notification_whatsapp SA grant service_profile partition_tree | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmukg | service_notification_whatsapp SA permit address_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmul0 | service_notification_whatsapp SA permit contact_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmulg | service_notification_whatsapp SA permit profile_create | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmum0 | service_notification_whatsapp SA permit profile_merge | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmumg | service_notification_whatsapp SA permit profile_update | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmun0 | service_notification_whatsapp SA permit profile_view | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmung | service_notification_whatsapp SA permit relationship_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuo0 | service_notification_whatsapp SA permit relationship_view | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuog | service_notification_whatsapp SA permit roster_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmup0 | service_notification_whatsapp SA permit roster_view | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmupg | service_notification_whatsapp SA grant service_setting partition_tree | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuq0 | service_notification_whatsapp SA permit setting_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuqg | service_notification_whatsapp SA permit setting_view | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmur0 | service_notification_whatsapp SA grant service_tenancy partition_tree | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmurg | service_notification_whatsapp SA permit access_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmus0 | service_notification_whatsapp SA permit access_view | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmusg | service_notification_whatsapp SA permit client_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmut0 | service_notification_whatsapp SA permit client_view | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmutg | service_notification_whatsapp SA permit page_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuu0 | service_notification_whatsapp SA permit page_view | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuug | service_notification_whatsapp SA permit partition_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuv0 | service_notification_whatsapp SA permit partition_view | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmuvg | service_notification_whatsapp SA permit permission_grant | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmv00 | service_notification_whatsapp SA permit role_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmv0g | service_notification_whatsapp SA permit service_account_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmv10 | service_notification_whatsapp SA permit service_account_view | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmv1g | service_notification_whatsapp SA permit tenant_manage | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |
| daend4kpf2t8cmavmv20 | service_notification_whatsapp SA permit tenant_view | apps/tenancy/migrations/0001/20260906_05_service_notification_whatsapp.sql |

## service_manufacturing SA (2026-09-12)
| xid | purpose | file |
|-----|---------|------|
| daid3v4pf2t8dv11qcd0 | service_manufacturing SA recipient https://api.stawi.org/profile | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcdg | service_manufacturing SA recipient https://api.stawi.org/tenancy | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3uspf2t8dfvkjnmg | service_manufacturing SA authorization policy | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qce0 | service_manufacturing SA grant service_manufacturing partition_tree | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qceg | service_manufacturing SA permission batch_complete | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcf0 | service_manufacturing SA permission batch_operate | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcfg | service_manufacturing SA permission batch_override | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcg0 | service_manufacturing SA permission batch_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcgg | service_manufacturing SA permission cleaning_perform | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qch0 | service_manufacturing SA permission cleaning_verify | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qchg | service_manufacturing SA permission costing_manage | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qci0 | service_manufacturing SA permission costing_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcig | service_manufacturing SA permission demand_manage | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcj0 | service_manufacturing SA permission demand_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcjg | service_manufacturing SA permission environment_alarm_acknowledge | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qck0 | service_manufacturing SA permission environment_manage | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qckg | service_manufacturing SA permission environment_record | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcl0 | service_manufacturing SA permission environment_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qclg | service_manufacturing SA permission equipment_manage | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcm0 | service_manufacturing SA permission equipment_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcmg | service_manufacturing SA permission inspection_override | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcn0 | service_manufacturing SA permission inspection_perform | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcng | service_manufacturing SA permission inspection_template_manage | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qco0 | service_manufacturing SA permission inspection_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcog | service_manufacturing SA permission inventory_adjust | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcp0 | service_manufacturing SA permission inventory_manage | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcpg | service_manufacturing SA permission inventory_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcq0 | service_manufacturing SA permission label_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcqg | service_manufacturing SA permission maintenance_manage | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcr0 | service_manufacturing SA permission plan_manage | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcrg | service_manufacturing SA permission plan_validate | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcs0 | service_manufacturing SA permission plan_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcsg | service_manufacturing SA permission recall_initiate | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qct0 | service_manufacturing SA permission recall_manage | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qctg | service_manufacturing SA permission recall_resolve | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcu0 | service_manufacturing SA permission recipe_manage | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcug | service_manufacturing SA permission recipe_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcv0 | service_manufacturing SA permission shelf_life_manage | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qcvg | service_manufacturing SA permission shelf_life_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qd00 | service_manufacturing SA permission trace_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qd0g | service_manufacturing SA permission waste_dispose | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qd10 | service_manufacturing SA permission waste_record | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
| daid3v4pf2t8dv11qd1g | service_manufacturing SA permission waste_view | apps/tenancy/migrations/0001/20260912_01_service_manufacturing.sql |
