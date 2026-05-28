-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add the `service_trustage` audience to service accounts that
-- need to call Trustage's CreateWorkflow API to register their workflow
-- definitions during their migration Jobs.
--
-- The original seeds used INSERT ... ON CONFLICT (id) DO NOTHING, so
-- editing those seeds alone fixes only fresh installs. On already-seeded
-- clusters the rows predate the service_trustage addition, so their
-- audiences JSON is missing the key. When the consumer app's migration
-- Job requests a token with service_trustage in the audience list,
-- Hydra rejects it because the audience isn't whitelisted.
--
-- Affected clients:
--   - opportunities-crawler (d86tt34pf2tddudk9q10)
--   - service-seed          (c2f4j7au6s7f91uqnq9g)
--   - service-stawi         (c2f4j7au6s7f91uqnqbg)
--
-- Idempotent: no-op if service_trustage is already present.
-- Clearing synced_at forces the next sync cycle to POST the corrected
-- audience list to Hydra.

UPDATE clients
SET audiences = audiences || '{"service_trustage":["*"]}'::jsonb,
    synced_at = NULL
WHERE id IN (
    'd86tt34pf2tddudk9q10',
    'c2f4j7au6s7f91uqnq9g',
    'c2f4j7au6s7f91uqnqbg'
)
  AND NOT (audiences ? 'service_trustage');

UPDATE service_accounts
SET audiences = audiences || '{"service_trustage":["*"]}'::jsonb
WHERE id IN (
    'd86tt34pf2tddudk9q1g',
    'c2f4j7au6s7f91uqnqag',
    'c2f4j7au6s7f91uqnqcg'
)
  AND NOT (audiences ? 'service_trustage');
