-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add missing audiences to the trustage client + service_account.
-- The original seed omitted opportunities_crawler and opportunities_api.
--
-- Clearing synced_at forces the next sync cycle to POST the corrected
-- audience list to Hydra.

UPDATE clients
SET audiences = audiences || '{"opportunities_crawler":["*"],"opportunities_api":["*"]}'::jsonb,
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnplg'
  AND NOT (audiences ?& array['opportunities_crawler','opportunities_api']);

UPDATE service_accounts
SET audiences = audiences || '{"opportunities_crawler":["*"],"opportunities_api":["*"]}'::jsonb
WHERE id = 'c2f4j7au6s7f91uqnpmg'
  AND NOT (audiences ?& array['opportunities_crawler','opportunities_api']);
