-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add the `opportunities_crawler` audience to the trustage
-- client + service_account on clusters where the original seed
-- (20260420_service_trustage.sql) was applied before this audience
-- was added.
--
-- Same ON CONFLICT DO NOTHING stale-row pattern as the
-- service-authentication service_file backfill.
--
-- Clearing synced_at forces the next sync cycle to POST the corrected
-- audience list to Hydra.

UPDATE clients
SET audiences = audiences || '{"opportunities_crawler":["*"]}'::jsonb,
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnplg'
  AND NOT (audiences ? 'opportunities_crawler');

UPDATE service_accounts
SET audiences = audiences || '{"opportunities_crawler":["*"]}'::jsonb
WHERE id = 'c2f4j7au6s7f91uqnpmg'
  AND NOT (audiences ? 'opportunities_crawler');
