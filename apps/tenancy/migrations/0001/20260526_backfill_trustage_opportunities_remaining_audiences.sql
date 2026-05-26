-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add remaining opportunities service audiences to the trustage
-- client + service_account. The deployment requests opportunities_writer,
-- opportunities_matching and opportunities_materializer but they were
-- never whitelisted — causing all trustage token requests to fail.
--
-- Clearing synced_at forces the next sync cycle to POST the corrected
-- audience list to Hydra.

UPDATE clients
SET audiences = audiences || '{"opportunities_writer":["*"],"opportunities_matching":["*"],"opportunities_materializer":["*"]}'::jsonb,
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnplg'
  AND NOT (audiences ?& array['opportunities_writer','opportunities_matching','opportunities_materializer']);

UPDATE service_accounts
SET audiences = audiences || '{"opportunities_writer":["*"],"opportunities_matching":["*"],"opportunities_materializer":["*"]}'::jsonb
WHERE id = 'c2f4j7au6s7f91uqnpmg'
  AND NOT (audiences ?& array['opportunities_writer','opportunities_matching','opportunities_materializer']);
