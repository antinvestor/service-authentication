-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add the `opportunities_api` audience to the trustage
-- client + service_account. Discovered from Hydra token request
-- rejections in the cluster.

UPDATE clients
SET audiences = audiences || '{"opportunities_api":["*"]}'::jsonb,
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnplg'
  AND NOT (audiences ? 'opportunities_api');

UPDATE service_accounts
SET audiences = audiences || '{"opportunities_api":["*"]}'::jsonb
WHERE id = 'c2f4j7au6s7f91uqnpmg'
  AND NOT (audiences ? 'opportunities_api');
