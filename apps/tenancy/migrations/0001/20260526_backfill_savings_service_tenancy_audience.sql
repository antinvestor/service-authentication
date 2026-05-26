-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add the `service_tenancy` audience to the service-savings
-- client + service_account. Discovered from Hydra token request
-- rejections in the cluster.

UPDATE clients
SET audiences = audiences || '{"service_tenancy":["*"]}'::jsonb,
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnq5g'
  AND NOT (audiences ? 'service_tenancy');

UPDATE service_accounts
SET audiences = audiences || '{"service_tenancy":["*"]}'::jsonb
WHERE id = 'c2f4j7au6s7f91uqnq6g'
  AND NOT (audiences ? 'service_tenancy');
