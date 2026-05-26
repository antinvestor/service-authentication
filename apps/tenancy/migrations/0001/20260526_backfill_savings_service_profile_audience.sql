-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add the `service_profile` audience to the service-savings
-- client + service_account.  The original seed
-- (20260420_service_savings.sql) omitted service_profile, so the
-- savings service cannot obtain tokens scoped to the profile service.
--
-- Clearing synced_at forces the next sync cycle to POST the corrected
-- audience list to Hydra.

UPDATE clients
SET audiences = audiences || '{"service_profile":["*"]}'::jsonb,
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnq5g'
  AND NOT (audiences ? 'service_profile');

UPDATE service_accounts
SET audiences = audiences || '{"service_profile":["*"]}'::jsonb
WHERE id = 'c2f4j7au6s7f91uqnq6g'
  AND NOT (audiences ? 'service_profile');
