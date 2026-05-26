-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add missing audiences to the service-savings client +
-- service_account.  The original seed omitted service_profile and
-- service_tenancy.
--
-- Clearing synced_at forces the next sync cycle to POST the corrected
-- audience list to Hydra.

UPDATE clients
SET audiences = audiences || '{"service_profile":["*"],"service_tenancy":["*"]}'::jsonb,
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnq5g'
  AND NOT (audiences ?& array['service_profile','service_tenancy']);

UPDATE service_accounts
SET audiences = audiences || '{"service_profile":["*"],"service_tenancy":["*"]}'::jsonb
WHERE id = 'c2f4j7au6s7f91uqnq6g'
  AND NOT (audiences ?& array['service_profile','service_tenancy']);
