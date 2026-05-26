-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add the `service_file` audience to the service-authentication
-- client + service_account on clusters where the original seed
-- (20260420_service_authentication.sql) was applied before service_file was
-- added (in 59728b4 — avatar sync to service-files).
--
-- The seed used INSERT ... ON CONFLICT (id) DO NOTHING, so editing the seed
-- alone fixes only fresh installs. On already-seeded clusters the row
-- predates the service_file addition, so its audiences JSON is missing
-- the key. When the auth pod boots and Frame's HTTPClientManager requests
-- an OAuth2 token with the full `OAUTH2_SERVICE_AUDIENCE` list, Hydra
-- rejects the request because `service_file` isn't whitelisted on the
-- Hydra client — and Hydra's whitelist is derived from these rows via
-- the tenancy sync_client event.
--
-- Idempotent across:
-- - fresh seeds (no-op, service_file already present in the seed)
-- - already-fixed clusters (no-op, the WHERE guard skips them)
-- - legacy clusters (one-time UPDATE that adds the key)
--
-- Clearing synced_at forces the next sync cycle to POST the corrected
-- audience list to Hydra.

UPDATE clients
SET audiences = audiences || '{"service_file":["*"]}'::jsonb,
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnoog'
  AND NOT (audiences ? 'service_file');

UPDATE service_accounts
SET audiences = audiences || '{"service_file":["*"]}'::jsonb
WHERE id = 'c2f4j7au6s7f91uqnolg'
  AND NOT (audiences ? 'service_file');
