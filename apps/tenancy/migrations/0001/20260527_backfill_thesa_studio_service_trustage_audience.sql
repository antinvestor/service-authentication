-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add the `service_trustage` audience to the Thesa Studio
-- public client on clusters where the original seed
-- (20260420_partition_thesa.sql) was applied before service_trustage
-- was added.
--
-- The seed used INSERT ... ON CONFLICT (id) DO NOTHING, so editing the
-- seed alone fixes only fresh installs. On already-seeded clusters the
-- row predates the service_trustage addition, so its audiences JSON is
-- missing the key. When the Thesa UI requests a token with
-- service_trustage in the audience list, Hydra rejects it because the
-- audience isn't whitelisted on the client.
--
-- Idempotent: no-op if service_trustage is already present.
-- Clearing synced_at forces the next sync cycle to POST the corrected
-- audience list to Hydra.

UPDATE clients
SET audiences = audiences || '{"service_trustage":["*"]}'::jsonb,
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnom0'
  AND NOT (audiences ? 'service_trustage');
