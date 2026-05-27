-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: update logo_uri from static.stawi.im to stawi.org/images
-- for all clients still referencing the old static asset host.
--
-- Idempotent: the WHERE guard skips clients already using the new URI.
-- Clearing synced_at forces the next sync cycle to push the update to
-- Hydra.

UPDATE clients
SET logo_uri = 'https://stawi.org/images/logo.png',
    synced_at = NULL
WHERE logo_uri = 'https://static.stawi.im/logo.png';
