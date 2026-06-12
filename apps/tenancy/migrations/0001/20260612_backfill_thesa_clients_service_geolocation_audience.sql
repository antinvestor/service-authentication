-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add the `service_geolocation` audience to the Thesa Studio
-- public clients (production + staging) on clusters seeded before this
-- audience was added.
--
-- The geolocation service (service-geolocation) verifies tokens with
-- OAUTH2_JWT_VERIFY_AUDIENCE=service_geolocation. Without the audience on
-- the client, Hydra cannot mint it: the console's Geolocation pages
-- (Areas, Routes, Events, Analytics) fail with
-- "token has invalid claims: token has invalid audience" and render
-- "An unexpected error occurred."
--
-- Idempotent: the audience is added only when missing.
-- Clearing synced_at forces the next sync cycle to POST the corrected
-- audience list to Hydra.

UPDATE clients
SET audiences = audiences || '{"service_geolocation":["*"]}'::jsonb,
    synced_at = NULL
WHERE id IN ('c2f4j7au6s7f91uqnom0', 'd8gueekpf2tfslum7lp0')
  AND NOT (audiences ? 'service_geolocation');
