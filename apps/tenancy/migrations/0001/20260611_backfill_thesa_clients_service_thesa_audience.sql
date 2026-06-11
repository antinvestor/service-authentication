-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add the `service_thesa` audience to the Thesa Studio public
-- clients (production + staging) on clusters seeded before the audience
-- was added.
--
-- The Thesa BFF (service-thesa) verifies tokens with
-- OAUTH2_JWT_VERIFY_AUDIENCE=service_thesa. Without this audience on the
-- client, Hydra cannot mint it, every /api/analytics/* call fails with
-- "token has invalid claims: token has invalid audience", and the admin
-- console dashboard shows "could not reach the analytics service".
--
-- Idempotent: no-op if service_thesa is already present.
-- Clearing synced_at forces the next sync cycle to POST the corrected
-- audience list to Hydra.

UPDATE clients
SET audiences = audiences || '{"service_thesa":["*"]}'::jsonb,
    synced_at = NULL
WHERE id IN ('c2f4j7au6s7f91uqnom0', 'd8gueekpf2tfslum7lp0')
  AND NOT (audiences ? 'service_thesa');
