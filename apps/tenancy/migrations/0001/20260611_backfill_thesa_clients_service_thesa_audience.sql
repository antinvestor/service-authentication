-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add the `service_thesa` and `service_audit` audiences to the
-- Thesa Studio public clients (production + staging) on clusters seeded
-- before these audiences were added.
--
-- The Thesa BFF (service-thesa) verifies tokens with
-- OAUTH2_JWT_VERIFY_AUDIENCE=service_thesa and the audit service
-- (service-audit) with service_audit. Without the audiences on the
-- client, Hydra cannot mint them: the console's analytics calls fail
-- with "token has invalid claims: token has invalid audience" and the
-- dashboard's audit-backed activity feed cannot load at all.
--
-- Idempotent: each audience is added only when missing.
-- Clearing synced_at forces the next sync cycle to POST the corrected
-- audience list to Hydra.

UPDATE clients
SET audiences = audiences
        || '{"service_thesa":["*"]}'::jsonb
        || '{"service_audit":["*"]}'::jsonb,
    synced_at = NULL
WHERE id IN ('c2f4j7au6s7f91uqnom0', 'd8gueekpf2tfslum7lp0')
  AND NOT (audiences ? 'service_thesa' AND audiences ? 'service_audit');
