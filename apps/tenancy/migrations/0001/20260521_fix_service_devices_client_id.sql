-- Copyright 2023-2026 Ant Investor Ltd
-- Fix-up: change service-device client_id to service-devices.
--
-- The original 20260420_service_device.sql seeded clients.client_id and
-- service_accounts.client_id as 'service-device', but the colony helm
-- release is named 'service-devices' (plural) and the colony chart sets
-- OAUTH2_SERVICE_CLIENT_ID to .Release.Name. The deployed pod could
-- not authenticate via client_credentials because Hydra had no client
-- with id 'service-devices'.
--
-- The earlier migration was edited in place to use the correct name,
-- so fresh seeds are already correct. Existing clusters that already
-- ran the original need this UPDATE — ON CONFLICT (id) DO NOTHING
-- in the original would otherwise be a no-op on re-run.
--
-- The WHERE clause restricts to the legacy value so this migration is
-- idempotent: a no-op on clusters that already hold the corrected value.
--
-- Operator follow-up: after this migration runs and the tenancy
-- container restarts, ReQueueClientsForHydraSync will POST a new
-- 'service-devices' OAuth2 client to Hydra. The orphaned legacy
-- 'service-device' Hydra client must be deleted manually:
--   curl -X DELETE \
--     "$HYDRA_ADMIN/admin/clients/service-device"

UPDATE clients
SET client_id = 'service-devices'
WHERE id = 'c2f4j7au6s7f91uqnovg'
  AND client_id = 'service-device';

UPDATE service_accounts
SET client_id = 'service-devices'
WHERE id = 'c2f4j7au6s7f91uqnp0g'
  AND client_id = 'service-device';

-- Clear synced_at on the client so the next sync cycle re-pushes the
-- corrected client_id even if the container is not restarted.
UPDATE clients
SET synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnovg'
  AND client_id = 'service-devices';
