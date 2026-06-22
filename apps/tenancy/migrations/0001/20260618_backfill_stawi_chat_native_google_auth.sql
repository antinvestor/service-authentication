-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: enable native Google credential exchange for the Stawi Chat
-- public clients (production + staging).
--
-- Android one-tap returns a Google ID token. The authentication service must
-- verify that token against the OAuth web/server client ID from server-side
-- configuration, then drive Hydra headlessly so Hydra remains the issuer of
-- Antinvestor access, refresh, and ID tokens.
--
-- Idempotent: properties are merged in place. Clearing synced_at forces the
-- next client sync cycle to push the updated client policy through the
-- tenancy/Hydra synchronization path.

UPDATE clients
SET properties = (COALESCE(properties, '{}'::jsonb) - 'native_google_server_client_id') ||
      '{"native_auth_enabled":true}'::jsonb,
    synced_at = NULL
WHERE id IN ('d6l82t4pf2t82gudn7tg', 'd6l82t4pf2t82gudn7u0')
  AND (
    properties IS NULL
    OR properties ->> 'native_auth_enabled' IS DISTINCT FROM 'true'
    OR properties ? 'native_google_server_client_id'
  );
