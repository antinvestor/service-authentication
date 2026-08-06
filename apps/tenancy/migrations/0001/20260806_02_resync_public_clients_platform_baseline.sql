-- Copyright 2023-2026 Ant Investor Ltd
--
-- Re-sync all public (user) OAuth clients so Hydra picks up the baseline
-- platform self-service audiences injected by ensurePublicPlatformAudiences
-- (profile, devices, geolocation, chat-agent, settings, files, notification).
--
-- No per-customer grant rows. Logged-in partition members already get
-- ROLE_MEMBER functional permits via access role sync + OPL.
-- See docs/adr/0002-product-peer-mesh-not-per-tenant-grants.md.

UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE type = 'public'
  AND deleted_at IS NULL;
