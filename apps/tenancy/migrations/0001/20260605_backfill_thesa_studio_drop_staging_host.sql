-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: remove the staging host https://thesa0.web.app from the PRODUCTION
-- Thesa Studio client. thesa0.web.app is a staging origin and now belongs to
-- the dedicated "Thesa Studio Development" client (20260604_partition_thesa_staging.sql);
-- production keeps only thesa.stawi.org and thesa.pages.dev.
--
-- Idempotent: the WHERE guard skips clients that no longer contain the URI.
-- Clearing synced_at forces the next sync cycle to push the trimmed URI list
-- to Hydra. Client id c2f4j7au6s7f91uqnom0 = production "Thesa Studio".

-- Redirect URIs: drop https://thesa0.web.app/auth/callback
UPDATE clients
SET redirect_uris = jsonb_set(
      redirect_uris,
      '{uris}',
      COALESCE(
        (
          SELECT jsonb_agg(elem)
          FROM jsonb_array_elements(redirect_uris -> 'uris') AS elem
          WHERE elem #>> '{}' <> 'https://thesa0.web.app/auth/callback'
        ),
        '[]'::jsonb
      )
    ),
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnom0'
  AND redirect_uris -> 'uris' @> '["https://thesa0.web.app/auth/callback"]'::jsonb;

-- Post-logout redirect URIs: drop https://thesa0.web.app/
UPDATE clients
SET post_logout_redirect_uris = jsonb_set(
      post_logout_redirect_uris,
      '{uris}',
      COALESCE(
        (
          SELECT jsonb_agg(elem)
          FROM jsonb_array_elements(post_logout_redirect_uris -> 'uris') AS elem
          WHERE elem #>> '{}' <> 'https://thesa0.web.app/'
        ),
        '[]'::jsonb
      )
    ),
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnom0'
  AND post_logout_redirect_uris -> 'uris' @> '["https://thesa0.web.app/"]'::jsonb;
