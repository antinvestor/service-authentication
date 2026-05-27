-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: replace thesa.stawi.org with thesa0.web.app (Firebase Hosting)
-- in the Thesa Studio client's redirect and post-logout URIs.
--
-- The admin console moves from a direct stawi.org subdomain to Firebase
-- Hosting so the sensitive admin surface is not exposed on the primary
-- domain. On already-seeded clusters the seed's ON CONFLICT DO NOTHING
-- means the old URIs are still in place.
--
-- Idempotent: the WHERE guard skips clusters that already have the
-- Firebase URI. Clearing synced_at forces the next sync cycle to push
-- the corrected URI list to Hydra.

-- Redirect URIs: swap thesa.stawi.org for thesa0.web.app
UPDATE clients
SET redirect_uris = jsonb_set(
      redirect_uris,
      '{uris}',
      (
        SELECT jsonb_agg(
          CASE
            WHEN elem #>> '{}' = 'https://thesa.stawi.org/auth/callback'
            THEN to_jsonb('https://thesa0.web.app/auth/callback'::text)
            ELSE elem
          END
        )
        FROM jsonb_array_elements(redirect_uris -> 'uris') AS elem
      )
    ),
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnom0'
  AND redirect_uris -> 'uris' @> '["https://thesa.stawi.org/auth/callback"]'::jsonb;

-- Post-logout redirect URIs: swap thesa.stawi.org for thesa0.web.app
UPDATE clients
SET post_logout_redirect_uris = jsonb_set(
      post_logout_redirect_uris,
      '{uris}',
      (
        SELECT jsonb_agg(
          CASE
            WHEN elem #>> '{}' = 'https://thesa.stawi.org/'
            THEN to_jsonb('https://thesa0.web.app/'::text)
            ELSE elem
          END
        )
        FROM jsonb_array_elements(post_logout_redirect_uris -> 'uris') AS elem
      )
    ),
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnom0'
  AND post_logout_redirect_uris -> 'uris' @> '["https://thesa.stawi.org/"]'::jsonb;
