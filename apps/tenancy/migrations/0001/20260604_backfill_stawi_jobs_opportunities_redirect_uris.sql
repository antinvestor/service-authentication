-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: rename the Stawi Jobs platform host from jobs.stawi.org to
-- opportunities.stawi.org (and jobs-dev.stawi.org to
-- opportunities-dev.stawi.org for the development client) in the redirect
-- and post-logout URIs.
--
-- The seeds use ON CONFLICT (id) DO NOTHING, so already-seeded clusters
-- still carry the old jobs.stawi.org URIs. This migration rewrites them in
-- place. Idempotent: each statement's WHERE guard skips clusters that have
-- already been migrated. Clearing synced_at forces the next sync cycle to
-- push the corrected URI list to Hydra.

-- ── Production client (Stawi Jobs Web, id d7gi6lkpf2t67dlsqrgg) ───────────

-- Redirect URIs: jobs.stawi.org -> opportunities.stawi.org
UPDATE clients
SET redirect_uris = jsonb_set(
      redirect_uris,
      '{uris}',
      (
        SELECT jsonb_agg(
          CASE
            WHEN elem #>> '{}' = 'https://jobs.stawi.org/auth/callback/'
            THEN to_jsonb('https://opportunities.stawi.org/auth/callback/'::text)
            ELSE elem
          END
        )
        FROM jsonb_array_elements(redirect_uris -> 'uris') AS elem
      )
    ),
    synced_at = NULL
WHERE id = 'd7gi6lkpf2t67dlsqrgg'
  AND redirect_uris -> 'uris' @> '["https://jobs.stawi.org/auth/callback/"]'::jsonb;

-- Post-logout redirect URIs: jobs.stawi.org -> opportunities.stawi.org
UPDATE clients
SET post_logout_redirect_uris = jsonb_set(
      post_logout_redirect_uris,
      '{uris}',
      (
        SELECT jsonb_agg(
          CASE
            WHEN elem #>> '{}' = 'https://jobs.stawi.org/'
            THEN to_jsonb('https://opportunities.stawi.org/'::text)
            ELSE elem
          END
        )
        FROM jsonb_array_elements(post_logout_redirect_uris -> 'uris') AS elem
      )
    ),
    synced_at = NULL
WHERE id = 'd7gi6lkpf2t67dlsqrgg'
  AND post_logout_redirect_uris -> 'uris' @> '["https://jobs.stawi.org/"]'::jsonb;

-- ── Development client (Stawi Jobs Development, id d7gi6ncpf2t7oh5akfr0) ──

-- Redirect URIs: jobs-dev.stawi.org -> opportunities-dev.stawi.org
UPDATE clients
SET redirect_uris = jsonb_set(
      redirect_uris,
      '{uris}',
      (
        SELECT jsonb_agg(
          CASE
            WHEN elem #>> '{}' = 'https://jobs-dev.stawi.org/auth/callback/'
            THEN to_jsonb('https://opportunities-dev.stawi.org/auth/callback/'::text)
            ELSE elem
          END
        )
        FROM jsonb_array_elements(redirect_uris -> 'uris') AS elem
      )
    ),
    synced_at = NULL
WHERE id = 'd7gi6ncpf2t7oh5akfr0'
  AND redirect_uris -> 'uris' @> '["https://jobs-dev.stawi.org/auth/callback/"]'::jsonb;

-- Post-logout redirect URIs: jobs-dev.stawi.org -> opportunities-dev.stawi.org
UPDATE clients
SET post_logout_redirect_uris = jsonb_set(
      post_logout_redirect_uris,
      '{uris}',
      (
        SELECT jsonb_agg(
          CASE
            WHEN elem #>> '{}' = 'https://jobs-dev.stawi.org/'
            THEN to_jsonb('https://opportunities-dev.stawi.org/'::text)
            ELSE elem
          END
        )
        FROM jsonb_array_elements(post_logout_redirect_uris -> 'uris') AS elem
      )
    ),
    synced_at = NULL
WHERE id = 'd7gi6ncpf2t7oh5akfr0'
  AND post_logout_redirect_uris -> 'uris' @> '["https://jobs-dev.stawi.org/"]'::jsonb;
