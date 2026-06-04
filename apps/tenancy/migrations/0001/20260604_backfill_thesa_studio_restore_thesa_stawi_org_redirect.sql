-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: keep https://thesa.stawi.org as a valid Thesa Studio host
-- alongside the Firebase Hosting URIs (thesa0.web.app, thesa.pages.dev).
--
-- 20260527_backfill_thesa_studio_firebase_redirect_uris.sql moved the admin
-- console to Firebase and dropped thesa.stawi.org. The primary-domain host is
-- still in use, so re-add it as an additional redirect and post-logout URI.
--
-- Additive + idempotent: the WHERE guard skips clients that already contain the
-- URI, so re-runs are no-ops. Clearing synced_at forces the next sync cycle to
-- push the updated URI list to Hydra. Client id c2f4j7au6s7f91uqnom0 =
-- "Thesa Studio".

-- Redirect URI: append https://thesa.stawi.org/auth/callback
UPDATE clients
SET redirect_uris = jsonb_set(
      redirect_uris,
      '{uris}',
      (redirect_uris -> 'uris') || '["https://thesa.stawi.org/auth/callback"]'::jsonb
    ),
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnom0'
  AND NOT (redirect_uris -> 'uris' @> '["https://thesa.stawi.org/auth/callback"]'::jsonb);

-- Post-logout redirect URI: append https://thesa.stawi.org/
UPDATE clients
SET post_logout_redirect_uris = jsonb_set(
      post_logout_redirect_uris,
      '{uris}',
      (post_logout_redirect_uris -> 'uris') || '["https://thesa.stawi.org/"]'::jsonb
    ),
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnom0'
  AND NOT (post_logout_redirect_uris -> 'uris' @> '["https://thesa.stawi.org/"]'::jsonb);
