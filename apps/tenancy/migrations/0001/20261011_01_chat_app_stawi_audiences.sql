-- Copyright 2023-2026 Ant Investor Ltd
-- Stawi chat app (public clients d6qbqdkpf2t52mcunf40 prod, d6qbqdkpf2t52mcunf4g dev):
-- allow user tokens for Stawi settlement and finance. Both services validate
-- exactly one resource audience (frame OAUTH2_RESOURCE_AUDIENCE), so the app's
-- access token must carry https://api.stawi.org/stawi-settlement and
-- https://api.stawi.org/stawi-finance. Hydra refuses a requested audience the
-- client is not allowed, and browser consent grants the client's full allowed
-- audience list, so the recipients below are what lets the token reach them.

INSERT INTO public.oauth_client_recipients (id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience) VALUES
  ('db5koukpf2t892ghj1ug', NOW(), NOW(), 1, '9bsv0s0hijjg02z5lbjg', '9bsv0s0hijjg02qk7l1g', 'd6l82t4pf2t82gudn7tg', 'https://api.stawi.org/stawi-settlement'),
  ('db5koukpf2t892ghj1v0', NOW(), NOW(), 1, '9bsv0s0hijjg02z5lbjg', '9bsv0s0hijjg02qk7l1g', 'd6l82t4pf2t82gudn7tg', 'https://api.stawi.org/stawi-finance'),
  ('db5koukpf2t892ghj1vg', NOW(), NOW(), 1, '9bsv0s0hijjg09bzz6dg', '9bsv0s0hijjg02qks6i0', 'd6l82t4pf2t82gudn7u0', 'https://api.stawi.org/stawi-settlement'),
  ('db5koukpf2t892ghj200', NOW(), NOW(), 1, '9bsv0s0hijjg09bzz6dg', '9bsv0s0hijjg02qks6i0', 'd6l82t4pf2t82gudn7u0', 'https://api.stawi.org/stawi-finance')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

-- Re-sync both Hydra clients so the new audiences land in their allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id IN ('d6qbqdkpf2t52mcunf40', 'd6qbqdkpf2t52mcunf4g');
