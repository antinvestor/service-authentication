-- Copyright 2023-2026 Ant Investor Ltd
-- Stawi Imports Web: allow browser sessions to call the identity API directly
-- (workforce/teams/roles admin). Adds the identity audience to the production
-- and development public clients seeded in 20260830_01 / 20260830_02.
INSERT INTO public.oauth_client_recipients (id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience) VALUES
  ('daa7eagthrqitmq00060', NOW(), NOW(), 1, 'daa7eagthrqitmq00000', 'daa7eagthrqitmq0000g', 'daa7eagthrqitmq00010', 'https://api.stawi.org/identity'),
  ('daa7eagthrqitmq0006g', NOW(), NOW(), 1, 'daa7eagthrqitmq00020', 'daa7eagthrqitmq0002g', 'daa7eagthrqitmq00030', 'https://api.stawi.org/identity')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;
