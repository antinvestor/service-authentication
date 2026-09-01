-- Copyright 2023-2026 Ant Investor Ltd
-- Stawi Imports Web: allow admin browser sessions to manage permissions
-- (tenancy GrantPermission/RevokePermission/ListServiceNamespaces) from the
-- Settings → Identity & Access screen.
INSERT INTO public.oauth_client_recipients (id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience) VALUES
  ('daa7eagthrqitmq00070', NOW(), NOW(), 1, 'daa7eagthrqitmq00000', 'daa7eagthrqitmq0000g', 'daa7eagthrqitmq00010', 'https://api.stawi.org/tenancy'),
  ('daa7eagthrqitmq0007g', NOW(), NOW(), 1, 'daa7eagthrqitmq00020', 'daa7eagthrqitmq0002g', 'daa7eagthrqitmq00030', 'https://api.stawi.org/tenancy')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;
