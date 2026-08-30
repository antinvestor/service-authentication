-- Copyright 2023-2026 Ant Investor Ltd
-- Stawi Imports Web (production): vehicle/product import funnel at
-- https://stawi.trade backed by api.stawi.org/imports (stawi-importation-sales).
--
--   Tenant:     daa7eagthrqitmq00000  Stawi Imports
--   Partition:  daa7eagthrqitmq0000g  Stawi Imports
--   Client row: daa7eagthrqitmq00010  (client_ref for recipients)
--   client_id:  daa7eagthrqitmq0001g  (Hydra, public PKCE)
--
-- Tenancy syncs the client to Hydra (synced_at NULL). The FedCM internal
-- callback is required on every user-facing authorization-code client.

INSERT INTO public.tenants (id, created_at, modified_at, created_by, modified_by, version, tenant_id, partition_id, access_id, deleted_at, name, description, environment, properties) VALUES
  ('daa7eagthrqitmq00000', NOW(), NOW(), NULL, NULL, NULL, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', NULL, NULL, 'Stawi Imports', 'Vehicle and product importation sales funnel', 'production', NULL)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.partitions (id, created_at, modified_at, created_by, modified_by, version, tenant_id, partition_id, access_id, deleted_at, name, description, domain, parent_id, allow_auto_access, properties, state) VALUES
  ('daa7eagthrqitmq0000g', NOW(), NOW(), NULL, NULL, NULL, 'daa7eagthrqitmq00000', 'daa7eagthrqitmq0000g', NULL, NULL, 'Stawi Imports', 'Vehicle and product importation sales funnel', NULL, 'c2f4j7au6s7f91uqnokg', true, '{"default_role": "user", "support_contacts": {"email": "info@stawi.org", "msisdn": "+256757546244"}, "allow_auto_access": true}', NULL)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.clients (id, created_at, modified_at, created_by, modified_by, version, tenant_id, partition_id, access_id, deleted_at, name, client_id, client_secret, type, grant_types, response_types, redirect_uris, scopes, logo_uri, post_logout_redirect_uris, token_endpoint_auth_method, service_account_id, properties, state, synced_at) VALUES
  ('daa7eagthrqitmq00010', NOW(), NOW(), NULL, NULL, NULL, 'daa7eagthrqitmq00000', 'daa7eagthrqitmq0000g', NULL, NULL, 'Stawi Imports Web', 'daa7eagthrqitmq0001g', NULL, 'public', '{"types": ["authorization_code", "refresh_token"]}', '{"types": ["code"]}', '{"uris": ["https://stawi.trade/auth/callback", "https://accounts.stawi.org/_internal/fedcm-callback"]}', 'openid offline_access profile', 'https://stawi.org/images/logo.png', '{"uris": ["https://stawi.trade/"]}', 'none', NULL, NULL, NULL, NULL)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.oauth_client_recipients (id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience) VALUES
  ('daa7eagthrqitmq00040', NOW(), NOW(), 1, 'daa7eagthrqitmq00000', 'daa7eagthrqitmq0000g', 'daa7eagthrqitmq00010', 'https://api.stawi.org/imports'),
  ('daa7eagthrqitmq0004g', NOW(), NOW(), 1, 'daa7eagthrqitmq00000', 'daa7eagthrqitmq0000g', 'daa7eagthrqitmq00010', 'https://api.stawi.org/profile')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;
