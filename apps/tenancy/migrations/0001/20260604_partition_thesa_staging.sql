-- Copyright 2023-2026 Ant Investor Ltd
-- Thesa Development — Staging tenant for the Thesa Studio admin console.
--
-- All IDs are stable xids registered in apps/tenancy/migrations/IDS.md.
-- Re-seeding is a no-op (ON CONFLICT DO NOTHING).

INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES (
    'd8gueekpf2tfslum7lmg',
    'd8gueekpf2tfslum7lmg',
    'd8gueekpf2tfslum7ln0',
    'Thesa Development',
    'Staging tenant for the Thesa Studio admin console',
    'staging'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES (
    'd8gueekpf2tfslum7ln0',
    'd8gueekpf2tfslum7lmg',
    'd8gueekpf2tfslum7ln0',
    'd8gueekpf2tfslum7ln0',
    'Thesa Development',
    'Staging tenant for the Thesa Studio admin console',
    true,
    '{
      "default_role": "user",
      "allow_auto_access": true,
      "support_contacts": {"msisdn": "+256757546244", "email": "info@antinvestor.com"}
    }'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('d8gueekpf2tfslum7lng',  NOW(), NOW(), 1, 'd8gueekpf2tfslum7lmg', 'd8gueekpf2tfslum7ln0', 'owner',  false, '{"description":"Full control across all services"}'),
  ('d8gueekpf2tfslum7lo0',  NOW(), NOW(), 1, 'd8gueekpf2tfslum7lmg', 'd8gueekpf2tfslum7ln0', 'admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('d8gueekpf2tfslum7log', NOW(), NOW(), 1, 'd8gueekpf2tfslum7lmg', 'd8gueekpf2tfslum7ln0', 'member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd8gueekpf2tfslum7lp0',
    'd8gueekpf2tfslum7lmg', 'd8gueekpf2tfslum7ln0',
    'Thesa Studio Development',
    'd8gueekpf2tfslum7lpg',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_tenancy":["*"],"service_device":["*"],"service_profile":["*"],"service_notification":["*"],"service_payment":["*"],"service_ledger":["*"],"service_setting":["*"],"service_file":["*"],"service_trustage":["*"]}',
    '{"uris":["https://thesa-dev.stawi.org/auth/callback","https://thesa0.web.app/auth/callback","org.stawi.thesa://auth/callback","http://localhost:5173/auth/callback","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://stawi.org/images/logo.png',
    '{"uris":["https://thesa-dev.stawi.org/","https://thesa0.web.app/","http://localhost:5173/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
