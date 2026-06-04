-- Copyright 2023-2026 Ant Investor Ltd
-- Thesa — platform root tenant, hosts centralised service accounts.
-- Includes the Sysops child partition.

INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg',
        'Thesa','Platform root tenant','production')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('c2f4j7au6s7f91uqnokg','c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg','c2f4j7au6s7f91uqnokg',
        'Thesa','Platform root partition',false,
        '{"default_role":"user","allow_auto_access":false,"support_contacts":{"msisdn":"+256757546244","email":"info@antinvestor.com"}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('c2f4j7au6s7f91uqnol0', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg','owner',  false, '{"description":"Full control across all services"}'),
  ('d7j42dspf2tfev9jfgt0', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg','admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('d7j42dspf2tfev9jfgtg', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg','member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Thesa Studio — the root-partition public client (internal admin/ops UI).
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'c2f4j7au6s7f91uqnom0',
    'c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg',
    'Thesa Studio',
    'c2f4j7au6s7f91uqnomg',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_tenancy":["*"],"service_device":["*"],"service_profile":["*"],"service_notification":["*"],"service_payment":["*"],"service_ledger":["*"],"service_setting":["*"],"service_file":["*"],"service_trustage":["*"]}',
    '{"uris":["https://thesa.stawi.org/auth/callback","https://thesa.pages.dev/auth/callback","org.stawi.thesa://auth/callback","http://localhost:5173/auth/callback","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://stawi.org/images/logo.png',
    '{"uris":["https://thesa.stawi.org/","https://thesa.pages.dev/","http://localhost:5173/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;

-- Sysops child partition (observability, ops tooling).
INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('d7b4qekpf2tshigkrv60','c2f4j7au6s7f91uqnojg','d7b4qekpf2tshigkrv60','c2f4j7au6s7f91uqnokg',
        'System Operations','Ops/observability partition',false,
        '{"default_role":"user","allow_auto_access":false,"support_contacts":{"msisdn":"+256757546244","email":"info@antinvestor.com"}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('d7b4qekpf2tshigkrv70', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg','d7b4qekpf2tshigkrv60','owner',  false, '{"description":"Full control across all services"}'),
  ('d7j42dspf2tfev9jfgu0', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg','d7b4qekpf2tshigkrv60','admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('d7j42dspf2tfev9jfgug', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg','d7b4qekpf2tshigkrv60','member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- OpenObserve — Sysops public client.
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd7b4qekpf2tshigkrv80',
    'c2f4j7au6s7f91uqnojg','d7b4qekpf2tshigkrv60',
    'System Operations',
    'd7b4qekpf2tshigkrv8g',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_tenancy":["*"],"service_setting":["*"]}',
    '{"uris":["https://openobserve.stawi.org/auth/callback","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://stawi.org/images/logo.png',
    '{"uris":["https://openobserve.stawi.org/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
