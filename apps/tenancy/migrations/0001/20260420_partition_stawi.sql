-- Copyright 2023-2026 Ant Investor Ltd
-- Stawi — core consumer social + chat platform.
-- Includes both production and development/test environments.

-- Production tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('9bsv0s0hijjg02z5lbjg','c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg',
        'Stawi','Default base tenant for stawi','production')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('9bsv0s0hijjg02qk7l1g','9bsv0s0hijjg02z5lbjg','9bsv0s0hijjg02qk7l1g','c2f4j7au6s7f91uqnokg',
        'Stawi','Default stawi partition to serve the masses',true,
        '{"default_role":"user","allow_auto_access":true,"support_contacts":{"msisdn":"+256757546244","email":"info@stawi.im"}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('9bsv0s0hijjg02qk7l20', NOW(), NOW(), 1, '9bsv0s0hijjg02z5lbjg','9bsv0s0hijjg02qk7l1g','owner',  false, '{"description":"Full control across all services"}'),
  ('9bsv0s0hijjg02qk7l21', NOW(), NOW(), 1, '9bsv0s0hijjg02z5lbjg','9bsv0s0hijjg02qk7l1g','admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('9bsv0s0hijjg02qk7l22', NOW(), NOW(), 1, '9bsv0s0hijjg02z5lbjg','9bsv0s0hijjg02qk7l1g','member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Production public client
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6l82t4pf2t82gudn7tg',
    '9bsv0s0hijjg02z5lbjg','9bsv0s0hijjg02qk7l1g',
    'Stawi',
    'd6qbqdkpf2t52mcunf40',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_chat":["*"],"service_device":["*"],"service_file":["*"],"service_geolocation":["*"],"service_profile":["*"]}',
    '{"uris":["https://app.stawi.im/sso/redirect","com.antinvestor.chat://sso/redirect","http://localhost:5170/sso/redirect","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://static.stawi.im/logo.png',
    '{"uris":["https://app.stawi.im/sso/logout"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;

-- Development/test tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('9bsv0s0hijjg09bzz6dg','c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg',
        'Stawi Development','Default base tenant for testing and building stawi','staging')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('9bsv0s0hijjg02qks6i0','9bsv0s0hijjg09bzz6dg','9bsv0s0hijjg02qks6i0','c2f4j7au6s7f91uqnokg',
        'Stawi Development','Default Stawi development partition',true,
        '{"default_role":"user","allow_auto_access":true,"support_contacts":{"msisdn":"+256757546244","email":"info@stawi.im"}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('9bsv0s0hijjg02qks6j0', NOW(), NOW(), 1, '9bsv0s0hijjg09bzz6dg','9bsv0s0hijjg02qks6i0','owner',  false, '{"description":"Full control across all services"}'),
  ('9bsv0s0hijjg02qks6j1', NOW(), NOW(), 1, '9bsv0s0hijjg09bzz6dg','9bsv0s0hijjg02qks6i0','admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('9bsv0s0hijjg02qks6j2', NOW(), NOW(), 1, '9bsv0s0hijjg09bzz6dg','9bsv0s0hijjg02qks6i0','member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Development public client
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6l82t4pf2t82gudn7u0',
    '9bsv0s0hijjg09bzz6dg','9bsv0s0hijjg02qks6i0',
    'Stawi Development',
    'd6qbqdkpf2t52mcunf4g',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_chat":["*"],"service_device":["*"],"service_file":["*"],"service_geolocation":["*"],"service_profile":["*"]}',
    '{"uris":["https://app-dev.stawi.im/sso/redirect","com.antinvestor.chat://sso/redirect","https://localhost:5170/sso/redirect","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://static.stawi.im/logo.png',
    '{"uris":["https://app-dev.stawi.im/sso/logout","com.antinvestor.chat://sso/logout","https://localhost:5170/sso/logout"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
