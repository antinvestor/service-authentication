-- Copyright 2023-2026 Ant Investor Ltd
-- Stawi AI Builder — low-code AI workflow builder product.
-- Includes both production and development/test environments.

-- Production tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('9bsv0s0hijjg02z5lr4g','c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg',
        'Stawi AI Builder','Default base tenant for stawi','production')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('9bsv0s0hid5g02qkl7gjg','9bsv0s0hijjg02z5lr4g','9bsv0s0hid5g02qkl7gjg','c2f4j7au6s7f91uqnokg',
        'Stawi AI Builder','Default stawi ai builder partition to serve the masses',true,
        '{"default_role":"user","allow_auto_access":true,"support_contacts":{"msisdn":"+256757546244","email":"info@stawi.im"}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('9bsv0s0hid5g02qkl7h0', NOW(), NOW(), 1, '9bsv0s0hijjg02z5lr4g','9bsv0s0hid5g02qkl7gjg','owner',  false, '{"description":"Full control across all services"}'),
  ('9bsv0s0hid5g02qkl7h1', NOW(), NOW(), 1, '9bsv0s0hijjg02z5lr4g','9bsv0s0hid5g02qkl7gjg','admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('9bsv0s0hid5g02qkl7h2', NOW(), NOW(), 1, '9bsv0s0hijjg02z5lr4g','9bsv0s0hid5g02qkl7gjg','member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Production public client
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6l82t4pf2t82gudn7ug',
    '9bsv0s0hijjg02z5lr4g','9bsv0s0hid5g02qkl7gjg',
    'Stawi AI Builder',
    'd6qbqdkpf2t52mcunf50',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_device":["*"],"service_file":["*"],"service_profile":["*"]}',
    '{"uris":["https://stawi.dev/auth/callback","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://static.stawi.dev/logo.png',
    '{"uris":["https://stawi.dev"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;

-- Development/test tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('9bsv0s0hijjghdbz96dg','c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg',
        'Stawi AI Builder Development','Default base tenant for testing and building stawi','staging')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('9bsv0s0hijjb83qksr20','9bsv0s0hijjghdbz96dg','9bsv0s0hijjb83qksr20','c2f4j7au6s7f91uqnokg',
        'Stawi AI Builder Development','Default Stawi development partition',true,
        '{"default_role":"user","allow_auto_access":true,"support_contacts":{"msisdn":"+256757546244","email":"info@stawi.dev"}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('9bsv0s0hijjb83qksr30', NOW(), NOW(), 1, '9bsv0s0hijjghdbz96dg','9bsv0s0hijjb83qksr20','owner',  false, '{"description":"Full control across all services"}'),
  ('9bsv0s0hijjb83qksr31', NOW(), NOW(), 1, '9bsv0s0hijjghdbz96dg','9bsv0s0hijjb83qksr20','admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('9bsv0s0hijjb83qksr32', NOW(), NOW(), 1, '9bsv0s0hijjghdbz96dg','9bsv0s0hijjb83qksr20','member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Development public client
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6l82t4pf2t82gudn7v0',
    '9bsv0s0hijjghdbz96dg','9bsv0s0hijjb83qksr20',
    'Stawi AI Builder Development',
    'd6qbqdkpf2t52mcunf5g',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_device":["*"],"service_file":["*"],"service_profile":["*"]}',
    '{"uris":["https://dev.stawi.dev/auth/callback","https://localhost:5170/auth/callback","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://static.stawi.dev/logo.png',
    '{"uris":["https://dev.stawi.dev","https://localhost:5170"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
