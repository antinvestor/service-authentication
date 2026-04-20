-- Copyright 2023-2026 Ant Investor Ltd
-- Stawi Jobs — remote job board platform for Africa and beyond.
-- Includes both production and development/test environments.

-- Production tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('d7gi6lkpf2t67dlsqre0','c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg',
        'Stawi Jobs','Remote job board platform for Africa and beyond','production')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('d7gi6lkpf2t67dlsqreg','d7gi6lkpf2t67dlsqre0','d7gi6lkpf2t67dlsqreg','c2f4j7au6s7f91uqnokg',
        'Stawi Jobs','Remote job board platform',true,
        '{"default_role":"user","allow_auto_access":true,"support_contacts":{"email":"hello@stawi.jobs"}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('d7gi6lkpf2t67dlsqrf0', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqre0','d7gi6lkpf2t67dlsqreg','owner',  false, '{"description":"Full control across all services"}'),
  ('d7gi6lkpf2t67dlsqrfg', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqre0','d7gi6lkpf2t67dlsqreg','admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('d7gi6lkpf2t67dlsqrg0', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqre0','d7gi6lkpf2t67dlsqreg','member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Production public client
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd7gi6lkpf2t67dlsqrgg',
    'd7gi6lkpf2t67dlsqre0','d7gi6lkpf2t67dlsqreg',
    'Stawi Jobs Web',
    'd7is2kspf2t7cl19qlp0',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_profile":["*"]}',
    '{"uris":["https://jobs.stawi.org/auth/callback/","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://static.stawi.im/logo.png',
    '{"uris":["https://jobs.stawi.org/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;

-- Development/test tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('d7gi6lkpf2t67dlsqrh0','c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg',
        'Stawi Jobs Development','Remote job board platform for Africa and beyond','staging')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('d7gi6lkpf2t67dlsqrhg','d7gi6lkpf2t67dlsqrh0','d7gi6lkpf2t67dlsqrhg','c2f4j7au6s7f91uqnokg',
        'Stawi Jobs Development','Remote job board platform',true,
        '{"default_role":"user","allow_auto_access":true,"support_contacts":{"email":"hello@stawi.jobs"}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('d7gi6lkpf2t67dlsqri0', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqrh0','d7gi6lkpf2t67dlsqrhg','owner',  false, '{"description":"Full control across all services"}'),
  ('d7gi6lkpf2t67dlsqrig', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqrh0','d7gi6lkpf2t67dlsqrhg','admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('d7gi6ncpf2t7oh5akfqg', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqrh0','d7gi6lkpf2t67dlsqrhg','member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Development public client
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd7gi6ncpf2t7oh5akfr0',
    'd7gi6lkpf2t67dlsqrh0','d7gi6lkpf2t67dlsqrhg',
    'Stawi Jobs Development',
    'd7is2kspf2t7cl19qlpg',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_profile":["*"]}',
    '{"uris":["https://jobs-dev.stawi.org/auth/callback/","http://localhost:5170/auth/callback/","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://static.stawi.im/logo.png',
    '{"uris":["https://jobs-dev.stawi.org/","http://localhost:5170/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
