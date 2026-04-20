-- Copyright 2023-2026 Ant Investor Ltd
-- Ant Investor — fintech lending and investment platform.
-- Includes both production and development/test environments.

-- Production tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('d6q1aekpf2taeg5iovp0','c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg',
        'Ant Investor','Default base tenant for Ant Investor','production')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('d6q1aekpf2taeg5iovpg','d6q1aekpf2taeg5iovp0','d6q1aekpf2taeg5iovpg','c2f4j7au6s7f91uqnokg',
        'Ant Investor','Default Ant Investor partition to serve the masses',false,
        '{"default_role":"user","support_contacts":{"msisdn":"+256757546244","email":"info@antinvestor.com"}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('d6q1aekpf2taeg5iovq1', NOW(), NOW(), 1, 'd6q1aekpf2taeg5iovp0','d6q1aekpf2taeg5iovpg','owner',  false, '{"description":"Full control across all services"}'),
  ('d6q1aekpf2taeg5iovq2', NOW(), NOW(), 1, 'd6q1aekpf2taeg5iovp0','d6q1aekpf2taeg5iovpg','admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('d6q1aekpf2taeg5iovq3', NOW(), NOW(), 1, 'd6q1aekpf2taeg5iovp0','d6q1aekpf2taeg5iovpg','member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Production public client
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6q1aekpf2taeg5iovq0',
    'd6q1aekpf2taeg5iovp0','d6q1aekpf2taeg5iovpg',
    'Ant Investor',
    'd6qbqdkpf2t52mcunf60',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_audit":["*"],"service_device":["*"],"service_field":["*"],"service_file":["*"],"service_funding":["*"],"service_geolocation":["*"],"service_identity":["*"],"service_loans":["*"],"service_operations":["*"],"service_profile":["*"],"service_savings":["*"]}',
    '{"uris":["https://app.antinvestor.com/auth/callback","com.antinvestor.app://auth/callback","http://localhost:5174/auth/callback","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://static.antinvestor.com/logo.png',
    '{"uris":["https://app.antinvestor.com/","http://localhost:5174/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;

-- Development/test tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('d6q1aekpf2taeg5iovqg','c2f4j7au6s7f91uqnojg','c2f4j7au6s7f91uqnokg',
        'Ant Investor Development','Default base tenant for testing and building Ant Investor','staging')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('d6q1aekpf2taeg5iovr0','d6q1aekpf2taeg5iovqg','d6q1aekpf2taeg5iovr0','c2f4j7au6s7f91uqnokg',
        'Ant Investor Development','Default Ant Investor development partition',false,
        '{"default_role":"user","support_contacts":{"msisdn":"+256757546244","email":"info@antinvestor.com"}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties) VALUES
  ('d6q1aekpf2taeg5iovr1', NOW(), NOW(), 1, 'd6q1aekpf2taeg5iovqg','d6q1aekpf2taeg5iovr0','owner',  false, '{"description":"Full control across all services"}'),
  ('d6q1aekpf2taeg5iovr2', NOW(), NOW(), 1, 'd6q1aekpf2taeg5iovqg','d6q1aekpf2taeg5iovr0','admin',  false, '{"description":"Manage partitions, access, roles, and pages"}'),
  ('d6q1aekpf2taeg5iovr3', NOW(), NOW(), 1, 'd6q1aekpf2taeg5iovqg','d6q1aekpf2taeg5iovr0','member', true,  '{"description":"Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Development public client
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6q1aekpf2taeg5iovrg',
    'd6q1aekpf2taeg5iovqg','d6q1aekpf2taeg5iovr0',
    'Ant Investor Development',
    'd6qbqdkpf2t52mcunf6g',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_audit":["*"],"service_device":["*"],"service_field":["*"],"service_file":["*"],"service_funding":["*"],"service_geolocation":["*"],"service_identity":["*"],"service_loans":["*"],"service_operations":["*"],"service_profile":["*"],"service_savings":["*"]}',
    '{"uris":["https://app-dev.antinvestor.com/auth/callback","com.antinvestor.app://auth/callback","http://localhost:5174/auth/callback","https://accounts.stawi.org/_internal/fedcm-callback"]}',
    'https://static.antinvestor.com/logo.png',
    '{"uris":["https://app-dev.antinvestor.com/","http://localhost:5174/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
