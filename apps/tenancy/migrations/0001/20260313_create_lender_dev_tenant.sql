-- ==========================================================================
-- DEVELOPMENT / TEST TENANT: Ant Investor Development
-- ==========================================================================
--
-- Entity relationships:
--
--   Tenant (Ant Investor Development) — child of Testing Manager
--     └─ Partition (Ant Investor Development)         ← the "home" partition
--          └─ Client (Ant Investor_dev)                ← public, for user login (authorization_code)
--
-- ==========================================================================

-- Tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description)
VALUES ('d6q1aekpf2taeg5iovqg', '9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qhg',
        'Ant Investor Development', 'Default base tenant for testing and building Ant Investor');

-- Partition
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
VALUES ('d6q1aekpf2taeg5iovr0', 'd6q1aekpf2taeg5iovqg', 'd6q1aekpf2taeg5iovr0',
        'Ant Investor Development', 'Default Ant Investor development partition',
        '{
          "support_contacts": {
            "msisdn": "+256757546244",
            "email": "info@antinvestor.com"
          }
        }');

-- Public client: user login via authorization_code + PKCE
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6q1aekpf2taeg5iovrg',
    'd6q1aekpf2taeg5iovqg',                       -- tenant: Ant Investor Development
    'd6q1aekpf2taeg5iovr0',                        -- partition: Ant Investor Development
    'Ant Investor Development',
    'Ant Investor_dev',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"namespaces": ["service_lender","service_devices","service_profile","service_files","service_geolocation"]}',
    '{"uris": ["https://app-dev.antinvestor.com/auth/callback","com.antinvestor.app://auth/callback","https://app-dev.antinvestor.com/auth/callback","http://localhost:5174/auth/callback"]}',
    'https://static.antinvestor.com/logo.png',
    '{"uris": ["https://app-dev.antinvestor.com/","http://localhost:5174/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
