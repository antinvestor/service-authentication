-- ==========================================================================
-- PRODUCTION TENANT: Ant Investor
-- ==========================================================================
--
-- Entity relationships:
--
--   Tenant (Ant Investor) — child of System Manager
--     └─ Partition (Ant Investor)                    ← the "home" partition
--          └─ Client (Ant Investor)                   ← public, for user login (authorization_code)
--
-- ==========================================================================

-- Tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description)
VALUES ('d6q1aekpf2taeg5iovp0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
        'Ant Investor', 'Default base tenant for Ant Investor');

-- Partition
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
VALUES ('d6q1aekpf2taeg5iovpg', 'd6q1aekpf2taeg5iovp0', 'd6q1aekpf2taeg5iovpg',
        'Ant Investor', 'Default Ant Investor partition to serve the masses',
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
    'd6q1aekpf2taeg5iovq0',
    'd6q1aekpf2taeg5iovp0',                       -- tenant: Ant Investor
    'd6q1aekpf2taeg5iovpg',                        -- partition: Ant Investor
    'Ant Investor',
    'Ant Investor',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"namespaces": ["service_lender","service_devices","service_profile","service_files","service_geolocation"]}',
    '{"uris": ["https://app.antinvestor.com/auth/callback","com.antinvestor.app://auth/callback","http://localhost:5174/auth/callback"]}',
    'https://static.antinvestor.com/logo.png',
    '{"uris": ["https://app.antinvestor.com/","http://localhost:5174/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
