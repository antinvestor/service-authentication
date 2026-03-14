-- ==========================================================================
-- PRODUCTION TENANT: System Manager
-- ==========================================================================
--
-- Entity relationships (service accounts in separate migration):
--
--   Tenant (System Manager)
--     └─ Partition (System Manager)            ← the "home" partition
--          └─ Client (d6qbqdkpf2t52mcunf30)      ← public, for user login (authorization_code)
--
-- Service account clients + service_accounts are seeded in:
--   20260306_seed_production_service_accounts.sql
-- ==========================================================================

-- Tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description)
VALUES ('c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
        'System Manager', 'Default base tenant that all others build on');

-- Partition
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
VALUES ('c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
        'System manager', 'Default base partition in the base tenant', '{
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
    'd6l82t4pf2t82gudn7s0',
    'c2f4j7au6s7f91uqnojg',                       -- tenant: System Manager
    'c2f4j7au6s7f91uqnokg',                        -- partition: System Manager
    'Thesa',
    'd6qbqdkpf2t52mcunf30',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"namespaces": ["service_tenancy","service_devices","service_profile","service_notifications"]}',
    '{"uris": ["https://admin.antinvestor.com/auth/callback"]}',
    'https://static.antinvestor.com/logo.png',
    '{"uris": ["https://admin.antinvestor.com/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
