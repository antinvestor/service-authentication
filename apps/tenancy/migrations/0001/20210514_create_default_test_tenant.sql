-- ==========================================================================
-- DEVELOPMENT / TEST TENANT: Testing Manager
-- ==========================================================================
--
-- Entity relationships (service accounts in separate migration):
--
--   Tenant (Testing Manager)
--     └─ Partition (Dev Backoffice)              ← the "home" partition
--          └─ Client (dev_backoffice)             ← public, for user login (authorization_code)
--
-- Service account clients + service_accounts are seeded in:
--   20260306_seed_dev_service_accounts.sql
-- ==========================================================================

-- Tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description)
VALUES ('9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qhg',
        'Testing Manager', 'Default test tenant that all others build on');

-- Partition
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
VALUES ('9bsv0s3pbdv002o80qhg', '9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qhg',
        'Dev Backoffice', 'default dev partition for test tenants', '{
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
    'd6l82t4pf2t82gudn7sg',
    '9bsv0s3pbdv002o80qfg',                       -- tenant: Testing Manager
    '9bsv0s3pbdv002o80qhg',                        -- partition: Dev Backoffice
    'Dev Backoffice',
    'dev_backoffice',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"namespaces": ["service_tenancy","service_devices","service_profile","service_notifications"]}',
    '{"uris": ["http://localhost:5173/auth/callback","https://admin-dev.antinvestor.com/auth/callback"]}',
    'https://static.antinvestor.com/logo.png',
    '{"uris": ["http://localhost:5173/","https://admin-dev.antinvestor.com/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
