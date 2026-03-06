-- ==========================================================================
-- DEVELOPMENT / TEST TENANT: Testing Manager
-- ==========================================================================
--
-- Entity relationships:
--
--   Tenant (Testing Manager)
--     └─ Partition (Dev Backoffice)              ← the "home" partition
--          ├─ Client (dev_backoffice)             ← public, for user login (authorization_code)
--          │
--          ├─ Client (dev_authentication_tests)   ← internal, for integration tests
--          │    └─ ServiceAccount
--          │
--          ├─ Client (dev_service_authentication) ← internal, for machine-to-machine
--          │    └─ ServiceAccount
--          │
--          ├─ Client (dev_service_profile)
--          │    └─ ServiceAccount
--          │
--          ├─ Client (dev_service_tenancy)
--          │    └─ ServiceAccount
--          │
--          ├─ Client (dev_service_notifications)
--          │    └─ ServiceAccount
--          │
--          └─ Client (dev_service_devices)
--               └─ ServiceAccount
--
-- These mirror the production (System Manager) service accounts so that
-- services running in dev/test environments can obtain tokens against
-- the test tenant without touching production data.
--
-- A Client defines HOW authentication happens (grant types, scopes, redirect URIs).
-- A ServiceAccount links a client_credentials Client to a profile identity and
-- records which partition/tenant it belongs to.
-- The client_ref on ServiceAccount is a foreign key to Client.id (not client_id).
-- ==========================================================================

-- Tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description)
VALUES ('9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qhg',
        'Testing Manager', 'Default test tenant that all others build on');

-- Partition
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
VALUES ('9bsv0s3pbdv002o80qhg', '9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qhg',
        'Dev Backoffice', 'default dev partition for test tenants', '{
    "scope": "openid offline offline_access profile contact",
    "token_endpoint_auth_method": "none",
    "audience": [
      "service_tenancy",
      "service_devices",
      "service_profile",
      "service_notification",
      "service_files",
      "service_ledger"
    ],
    "logo_uri": "https://static.antinvestor.com/logo.png",
    "redirect_uris": [
      "http://localhost:5173/auth/callback",
      "https://admin-dev.antinvestor.com/auth/callback"
    ],
    "post_logout_redirect_uris": [
      "http://localhost:5173/",
      "https://admin-dev.antinvestor.com/"
    ],
    "support_contacts": {
      "msisdn": "+256757546244",
      "email": "info@antinvestor.com"
    }
  }');

-- ──────────────────────────────────────────────────────────────
-- Public client: user login via authorization_code + PKCE
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris, properties
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
    '{"logo_uri": "https://static.antinvestor.com/logo.png", "post_logout_redirect_uris": ["http://localhost:5173/","https://admin-dev.antinvestor.com/"]}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- DEV service account: authentication_tests (integration tests)
--   Client ──(client_ref)──▶ ServiceAccount
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'd6l82t4pf2t82gudn7vg',
    '9bsv0s3pbdv002o80qfg',                       -- tenant: Testing Manager
    '9bsv0s3pbdv002o80qhg',                        -- partition: Dev Backoffice
    'sa-authentication_tests',
    'dev_authentication_tests',
    'vkGiJroO9dAS5eFnuaGy',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn800',
    '9bsv0s3pbdv002o80qfg',                       -- tenant: Testing Manager
    '9bsv0s3pbdv002o80qhg',                        -- partition: Dev Backoffice
    'dev_authentication_tests',                     -- profile_id (subject in tokens)
    'dev_authentication_tests',                     -- client_id (denormalized for lookup)
    'd6l82t4pf2t82gudn7vg',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- DEV service account: service_authentication
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'd6l82t4pf2t82gudn80g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_authentication',
    'dev_service_authentication',
    'vkGiJroO9dAS5eFnuaGy',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn810',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'dev_service_authentication',
    'dev_service_authentication',
    'd6l82t4pf2t82gudn80g',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- DEV service account: service_profile
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'd6l82t4pf2t82gudn81g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_profile',
    'dev_service_profile',
    'hkGiJroO9cDS5eFnuaAV',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_notifications","service_tenancy"]}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn820',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'dev_service_profile',
    'dev_service_profile',
    'd6l82t4pf2t82gudn81g',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_notifications","service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- DEV service account: service_tenancy
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'd6l82t4pf2t82gudn82g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_tenancy',
    'dev_service_tenancy',
    'hkGiJroO9cDS5eFnuaAV',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_notifications","service_profile","dev_authentication_tests"]}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn830',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'dev_service_tenancy',
    'dev_service_tenancy',
    'd6l82t4pf2t82gudn82g',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_notifications","service_profile","dev_authentication_tests"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- DEV service account: service_notifications
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'd6l82t4pf2t82gudn83g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_notifications',
    'dev_service_notifications',
    'hkGiJroO9cDS5eFnuaAV',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_tenancy"]}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn840',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'dev_service_notifications',
    'dev_service_notifications',
    'd6l82t4pf2t82gudn83g',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- DEV service account: service_devices
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'd6l82t4pf2t82gudn84g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_devices',
    'dev_service_devices',
    'hkBaJroO9cDGleFnuaAZ',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_tenancy"]}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn850',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'dev_service_devices',
    'dev_service_devices',
    'd6l82t4pf2t82gudn84g',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
