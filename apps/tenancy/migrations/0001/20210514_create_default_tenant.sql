-- ==========================================================================
-- PRODUCTION TENANT: System Manager
-- ==========================================================================
--
-- Entity relationships:
--
--   Tenant (System Manager)
--     └─ Partition (System Manager)            ← the "home" partition
--          ├─ Client (system_manager)           ← public, for user login (authorization_code)
--          │
--          ├─ Client (authentication_tests)     ← internal, for integration tests (client_credentials)
--          │    └─ ServiceAccount
--          │
--          ├─ Client (service_authentication)   ← internal, for machine-to-machine (client_credentials)
--          │    └─ ServiceAccount               ← links client to profile_id "service_authentication"
--          │
--          ├─ Client (service_profile)
--          │    └─ ServiceAccount
--          │
--          ├─ Client (service_tenancy)
--          │    └─ ServiceAccount
--          │
--          ├─ Client (service_notifications)
--          │    └─ ServiceAccount
--          │
--          └─ Client (service_devices)
--               └─ ServiceAccount
--
-- A Client defines HOW authentication happens (grant types, scopes, redirect URIs).
-- A ServiceAccount links a client_credentials Client to a profile identity and
-- records which partition/tenant it belongs to.
-- The client_ref on ServiceAccount is a foreign key to Client.id (not client_id).
-- ==========================================================================

-- Tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description)
VALUES ('c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
        'System Manager', 'Default base tenant that all others build on');

-- Partition
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
VALUES ('c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
        'System manager', 'Default base partition in the base tenant', '{
    "scope": "openid offline offline_access profile contact",
    "audience": [
      "service_tenancy",
      "service_devices",
      "service_profile",
      "service_notification",
      "service_payments",
      "service_files",
      "service_ledger"
    ],
    "logo_uri": "https://static.antinvestor.com/logo.png",
    "redirect_uris": [
      "https://admin.antinvestor.com/auth/callback"
    ],
    "post_logout_redirect_uris": [
      "https://admin.antinvestor.com/"
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
    'd6l82t4pf2t82gudn7s0',
    'c2f4j7au6s7f91uqnojg',                       -- tenant: System Manager
    'c2f4j7au6s7f91uqnokg',                        -- partition: System Manager
    'System Manager',
    'system_manager',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"namespaces": ["service_tenancy","service_devices","service_profile","service_notifications"]}',
    '{"uris": ["https://admin.antinvestor.com/auth/callback"]}',
    '{"logo_uri": "https://static.antinvestor.com/logo.png", "post_logout_redirect_uris": ["https://admin.antinvestor.com/"]}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- PRODUCTION service account: authentication_tests
--   Used by integration tests to obtain tokens.
--   Client ──(client_ref)──▶ ServiceAccount
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'c2f4j7au6s7f91uqnong',
    'c2f4j7au6s7f91uqnojg',                       -- tenant: System Manager
    'c2f4j7au6s7f91uqnokg',                        -- partition: System Manager
    'sa-authentication_tests',
    'authentication_tests',
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
    'c2f4j7au6s7f91uqnomg',
    'c2f4j7au6s7f91uqnojg',                       -- tenant: System Manager
    'c2f4j7au6s7f91uqnokg',                        -- partition: System Manager
    'authentication_tests',                         -- profile_id (subject in tokens)
    'authentication_tests',                         -- client_id (denormalized for lookup)
    'c2f4j7au6s7f91uqnong',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- PRODUCTION service account: service_authentication
--   Client ──(client_ref)──▶ ServiceAccount
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'c2f4j7au6s7f91uqnoog',
    'c2f4j7au6s7f91uqnojg',                       -- tenant: System Manager
    'c2f4j7au6s7f91uqnokg',                        -- partition: System Manager
    'sa-service_authentication',
    'service_authentication',
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
    'c2f4j7au6s7f91uqnolg',
    'c2f4j7au6s7f91uqnojg',                       -- tenant: System Manager
    'c2f4j7au6s7f91uqnokg',                        -- partition: System Manager
    'service_authentication',                       -- profile_id (subject in tokens)
    'service_authentication',                       -- client_id (denormalized for lookup)
    'c2f4j7au6s7f91uqnoog',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- PRODUCTION service account: service_profile
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'c2f4j7au6s7f91uqnopg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_profile',
    'service_profile',
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
    'c2f4j7au6s7f91uqnoqg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_profile',
    'service_profile',
    'c2f4j7au6s7f91uqnopg',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_notifications","service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- PRODUCTION service account: service_tenancy
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'c2f4j7au6s7f91uqnorg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_tenancy',
    'service_tenancy',
    'hkGiJroO9cDS5eFnuaAV',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_notifications","service_profile"]}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnosg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_tenancy',
    'service_tenancy',
    'c2f4j7au6s7f91uqnorg',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_notifications","service_profile"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- PRODUCTION service account: service_notifications
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'c2f4j7au6s7f91uqnotg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_notifications',
    'service_notifications',
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
    'c2f4j7au6s7f91uqnoug',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_notifications',
    'service_notifications',
    'c2f4j7au6s7f91uqnotg',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- PRODUCTION service account: service_devices
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'c2f4j7au6s7f91uqnovg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_devices',
    'service_devices',
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
    'c2f4j7au6s7f91uqnp0g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_devices',
    'service_devices',
    'c2f4j7au6s7f91uqnovg',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
