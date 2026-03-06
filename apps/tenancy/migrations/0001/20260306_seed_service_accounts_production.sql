-- ==========================================================================
-- PRODUCTION service account clients + service_accounts
-- ==========================================================================
--
-- Partition: System Manager (c2f4j7au6s7f91uqnokg)
-- Tenant:    System Manager (c2f4j7au6s7f91uqnojg)
--
-- Each service gets a Client + ServiceAccount pair:
--
--   Client (type=internal, grant=client_credentials)
--     │
--     │  client_ref (FK → Client.id)
--     ▼
--   ServiceAccount (profile_id = subject in tokens)
--
-- The Client defines the OAuth2 credentials (client_id/secret, scopes).
-- The ServiceAccount links the Client to a profile identity and records
-- which partition/tenant it belongs to.
-- ==========================================================================

-- ──────────────────────────────────────────────────────────────
-- service_authentication
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnoog',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_authentication',
    'service_authentication',
    'vkGiJroO9dAS5eFnuaGy',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnolg'                        -- service_account_id → SA.id below
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnolg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_authentication',
    'service_authentication',
    'c2f4j7au6s7f91uqnoog',                        -- client_ref → Client.id above
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service_profile
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
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
    '{"namespaces": ["service_notifications","service_tenancy"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnoqg'                        -- service_account_id → SA.id below
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
-- service_tenancy
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
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
    '{"namespaces": ["service_notifications","service_profile"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnosg'                        -- service_account_id → SA.id below
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
-- service_notifications
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
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
    '{"namespaces": ["service_tenancy"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnoug'                        -- service_account_id → SA.id below
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
-- service_devices
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
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
    '{"namespaces": ["service_tenancy"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnp0g'                        -- service_account_id → SA.id below
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
