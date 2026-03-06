
-- Seed: Client + ServiceAccount records for all platform services.
-- These are synced to Hydra via the client sync event handler so that
-- each service can obtain OAuth2 tokens via client_credentials grant.

-- ============================================================
-- authentication_tests (used by integration tests)
-- ============================================================
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'c2f4j7au6s7f91uqnong',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
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
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'authentication_tests',
    'authentication_tests',
    'c2f4j7au6s7f91uqnong',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- service_authentication (production auth service)
-- ============================================================
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
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
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}'
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
    'c2f4j7au6s7f91uqnoog',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- service_profile
-- ============================================================
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
    'c2f4j7au6s7f91uqnopg',
    'internal',
    '{"namespaces": ["service_notifications","service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- service_tenancy (partition service)
-- ============================================================
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
    '{"namespaces": ["service_notifications","service_profile","authentication_tests"]}'
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
    'c2f4j7au6s7f91uqnorg',
    'internal',
    '{"namespaces": ["service_notifications","service_profile","authentication_tests"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- service_notifications
-- ============================================================
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
    'c2f4j7au6s7f91uqnotg',
    'internal',
    '{"namespaces": ["service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- service_devices
-- ============================================================
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
    'c2f4j7au6s7f91uqnovg',
    'internal',
    '{"namespaces": ["service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
