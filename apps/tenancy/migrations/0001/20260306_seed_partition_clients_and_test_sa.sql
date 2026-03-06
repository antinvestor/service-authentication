
-- Seed: SA clients + service_accounts for the test tenant partition.

-- ============================================================
-- Service account clients + service_accounts for
-- the test tenant partition (Dev Backoffice).
--
-- These mirror the System Manager SA records so that services
-- running against the test tenant can obtain tokens too.
--
-- Test tenant:    9bsv0s3pbdv002o80qfg
-- Test partition: 9bsv0s3pbdv002o80qhg
-- ============================================================

-- authentication_tests (test tenant)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'd6l82t4pf2t82gudn7vg',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-authentication_tests',
    'test_authentication_tests',
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
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'test_authentication_tests',
    'test_authentication_tests',
    'd6l82t4pf2t82gudn7vg',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- service_authentication (test tenant)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'd6l82t4pf2t82gudn80g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_authentication',
    'test_service_authentication',
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
    'test_service_authentication',
    'test_service_authentication',
    'd6l82t4pf2t82gudn80g',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- service_profile (test tenant)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'd6l82t4pf2t82gudn81g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_profile',
    'test_service_profile',
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
    'test_service_profile',
    'test_service_profile',
    'd6l82t4pf2t82gudn81g',
    'internal',
    '{"namespaces": ["service_notifications","service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- service_tenancy (test tenant)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'd6l82t4pf2t82gudn82g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_tenancy',
    'test_service_tenancy',
    'hkGiJroO9cDS5eFnuaAV',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_notifications","service_profile","test_authentication_tests"]}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn830',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'test_service_tenancy',
    'test_service_tenancy',
    'd6l82t4pf2t82gudn82g',
    'internal',
    '{"namespaces": ["service_notifications","service_profile","test_authentication_tests"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- service_notifications (test tenant)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'd6l82t4pf2t82gudn83g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_notifications',
    'test_service_notifications',
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
    'test_service_notifications',
    'test_service_notifications',
    'd6l82t4pf2t82gudn83g',
    'internal',
    '{"namespaces": ["service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- service_devices (test tenant)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences
) VALUES (
    'd6l82t4pf2t82gudn84g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_devices',
    'test_service_devices',
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
    'test_service_devices',
    'test_service_devices',
    'd6l82t4pf2t82gudn84g',
    'internal',
    '{"namespaces": ["service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
