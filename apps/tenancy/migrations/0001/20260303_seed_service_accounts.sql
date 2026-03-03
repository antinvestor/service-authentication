-- Seed: authentication service account
-- Attached to System Manager partition → access cascades to all children via Keto
INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_secret, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnolg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_authentication',
    'service_authentication',
    'vkGiJroO9dAS5eFnuaGy',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- Seed: authentication_tests service account (used by integration tests)
-- Uses the same credentials as authentication but with test client ID
INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_secret, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnomg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'authentication_tests',
    'authentication_tests',
    'vkGiJroO9dAS5eFnuaGy',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
