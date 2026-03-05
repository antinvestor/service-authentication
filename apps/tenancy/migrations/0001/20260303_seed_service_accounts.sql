
-- Seed: Client record for authentication_tests service account
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

-- Seed: authentication_tests service account (used by integration tests)
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

-- Seed: Client record for authentication service account
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

-- Seed: authentication service account
-- Attached to System Manager partition → access cascades to all children via Keto
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
