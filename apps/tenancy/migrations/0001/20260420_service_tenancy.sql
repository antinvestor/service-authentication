-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-tenancy
-- Partition, tenant, and access management. Needs notification
-- for sending invitations and profile for user provisioning
-- during access grants.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnorg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_tenancy',
    'service-tenancy',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification":["*"],"service_profile":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnosg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnosg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ij50',
    'service-tenancy',
    'c2f4j7au6s7f91uqnorg',
    'internal',
    '{"service_notification":["*"],"service_profile":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
