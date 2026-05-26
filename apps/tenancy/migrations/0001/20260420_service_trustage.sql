-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: trustage
-- Trust and escrow management. Handles held funds and conditional
-- releases. Needs notification for status updates, profile/tenancy
-- for participant identity, and opportunities_crawler for trust-
-- linked opportunity data.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnplg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-trustage',
    'trustage',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"opportunities_crawler":["*"],"service_notification":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpmg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpmg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijbg',
    'trustage',
    'c2f4j7au6s7f91uqnplg',
    'internal',
    '{"opportunities_crawler":["*"],"service_notification":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
