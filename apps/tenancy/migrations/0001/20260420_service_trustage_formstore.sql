-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: trustage-formstore
-- Trustage form-storage worker. Persists and retrieves dynamic
-- form submissions for the trustage product. Needs profile and
-- tenancy for participant scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd86tt34pf2tddudk9psg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-trustage_formstore',
    'trustage-formstore',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'd86tt34pf2tddudk9pt0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd86tt34pf2tddudk9pt0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd86tt34pf2tddudk9ptg',
    'trustage-formstore',
    'd86tt34pf2tddudk9psg',
    'internal',
    '{"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
