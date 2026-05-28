-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-seed
-- Direct-to-client lending service. Manages credit profiles,
-- tiers, and loan requests. Composes origination, loans, and
-- operations for end-to-end loan workflows. Calls identity/field
-- for borrower data and tenancy for partition scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnq9g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_seed',
    'service-seed',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_field":["*"],"service_identity":["*"],"service_loans":["*"],"service_operations":["*"],"service_tenancy":["*"],"service_trustage":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnqag',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnqag',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijgg',
    'service-seed',
    'c2f4j7au6s7f91uqnq9g',
    'internal',
    '{"service_field":["*"],"service_identity":["*"],"service_loans":["*"],"service_operations":["*"],"service_tenancy":["*"],"service_trustage":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
