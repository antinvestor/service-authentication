-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-savings
-- Savings account management. Handles savings products, accounts,
-- deposits, withdrawals, and interest calculations. Calls
-- operations for transfer execution, profile for account holder
-- identity, and tenancy for multi-tenant scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnq5g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_savings',
    'service-savings',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_audit":["*"],"service_identity":["*"],"service_operations":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnq6g',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnq6g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijfg',
    'service-savings',
    'c2f4j7au6s7f91uqnq5g',
    'internal',
    '{"service_audit":["*"],"service_identity":["*"],"service_operations":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
