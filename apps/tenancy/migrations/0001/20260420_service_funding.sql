-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-funding
-- Loan fund management and disbursement. Manages investor accounts
-- and fund allocation. Heavy cross-service dependency: calls
-- identity/field for borrower data, loans for account linkage and
-- loan request context, ledger for accounting entries,
-- payment for disbursement execution, operations for transfers,
-- notification for alerts, and profile/tenancy for scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnq3g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_funding',
    'service-funding',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_audit":["*"],"service_field":["*"],"service_identity":["*"],"service_ledger":["*"],"service_loans":["*"],"service_notification":["*"],"service_operations":["*"],"service_payment":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnq4g',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnq4g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijf0',
    'service-funding',
    'c2f4j7au6s7f91uqnq3g',
    'internal',
    '{"service_audit":["*"],"service_field":["*"],"service_identity":["*"],"service_ledger":["*"],"service_loans":["*"],"service_notification":["*"],"service_operations":["*"],"service_payment":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
