-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-stawi
-- Stawi workflow orchestration. Composes the full fintech stack
-- for end-to-end lending workflows (USSD/API). Calls identity/
-- field for borrower and agent data, origination for applications,
-- loans for accounts, savings for deposits, ledger for balances,
-- payment for disbursement/collection, notification for SMS/push,
-- files for document handling, and profile/tenancy for scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnqbg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_stawi',
    'service-stawi',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_field":["*"],"service_file":["*"],"service_identity":["*"],"service_ledger":["*"],"service_loans":["*"],"service_notification":["*"],"service_operations":["*"],"service_payment":["*"],"service_profile":["*"],"service_savings":["*"],"service_tenancy":["*"],"service_trustage":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnqcg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnqcg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijh0',
    'service-stawi',
    'c2f4j7au6s7f91uqnqbg',
    'internal',
    '{"service_field":["*"],"service_file":["*"],"service_identity":["*"],"service_ledger":["*"],"service_loans":["*"],"service_notification":["*"],"service_operations":["*"],"service_payment":["*"],"service_profile":["*"],"service_savings":["*"],"service_tenancy":["*"],"service_trustage":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
