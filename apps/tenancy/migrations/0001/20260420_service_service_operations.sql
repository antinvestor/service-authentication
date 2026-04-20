-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-operations
-- Operational utilities and transfer execution. Orchestrates
-- fund transfers between accounts. Calls identity/field for
-- agent/borrower data, ledger for accounting entries, payment
-- for execution, notification for alerts, and profile/tenancy
-- for scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnq7g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_operations',
    'service-operations',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_audit":["*"],"service_field":["*"],"service_identity":["*"],"service_ledger":["*"],"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnq8g',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnq8g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijg0',
    'service-operations',
    'c2f4j7au6s7f91uqnq7g',
    'internal',
    '{"service_audit":["*"],"service_field":["*"],"service_identity":["*"],"service_ledger":["*"],"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
