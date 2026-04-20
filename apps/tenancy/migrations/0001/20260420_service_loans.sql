-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-loans
-- Loan lifecycle management. Handles loan accounts, disbursements,
-- repayments, penalties, restructuring, and collections. Calls
-- origination for application data, operations for transfers,
-- funding for fund allocation, and notification for borrower alerts.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnpvg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_loans',
    'service-loans',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_audit":["*"],"service_field":["*"],"service_funding":["*"],"service_identity":["*"],"service_notification":["*"],"service_operations":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnq0g',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnq0g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ije0',
    'service-loans',
    'c2f4j7au6s7f91uqnpvg',
    'internal',
    '{"service_audit":["*"],"service_field":["*"],"service_funding":["*"],"service_identity":["*"],"service_notification":["*"],"service_operations":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
