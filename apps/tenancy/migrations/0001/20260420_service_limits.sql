-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-limits
-- Customer-facing rate-limit and quota service. Calls profile and
-- tenancy for principal lookup; talks to ledger and payment to
-- enforce financial caps before settlement.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd87bdkcpf2t58bn6vaeg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_limits',
    'service-limits',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_profile":["*"],"service_tenancy":["*"],"service_ledger":["*"],"service_payment":["*"]}',
    'private_key_jwt',
    'd87bdkcpf2t58bn6vaf0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd87bdkcpf2t58bn6vaf0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd87bdkcpf2t58bn6vafg',
    'service-limits',
    'd87bdkcpf2t58bn6vaeg',
    'internal',
    '{"service_profile":["*"],"service_tenancy":["*"],"service_ledger":["*"],"service_payment":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
