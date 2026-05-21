-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: operations-queuestore
-- Queue-storage worker (release name `operations-queuestore` in the
-- operations namespace). Persists durable job/message queue state.
-- Needs profile and tenancy for participant scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd87bdkcpf2t58bn6vahg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-operations_queuestore',
    'operations-queuestore',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'd87bdkcpf2t58bn6vai0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd87bdkcpf2t58bn6vai0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd87bdqcpf2t5b0c3bgbg',
    'operations-queuestore',
    'd87bdkcpf2t58bn6vahg',
    'internal',
    '{"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
